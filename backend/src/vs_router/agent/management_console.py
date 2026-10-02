"""Explicit root console provisioning; dependencies are injectable for host-free tests."""
import argparse
from datetime import datetime, timedelta, timezone
import grp
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from ipaddress import IPv4Address

from ..management import (Management, STATE_DIR, TLS_DIR, read_management,
                          verify_identity, wired_ports)
from ..schema import ConfigurationVersion
from ..generators.caddy import generate_caddy_json
from ..generators.networkd import deserialize_networkd, serialize_networkd
from .apply import LocalFileSystem


class Console:
    def __init__(self, root=Path('/'), runner=None, caddy_gid=None):
        self.root = root
        self.runner = runner or self.run
        self.caddy_gid = grp.getgrnam('caddy').gr_gid if caddy_gid is None else caddy_gid
        self.fs = LocalFileSystem()

    def path(self, path):
        return self.root / str(path).lstrip('/')

    @staticmethod
    def run(argv):
        # Never echo subprocess output: validators can contain private config.
        return subprocess.run(argv, check=True, capture_output=True, timeout=60)

    def write(self, path, content, mode=0o600, gid=None):
        target = self.path(path)
        self.fs.write(target, content)
        os.chmod(target, mode)
        if gid is not None:
            os.chown(target, -1, gid)

    @staticmethod
    def server_certificate(state: Management, ca_key: rsa.RSAPrivateKey,
                          key: rsa.RSAPrivateKey):
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, state.ip)])
        subject_key_id = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        authority_key_id = x509.AuthorityKeyIdentifier(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest, None, None)
        return (x509.CertificateBuilder().subject_name(name).issuer_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                  'vs-router local management CA')]))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=397))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address(state.ip))]), critical=False)
                .add_extension(subject_key_id, critical=False)
                .add_extension(authority_key_id, critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))

    def certificates(self, state):
        target = self.path(TLS_DIR)
        ca_dir = self.path(STATE_DIR / 'ca')
        if target.exists() or ca_dir.exists():
            # An incomplete pair requires console repair, never key replacement.
            cert = x509.load_pem_x509_certificate((target / 'server.crt').read_bytes())
            ca = x509.load_pem_x509_certificate((ca_dir / 'ca.crt').read_bytes())
            key = serialization.load_pem_private_key((target / 'server.key').read_bytes(), None)
            ca_key = serialization.load_pem_private_key((ca_dir / 'ca.key').read_bytes(), None)
            if not isinstance(ca_key, rsa.RSAPrivateKey) or not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError('management.certificate_invalid')
            try:
                cert.verify_directly_issued_by(ca)
            except InvalidSignature as exc:
                raise ValueError('management.certificate_invalid') from exc
            expected_aki = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()).digest
            try:
                actual_aki = cert.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier).value.key_identifier
            except x509.ExtensionNotFound:
                actual_aki = None
            expired = cert.not_valid_after_utc <= datetime.now(timezone.utc)
            if (cert.public_key().public_numbers() != key.public_key().public_numbers()
                    or ca.public_key().public_numbers() != ca_key.public_key().public_numbers()
                    or cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                    .get_values_for_type(x509.IPAddress) != [IPv4Address(state.ip)]
                    or expired or actual_aki != expected_aki):
                cert = self.server_certificate(state, ca_key, key)
                self.write(TLS_DIR / 'server.crt', cert.public_bytes(serialization.Encoding.PEM).decode(),
                           0o640, self.caddy_gid)
            os.chmod(ca_dir, 0o700)
            os.chmod(ca_dir / 'ca.key', 0o600)
            os.chmod(target, 0o750)
            os.chown(target, -1, self.caddy_gid)
            for name in ('server.key', 'server.crt'):
                os.chmod(target / name, 0o640)
                os.chown(target / name, -1, self.caddy_gid)
            return ca
        ca_dir.mkdir(mode=0o700)
        now = datetime.now(timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'vs-router local management CA')])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        cert = self.server_certificate(state, ca_key, key)
        pem = serialization.Encoding.PEM
        private = lambda k: k.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()).decode()
        self.write(STATE_DIR / 'ca/ca.key', private(ca_key))
        self.write(STATE_DIR / 'ca/ca.crt', ca.public_bytes(pem).decode(), 0o644)
        target.mkdir(mode=0o750)
        os.chown(target, -1, self.caddy_gid)
        self.write(TLS_DIR / 'server.key', private(key), 0o640, self.caddy_gid)
        self.write(TLS_DIR / 'server.crt', cert.public_bytes(pem).decode(), 0o640, self.caddy_gid)
        self.write(TLS_DIR / 'ca.crt', ca.public_bytes(pem).decode(), 0o644, self.caddy_gid)
        return ca

    def provision(self, mac, address):
        state_dir = self.path(STATE_DIR)
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state_dir, 0o700)
        ports = wired_ports(self.path('/sys/class/net'))
        matches = [name for name, value in ports.items() if value == mac.lower()]
        if len(ports) < 2 or len(matches) != 1:
            raise ValueError('management.separate_wired_port_required')
        uplink, uplink_mac = (state_dir / 'installer-uplink').read_text().split()
        if (not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,14}', uplink)
                or ports.get(uplink) != uplink_mac or matches[0] == uplink):
            raise ValueError('management.uplink_mismatch')
        state = Management(interface=matches[0], mac=mac.lower(), address=address)
        previous = read_management(state_dir / 'management.json')
        if previous is not None and previous != state:
            raise ValueError('management.migration_not_supported')
        # Provisioning is exclusively pre-apply. Never replace an applied state.
        if (self.path('/etc/vs-router/applied/snapshot.json').exists()
                or self.path('/etc/vs-router/marker.json').exists()):
            raise ValueError('management.already_applied')
        network_path = Path(f'/etc/systemd/network/10-vs-router-{state.interface}.network')
        manifest_path = Path('/etc/vs-router/networkd-manifest.conf')
        manifest = deserialize_networkd(self.path(manifest_path).read_text())
        existing = self.path(network_path)
        if existing.exists() and manifest.get(existing.name) != existing.read_text():
            raise ValueError('management.network_ownership_conflict')
        expected_caddy = generate_caddy_json(ConfigurationVersion(), state)
        caddy_path = self.path('/etc/caddy/caddy.json')
        if caddy_path.exists():
            current = json.loads(caddy_path.read_text())
            if current.get('apps') and current != expected_caddy:
                raise ValueError('management.caddy_ownership_conflict')
        # Record identity before mutations, so a failed retry cannot silently move LAN.
        self.write(STATE_DIR / 'management.json', state.model_dump_json())
        ca = self.certificates(state)
        network = (f'[Match]\nName={state.interface}\nMACAddress={state.mac}\n\n'
                   f'[Network]\nAddress={state.address}\nDHCP=no\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n')
        manifest[network_path.name] = network
        self.write(manifest_path, serialize_networkd(manifest))
        self.write(network_path, network, 0o644)
        rules = bootstrap_rules(state, uplink)
        self.write(STATE_DIR / 'management.nft', rules)
        self.runner(['nft', '-c', '-f', str(self.path(STATE_DIR / 'management.nft'))])
        self.runner(['nft', '-f', str(self.path(STATE_DIR / 'management.nft'))])
        self.runner(['systemctl', 'enable', '--now', 'systemd-networkd.service'])
        self.runner(['networkctl', 'reload'])
        self.runner(['networkctl', 'reconfigure', state.interface])
        self.runner(['/usr/lib/systemd/systemd-networkd-wait-online',
                     f'--interface={state.interface}:routable', '--ipv4', '--timeout=30'])
        assigned = self.runner(['ip', '-j', '-4', 'address', 'show', 'dev', state.interface])
        addresses = json.loads(assigned.stdout)
        from ipaddress import IPv4Interface
        expected_address = IPv4Interface(state.address)
        if not any(entry.get('ifname') == state.interface and any(
                addr.get('local') == state.ip and addr.get('prefixlen') == expected_address.network.prefixlen
                for addr in entry.get('addr_info', [])) for entry in addresses):
            raise ValueError('management.address_not_ready')
        self.write('/etc/caddy/caddy.json', json.dumps(expected_caddy),
                   0o640, self.caddy_gid)
        self.runner(['caddy', 'validate', '--config', str(self.path('/etc/caddy/caddy.json'))])
        for service in ('vs-router-agent', 'vs-router-web', 'caddy'):
            self.runner(['systemctl', 'restart', service])
            self.runner(['systemctl', 'is-active', '--quiet', service])
        # systemctl restart returns before Caddy has bound the LAN listener.
        # Verify real HTTPS, not only its unit state, with a bounded wait.
        probe = ['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                 '--cacert', str(self.path(TLS_DIR / 'ca.crt')), '--max-time', '3',
                 f'https://{state.ip}/health']
        for attempt in range(30):
            try:
                self.runner(probe)
                break
            except subprocess.CalledProcessError:
                if attempt == 29:
                    raise
                time.sleep(1)
        return state, ca.fingerprint(hashes.SHA256()).hex(':')


def bootstrap_rules(state, uplink):
    # Uplink is validated against the sysfs inventory before interpolation.
    return f'''destroy table inet vs_router
table inet vs_router {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        iifname "{state.interface}" ip daddr {state.ip} tcp dport 443 accept
        ip daddr {state.ip} tcp dport 443 drop
        ct state established,related accept
        iifname "{uplink}" udp sport 67 udp dport 68 accept
    }}
    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}
    chain output {{
        type filter hook output priority filter; policy accept;
    }}
}}
'''


def check():
    state = read_management()
    if state is None:
        if TLS_DIR.exists():
            raise ValueError('management.state_missing')
    else:
        verify_identity(state)


def main():
    parser = argparse.ArgumentParser(description='Assign first-run management LAN from the local root console')
    parser.add_argument('--mac', help='actual MAC of a separate wired LAN port')
    parser.add_argument('--address', default='192.168.10.1/24')
    parser.add_argument('--check', action='store_true', help='identity gate used at service startup')
    args = parser.parse_args()
    try:
        if args.check:
            check()
            return 0
        if os.geteuid() != 0 or not sys.stdin.isatty() or os.environ.get('SSH_CONNECTION'):
            raise ValueError('management.local_root_console_required')
        if not args.mac:
            parser.error('--mac is required; inspect ports with ip link from the local console')
        state, fingerprint = Console().provision(args.mac, args.address)
        print(f'Local HTTPS check passed: https://{state.ip}/')
        print(f'CA SHA-256: {fingerprint}')
        print('Assign the administrator computer an address in the same subnet. Verify HTTPS from LAN and denial from WAN before declaring LAN readiness.')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print('Management provisioning/check failed; inspect identity, ownership and service status from the local console. Panel readiness is NOT established.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
