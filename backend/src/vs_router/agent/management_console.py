"""Explicit root console provisioning; dependencies are injectable for host-free tests."""
import argparse
from datetime import datetime, timedelta, timezone
import grp
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from ipaddress import IPv4Address

from ..management import (Management, STATE_DIR, STATE_PATH, TLS_DIR, panel_probe_target,
                          read_management, verify_identity, with_hostname, wired_ports)
from ..schema import ConfigurationVersion
from ..generators.caddy import generate_caddy_json
from ..generators.nftables import generate_nftables
from ..generators.networkd import deserialize_networkd, serialize_networkd
from .apply import APPLIED_DIR, LocalFileSystem


def resolve_hostname(hostname):
    """Resolve a public name to at least one address; ``OSError`` when it does not.

    A name the host cannot resolve can never obtain an ACME certificate, so the
    panel rejects it before touching the live endpoint rather than locking the
    operator out with an unreachable publication.
    """
    socket.getaddrinfo(hostname, None)


class Console:
    def __init__(self, root=Path('/'), runner=None, caddy_gid=None, resolver=None):
        self.root = root
        self.runner = runner or self.run
        self.caddy_gid = grp.getgrnam('caddy').gr_gid if caddy_gid is None else caddy_gid
        self.resolver = resolver or resolve_hostname
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
        # systemctl restart returns before Caddy has bound the listener.
        # Verify real HTTPS, not only its unit state, with a bounded wait.
        self.probe_panel(state)
        return state, ca.fingerprint(hashes.SHA256()).hex(':')

    def live_address(self, interface):
        """The interface's current IPv4 address as ``a.b.c.d/prefix``, or None."""
        result = self.runner(['ip', '-j', '-4', 'address', 'show', 'dev', interface])
        try:
            entries = json.loads(result.stdout)
        except (ValueError, TypeError):
            return None
        for entry in entries:
            if entry.get('ifname') == interface:
                for addr in entry.get('addr_info', []):
                    if addr.get('family') == 'inet' and addr.get('local'):
                        return f"{addr['local']}/{addr['prefixlen']}"
        return None

    def provision_single_uplink(self, interface=None, address=None, hostname=None,
                                path_prefix=None, ssh_port=22):
        """One-NIC (VPS) provisioning, run over SSH: no console, no ISO markers.

        The uplink keeps its own addressing (DHCP or static); only the panel is
        published on it and SSH is left open, so a remote administrator is never
        locked out (ADR-0017). The record is created pre-apply only.
        """
        ports = wired_ports(self.path('/sys/class/net'))
        if len(ports) != 1:
            raise ValueError('management.single_port_required')
        name, mac = next(iter(ports.items()))
        if interface is not None and interface != name:
            raise ValueError('management.identity_mismatch')
        if address is None:
            address = self.live_address(name)
            if address is None:
                raise ValueError('management.address_unavailable')
        state = Management(interface=name, mac=mac, address=address,
                           mode='single-uplink', hostname=hostname, path_prefix=path_prefix)
        previous = read_management(self.path(STATE_PATH))
        if previous is not None and previous != state:
            raise ValueError('management.migration_not_supported')
        if (self.path('/etc/vs-router/applied/snapshot.json').exists()
                or self.path('/etc/vs-router/marker.json').exists()):
            raise ValueError('management.already_applied')
        expected_caddy = generate_caddy_json(ConfigurationVersion(), state)
        caddy_path = self.path('/etc/caddy/caddy.json')
        if caddy_path.exists():
            current = json.loads(caddy_path.read_text())
            if current.get('apps') and current != expected_caddy:
                raise ValueError('management.caddy_ownership_conflict')
        self.write(STATE_DIR / 'management.json', state.model_dump_json())
        ca = self.certificates(state)
        self.write('/etc/caddy/caddy.json', json.dumps(expected_caddy), 0o640, self.caddy_gid)
        self.runner(['caddy', 'validate', '--config', str(self.path('/etc/caddy/caddy.json'))])
        self.write(STATE_DIR / 'management.nft', single_uplink_rules(state, ssh_port))
        self.runner(['nft', '-c', '-f', str(self.path(STATE_DIR / 'management.nft'))])
        self.runner(['nft', '-f', str(self.path(STATE_DIR / 'management.nft'))])
        for service in ('vs-router-agent', 'vs-router-web', 'caddy'):
            self.runner(['systemctl', 'restart', service])
            self.runner(['systemctl', 'is-active', '--quiet', service])
        # Real HTTPS, not only unit state: with a public hostname the ACME
        # certificate may still be issuing, so allow a bounded wait and verify
        # against the system trust store rather than the local CA.
        self.probe_panel(state, attempts=60, delay=2)
        return state, ca.fingerprint(hashes.SHA256()).hex(':')

    def probe_panel(self, state, attempts=30, delay=1):
        """Wait until the panel answers over HTTPS, or re-raise the last failure.

        A public name is verified against the system trust store (its ACME
        certificate may still be issuing); the local-CA endpoint is verified
        against the host CA. ``/health`` sits outside any secret path prefix.
        """
        url, ca_file = panel_probe_target(state)
        probe = ['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                 '--max-time', '5']
        if ca_file is not None:
            probe += ['--cacert', str(self.path(ca_file))]
        probe.append(url)
        for attempt in range(attempts):
            try:
                self.runner(probe)
                return
            except subprocess.CalledProcessError:
                if attempt == attempts - 1:
                    raise
                time.sleep(delay)

    def applied_version(self):
        """The configuration currently in force, or an empty one before first apply."""
        try:
            payload = json.loads(self.fs.read(self.path(APPLIED_DIR / 'snapshot.json')))
        except (FileNotFoundError, ValueError):
            return ConfigurationVersion()
        return ConfigurationVersion.model_validate(payload)

    def _reload_panel(self, state):
        """Reload Caddy for a new management record and keep the firewall in step.

        Caddy is restarted, not reloaded: a changed listener/config is not
        guaranteed to be picked up otherwise. When a configuration is already
        applied its nftables is regenerated from the same version and the *new*
        record — opening the :80 ACME listener a public name needs, and removing
        it again when the name is cleared — and the live table is replaced.
        """
        path = self.path(APPLIED_DIR / 'nftables.conf')
        if self.path(APPLIED_DIR / 'snapshot.json').exists():
            self.write(APPLIED_DIR / 'nftables.conf',
                       generate_nftables(self.applied_version(), state))
            self.runner(['nft', '-c', '-f', str(path)])
            self.runner(['nft', '-f', str(path)])
        self.runner(['systemctl', 'restart', 'caddy'])

    def publish_panel_domain(self, hostname=None):
        """Republish the panel under a public name (or back to its IP) from the panel.

        Transactional TLS: the new management record and Caddy config are
        installed, Caddy is reloaded, and the public name must answer HTTPS (its
        ACME certificate verified against the system trust store) before the
        change is kept. Any failure — an unresolved name, a Caddy config the
        binary rejects, or a name that never issues — restores the previous
        record and config, so a bad domain cannot lock the operator out. This is
        the transactional step ADR-0017 required before the pinned endpoint may
        move. ``None`` clears the name and returns the panel to its IP endpoint.
        """
        state = read_management(self.path(STATE_PATH))
        if state is None:
            raise ValueError('management.state_missing')
        updated = with_hostname(state, hostname)
        if updated == state:
            return state
        if updated.hostname:
            try:
                self.resolver(updated.hostname)
            except OSError as exc:
                raise ValueError('management.domain_unresolved') from exc
        management_path = self.path(STATE_PATH)
        caddy_path = self.path('/etc/caddy/caddy.json')
        previous = {'management': management_path.read_text(),
                    'caddy': caddy_path.read_text() if caddy_path.exists() else None}
        self.write(STATE_PATH, updated.model_dump_json())
        self.write('/etc/caddy/caddy.json',
                   json.dumps(generate_caddy_json(self.applied_version(), updated)),
                   0o640, self.caddy_gid)
        self.runner(['caddy', 'validate', '--config', str(caddy_path)])
        self._reload_panel(updated)
        try:
            self.probe_panel(updated, attempts=60, delay=2)
        except (OSError, subprocess.SubprocessError) as exc:
            self.write(STATE_PATH, previous['management'])
            if previous['caddy'] is None:
                self.fs.remove(caddy_path)
            else:
                self.write('/etc/caddy/caddy.json', previous['caddy'], 0o640, self.caddy_gid)
            self._reload_panel(state)
            raise ValueError('management.domain_unverified') from exc
        return updated


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


def single_uplink_rules(state, ssh_port=22):
    """Temporary rules for a one-NIC box until the first apply (ADR-0017).

    The panel and SSH remain reachable on the single uplink; everything else is
    dropped. SSH stays open because a remote box has no local console to fall
    back on. Port 80 stays open too: ACME HTTP-01 challenges (and later renewals)
    arrive there, even though the panel itself is served over HTTPS. The panel's
    own generated ruleset replaces this at the first apply.
    """
    return f'''destroy table inet vs_router
table inet vs_router {{
    chain input {{
        type filter hook input priority filter; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "{state.interface}" ip daddr {state.ip} tcp dport 443 accept
        iifname "{state.interface}" ip daddr {state.ip} tcp dport 80 accept
        iifname "{state.interface}" tcp dport {ssh_port} accept
        iifname "{state.interface}" udp sport 67 udp dport 68 accept
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
    parser = argparse.ArgumentParser(description='Assign the first-run management endpoint')
    parser.add_argument('--mac', help='actual MAC of a separate wired LAN port')
    parser.add_argument('--address', default=None,
                        help='panel address/prefix; defaults to 192.168.10.1/24 (LAN) '
                             'or the live lease (--single-uplink)')
    parser.add_argument('--single-uplink', action='store_true',
                        help='one-NIC VPS: publish the panel on the uplink over SSH (keeps SSH open)')
    parser.add_argument('--interface', help='uplink interface for --single-uplink '
                                            '(default: the only wired port)')
    parser.add_argument('--hostname', help='public hostname for an ACME certificate, e.g. <ip>.nip.io')
    parser.add_argument('--path-prefix', dest='path_prefix', help='secret panel path, e.g. /uOE3flWG7hvM')
    parser.add_argument('--ssh-port', type=int, default=22,
                        help='SSH port kept open on a --single-uplink host (default 22)')
    parser.add_argument('--check', action='store_true', help='identity gate used at service startup')
    args = parser.parse_args()
    try:
        if args.check:
            check()
            return 0
        if os.geteuid() != 0:
            raise ValueError('management.root_required')
        if args.single_uplink:
            state, fingerprint = Console().provision_single_uplink(
                interface=args.interface, address=args.address,
                hostname=args.hostname, path_prefix=args.path_prefix,
                ssh_port=args.ssh_port)
            print(f'Panel: https://{state.hostname or state.ip}{state.path_prefix or ""}/')
            print(f'CA SHA-256: {fingerprint}')
            print('SSH and the panel are open on the uplink; '
                  'everything else is dropped until the first apply.')
            return 0
        if not sys.stdin.isatty() or os.environ.get('SSH_CONNECTION'):
            raise ValueError('management.local_root_console_required')
        if not args.mac:
            parser.error('--mac is required; inspect ports with ip link from the local console')
        state, fingerprint = Console().provision(args.mac, args.address or '192.168.10.1/24')
        print(f'Local HTTPS check passed: https://{state.ip}/')
        print(f'CA SHA-256: {fingerprint}')
        print('Assign the administrator computer an address in the same subnet. Verify HTTPS from LAN and denial from WAN before declaring LAN readiness.')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Management provisioning/check failed ({error}); inspect identity, '
              'ownership and service status from the local console. '
              'Panel readiness is NOT established.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
