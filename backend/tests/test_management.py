"""All host effects use temporary trees or injected executors; no live services."""
import json
import os
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from vs_router.management import (Management, verify_identity, validate_management,
                                  validate_site_bindings, unmanaged_host_interfaces)
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.generators.caddy import generate_caddy_json
from vs_router.generators.nftables import generate_nftables
from vs_router.agent.management_console import Console
from vs_router.agent.apply import ApplyEngine, ApplyError, APPLIED_DIR
from vs_router.agent.network_ownership import foreign_owner, host_config_candidates
from test_agent_apply import FakeFS, FakeExecutor

STATE = Management(interface='eth1', mac='02:00:00:00:00:02', address='192.168.10.1/24')
# The operator's own panel domain in these tests. Our server's name, deliberately
# NOT the work machine's: a live-looking domain in a fixture is a name someone
# will eventually point a probe at.
CUSTOM = 'rg4.poshl9k.ru'


def recording_runner(calls, address='192.168.10.1'):
    def run(argv):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps([{'ifname': 'eth1', 'addr_info': [
            {'local': address, 'prefixlen': 24}]}]))
    return run


def version(**changes):
    config = {'interfaces': [{'name': 'eth0', 'zone': 'wan'},
                             {'name': 'eth1', 'zone': 'lan', 'addresses': [STATE.address]}]}
    config.update(changes)
    return ConfigurationVersion(configuration=Configuration.model_validate(config))


def host(tmp_path):
    for index in (0, 1):
        port = tmp_path / f'sys/class/net/eth{index}'
        (port / 'device').mkdir(parents=True)
        (port / 'address').write_text(f'02:00:00:00:00:0{index + 1}\n')
        (port / 'type').write_text('1\n')
    directory = tmp_path / 'var/lib/vs-router-bootstrap'
    directory.mkdir(parents=True)
    (directory / 'installer-uplink').write_text('eth0 02:00:00:00:00:01\n')
    directory = tmp_path / 'etc/vs-router'
    directory.mkdir(parents=True)
    (directory / 'networkd-manifest.conf').write_text('')
    (tmp_path / 'etc/caddy').mkdir(parents=True)


def test_provision_and_retry_preserve_keys_and_ownership(tmp_path):
    host(tmp_path)
    calls = []
    console = Console(tmp_path, recording_runner(calls), os.getgid())
    state, fingerprint = console.provision(STATE.mac, STATE.address)
    assert state == STATE
    ca_key = tmp_path / 'var/lib/vs-router-bootstrap/ca/ca.key'
    original = ca_key.read_bytes()
    assert ca_key.stat().st_mode & 0o777 == 0o600
    cert = x509.load_pem_x509_certificate((tmp_path / 'etc/caddy/management/server.crt').read_bytes())
    ca = x509.load_pem_x509_certificate((ca_key.parent / 'ca.crt').read_bytes())
    cert.verify_directly_issued_by(ca)
    assert ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert fingerprint == ca.fingerprint(hashes.SHA256()).hex(':')
    console.provision(STATE.mac, STATE.address)
    assert ca_key.read_bytes() == original
    assert any(c[0] == 'curl' and '--cacert' in c for c in calls)
    assert not any('apt' in c or 'ssh' in c for c in calls)
    rules = (tmp_path / 'var/lib/vs-router-bootstrap/management.nft').read_text()
    assert 'iifname "eth1" ip daddr 192.168.10.1 tcp dport 443 accept' in rules
    assert 'iifname "eth0" udp sport 67 udp dport 68 accept' in rules
    assert rules.index('tcp dport 443 drop') < rules.index('ct state established')
    with pytest.raises(ValueError, match='migration_not_supported'):
        console.provision(STATE.mac, '192.168.20.1/24')


def test_legacy_leaf_is_reissued_without_rotating_ca(tmp_path):
    host(tmp_path)
    console = Console(tmp_path, recording_runner([]), os.getgid())
    console.provision(STATE.mac, STATE.address)
    ca_path = tmp_path / 'etc/caddy/management/ca.crt'
    ca_before = ca_path.read_bytes()
    ca = x509.load_pem_x509_certificate(ca_before)
    ca_key = serialization.load_pem_private_key(
        (tmp_path / 'var/lib/vs-router-bootstrap/ca/ca.key').read_bytes(), None)
    key_path = tmp_path / 'etc/caddy/management/server.key'
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    legacy = (x509.CertificateBuilder()
              .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, STATE.ip)]))
              .issuer_name(ca.subject).public_key(key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
              .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(IPv4Address(STATE.ip))]), False)
              .sign(ca_key, hashes.SHA256()))
    cert_path = tmp_path / 'etc/caddy/management/server.crt'
    cert_path.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
    console.provision(STATE.mac, STATE.address)
    assert ca_path.read_bytes() == ca_before
    renewed = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert renewed.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier


@pytest.mark.parametrize('problem', ['one_port', 'mac', 'name', 'wireless', 'uplink'])
def test_provision_refuses_identity_problem_without_host_commands(tmp_path, problem):
    host(tmp_path)
    port = tmp_path / 'sys/class/net/eth1'
    if problem == 'one_port':
        (port / 'device').rmdir()
    elif problem == 'mac':
        (port / 'address').write_text('02:00:00:00:00:03')
    elif problem == 'name':
        port.rename(port.with_name('renamed'))
        with pytest.raises(ValueError):
            verify_identity(STATE, tmp_path / 'sys/class/net')
        return
    elif problem == 'wireless':
        (port / 'wireless').mkdir()
    calls = []
    with pytest.raises(ValueError):
        Console(tmp_path, recording_runner(calls), os.getgid()).provision(
            '02:00:00:00:00:01' if problem == 'uplink' else STATE.mac, STATE.address)
    assert calls == []


def test_failed_startup_never_reports_readiness(tmp_path):
    host(tmp_path)
    def fail(argv):
        if argv[0] == 'curl':
            raise OSError('unavailable')
        return recording_runner([])(argv)
    with pytest.raises(OSError):
        Console(tmp_path, fail, os.getgid()).provision(STATE.mac, STATE.address)
    assert (tmp_path / 'var/lib/vs-router-bootstrap/management.json').exists()


def test_panel_exists_without_sites_and_rejects_unusable_bindings():
    config = generate_caddy_json(version(), STATE)
    panel = config['apps']['http']['servers']['management']
    assert panel['listen'] == ['192.168.10.1:443']
    assert panel['routes'][0]['handle'][0]['upstreams'][0]['dial'].startswith('unix//')
    site = {'name': 'app', 'hostname': 'app.example.com', 'upstream': '127.0.0.1:9000', 'certificate_mode': 'passthrough'}
    # A dynamic (addressless) WAN gives a site no anchor: an actionable code,
    # not the opaque management conflict.
    with pytest.raises(ValueError, match='caddy.wan_address_unavailable'):
        generate_caddy_json(version(sites=[site]), STATE)
    # A site explicitly binding the management IP shadows it → conflict.
    conflict = version(sites=[dict(site, wan_address=STATE.ip)], interfaces=[
        {'name': 'eth0', 'zone': 'wan', 'addresses': [STATE.address]},
        {'name': 'eth1', 'zone': 'lan', 'addresses': [STATE.address]}])
    with pytest.raises(ValueError, match='site_binding_conflict'):
        generate_caddy_json(conflict, STATE)
    site['wan_address'] = '203.0.113.2'
    site['certificate_mode'] = 'http01'
    configured = version(sites=[site], interfaces=[
        {'name': 'eth0', 'zone': 'wan', 'addresses': ['203.0.113.2/24']},
        {'name': 'eth1', 'zone': 'lan', 'addresses': [STATE.address]}])
    assert len(generate_caddy_json(configured, STATE)['apps']['http']['servers']) >= 2


@pytest.mark.parametrize('changes,code', [
    ({'interfaces': []}, 'management.endpoint_required'),
    ({'panel_port': 8443}, 'management.endpoint_required'),
    ({'interfaces': [{'name': 'eth1', 'zone': 'wan', 'addresses': [STATE.address]}]},
     'management.endpoint_required'),
    ({'port_forwards': [{'name': 'hijack', 'interface': 'eth0', 'protocol': 'tcp',
                         'external_port': 443, 'target': '192.168.10.2', 'target_port': 443}]},
     'management.port_reserved'),
    ({'sites': [{'name': 's', 'hostname': 'a.example.com', 'upstream': '127.0.0.1:9000',
                 'certificate_mode': 'passthrough'}]},
     'caddy.wan_address_unavailable'),
])
def test_guard_rejects_before_mutations(changes, code):
    """The specific guard code is surfaced, not one opaque code."""
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(), management_provider=lambda: STATE)
    with pytest.raises(ApplyError, match=code) as exc:
        engine.apply_version(version(**changes).model_dump(mode='json'))
    assert exc.value.code == code
    assert not fs.files


def test_guard_code_keeps_a_generic_fallback():
    from vs_router.agent.apply import guard_code
    assert guard_code(ValueError('management.endpoint_required')) == 'management.endpoint_required'
    assert guard_code(ValueError('management.site_binding_conflict')) == 'management.site_binding_conflict'
    assert guard_code(ValueError('caddy.wan_address_unavailable')) == 'caddy.wan_address_unavailable'
    assert guard_code(ValueError('boom, not a code')) == 'management.access_invalid'


def test_apply_without_console_assigned_management_is_rejected_before_mutation():
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(),
                         management_provider=lambda: None,
                         panel_probe=lambda: pytest.fail('no network probe before LAN assignment'))
    with pytest.raises(ApplyError, match='management.assignment_required'):
        engine.apply_version(version().model_dump(mode='json'))
    assert not fs.files


def test_panel_probe_without_management_never_uses_unix_socket(monkeypatch):
    from vs_router.agent import daemon
    monkeypatch.setattr('vs_router.management.host_management', lambda: None)
    monkeypatch.setattr(daemon.socket, 'socket',
                        lambda *a, **kw: pytest.fail('Unix API is not LAN HTTPS'))
    assert daemon.panel_probe() is False


def test_panel_probe_requires_https_with_management_ca(monkeypatch):
    from vs_router.agent import daemon
    from vs_router.management import TLS_DIR
    monkeypatch.setattr('vs_router.management.host_management', lambda: STATE)
    calls = []
    context = object()
    monkeypatch.setattr(ssl, 'create_default_context',
                        lambda cafile: calls.append(cafile) or context)
    connection = MagicMock()
    connection.getresponse.return_value.status = 200
    factory = MagicMock(return_value=connection)
    monkeypatch.setattr(daemon.http.client, 'HTTPSConnection', factory)
    assert daemon.panel_probe() is True
    assert calls == [str(TLS_DIR / 'ca.crt')]
    factory.assert_called_once_with('192.168.10.1', 443, context=context, timeout=5)
    connection.request.assert_called_once_with('GET', '/health', headers={'Connection': 'close'})
    connection.close.assert_called_once()


def test_panel_probe_natted_hostname_uses_resolve_and_verifies_tls(tmp_path, monkeypatch):
    """A public name need not resolve locally when its management IP serves TLS."""
    from vs_router.agent import daemon
    from vs_router.management import panel_probe_targets

    name = 'panel.invalid'  # RFC 6761: DNS never points this name at localhost.
    state = STATE.model_copy(update={'address': '127.0.0.1/24',
                                     'mode': 'single-uplink', 'hostname': 'reserve.invalid',
                                     'custom_hostname': name})
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
                   .sign(key, hashes.SHA256()))
    ca_file = tmp_path / 'ca.crt'
    ca_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file = tmp_path / 'server.key'
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    received, sni, statuses = [], [], [200]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append((self.path, self.headers['Host']))
            self.send_response(statuses[0])
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(ca_file), str(key_file))
    context.set_servername_callback(lambda _sock, host, _ctx: sni.append(host))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        original = list(panel_probe_targets(state))
        assert original[0][2] == f'{name}:443:127.0.0.1'
        assert original[1][2] is None
        assert original[2][2] == 'reserve.invalid:443:127.0.0.1'
        # The shipped target uses :443; translate only its port for an unprivileged server.
        targets = tuple((url.replace('/health', f':{port}/health'), ca_file,
                         resolve.replace(':443:', f':{port}:') if resolve else None)
                        for url, _ca, resolve in original)
        monkeypatch.setattr('vs_router.management.host_management', lambda: state)
        monkeypatch.setattr('vs_router.management.panel_probe_targets', lambda _state: targets)
        lookup = socket.getaddrinfo

        def no_published_name_lookup(host, *args, **kwargs):
            assert host not in (name, 'reserve.invalid')
            return lookup(host, *args, **kwargs)

        monkeypatch.setattr(socket, 'getaddrinfo', no_published_name_lookup)
        monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
        assert daemon.panel_probe() is True
        assert received == [('/health', f'{name}:{port}')]
        assert sni == [name]

        # Keep just one failing target so neither DNS nor a reserve name can rescue it.
        with socket.socket() as unused:
            unused.bind(('127.0.0.1', 0))
            closed_port = unused.getsockname()[1]
        failed = (f'https://{name}:{closed_port}/health', ca_file,
                  f'{name}:{closed_port}:127.0.0.1')
        monkeypatch.setattr('vs_router.management.panel_probe_targets', lambda _state: (failed,))
        assert daemon.panel_probe() is False
        assert len(received) == 1
        monkeypatch.setattr('vs_router.management.panel_probe_targets',
                            lambda _state: (failed, targets[0]))
        assert daemon.panel_probe() is True  # Keep target order; stop on first 200.
        assert len(received) == 2
        statuses[0] = 503
        monkeypatch.setattr('vs_router.management.panel_probe_targets', lambda _state: (targets[0],))
        assert daemon.panel_probe() is False
        assert len(received) == 3
        statuses[0] = 200

        monkeypatch.setattr('vs_router.management.panel_probe_targets',
                            lambda _state: ((targets[0][0], None, targets[0][2]),))
        assert daemon.panel_probe() is False  # The system store does not trust this cert.
        assert len(received) == 3

        mismatch = (f'https://wrong.invalid:{port}/health', ca_file,
                    f'wrong.invalid:{port}:127.0.0.1')
        monkeypatch.setattr('vs_router.management.panel_probe_targets', lambda _state: (mismatch,))
        assert daemon.panel_probe() is False
        assert len(received) == 3
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_guarded_first_apply_and_rollback_preserve_panel():
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(), management_provider=lambda: STATE,
                         panel_probe=lambda: True)
    snapshot = version().model_dump(mode='json')
    assert engine.apply_version(snapshot, safe_mode=True).status == 'confirmed'
    assert engine.status()['deadline'] is None
    assert 'MACAddress=' + STATE.mac in fs.read(APPLIED_DIR / 'networkd.conf')
    assert 'management' in fs.read(APPLIED_DIR / 'caddy.conf')
    original = fs.read(APPLIED_DIR / 'caddy.conf')
    assert engine.apply_version(dict(snapshot, id=2), safe_mode=True).status == 'pending'
    assert engine.rollback('test').status == 'rolled_back'
    assert fs.read(APPLIED_DIR / 'caddy.conf') == original
    nft = generate_nftables(version(anti_lockout=False), STATE)
    assert nft.index('comment "management"') < nft.index('ct state established')
    assert 'ip daddr 192.168.10.1 tcp dport 443 drop' in nft


def test_first_apply_failure_does_not_attempt_nonexistent_rollback():
    def fail(path):
        raise OSError('service failed')
    engine = ApplyEngine(filesystem=FakeFS(), executor=FakeExecutor(),
                         management_provider=lambda: STATE, panel_probe=lambda: True,
                         reload_commands={'nftables': fail})
    assert engine.apply_version(version().model_dump(mode='json')).status == 'failed'


def test_management_lan_edits_force_timer_even_when_default_off():
    engine = ApplyEngine(filesystem=FakeFS(), executor=FakeExecutor(), management_provider=lambda: STATE,
                         panel_probe=lambda: True)
    snapshot = version().model_dump(mode='json')
    engine.apply_version(snapshot)
    snapshot['id'] = 2
    snapshot['configuration']['interfaces'][1]['addresses'].append('192.168.20.1/24')
    assert engine.apply_version(snapshot, safe_mode=False).status == 'pending'
    assert engine.status()['deadline'] is not None


def test_boot_identity_failure_stops_before_restoration(monkeypatch):
    from vs_router.agent import boot_restore, management_console
    def fail():
        raise ValueError('management.identity_mismatch')
    monkeypatch.setattr(management_console, 'check', fail)
    monkeypatch.setattr(boot_restore, 'restore_tunnel_proxy_files',
                        lambda: pytest.fail('must not restore listeners'))
    monkeypatch.setattr(boot_restore, 'run', lambda _: pytest.fail('must not load applied firewall'))
    assert boot_restore.main() == 1


def test_boot_restores_bootstrap_firewall_before_services(tmp_path, monkeypatch):
    from vs_router.agent import boot_restore, management_console
    from vs_router import management
    calls = []
    monkeypatch.setattr(management_console, 'check', lambda: None)
    monkeypatch.setattr(management, 'read_management', lambda: STATE)
    monkeypatch.setattr(management, 'STATE_DIR', tmp_path)
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path / 'applied'))
    monkeypatch.setattr(boot_restore, 'run', lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(boot_restore, 'restore_tunnel_proxy_files', lambda: calls.append('proxy') or 0)
    monkeypatch.setattr(boot_restore, 'restore_ssh', lambda: calls.append('ssh') or None)
    assert boot_restore.main() == 0
    assert calls == [['/usr/sbin/nft', '-f', str(tmp_path / 'management.nft')],
                     ['/usr/sbin/sysctl', '-w', 'net.ipv4.ip_forward=1'],
                     'proxy', 'ssh']


def test_first_apply_https_probe_failure_does_not_confirm():
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(),
                         management_provider=lambda: STATE, panel_probe=lambda: False)
    with pytest.raises(ApplyError, match='panel.unavailable'):
        engine.apply_version(version().model_dump(mode='json'))
    assert not fs.files


def test_first_apply_without_https_probe_is_rejected_before_mutation():
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(), management_provider=lambda: STATE)
    with pytest.raises(ApplyError, match='panel.unavailable'):
        engine.apply_version(version().model_dump(mode='json'))
    assert not fs.files


def test_provision_preserves_unowned_configuration(tmp_path):
    host(tmp_path)
    caddy = tmp_path / 'etc/caddy/caddy.json'
    original = '{"apps":{"http":{"servers":{"custom":{}}}}}'
    caddy.write_text(original)
    calls = []
    with pytest.raises(ValueError, match='ownership_conflict'):
        Console(tmp_path, recording_runner(calls), os.getgid()).provision(STATE.mac, STATE.address)
    assert caddy.read_text() == original
    assert not calls
    assert not (tmp_path / 'var/lib/vs-router-bootstrap/management.json').exists()


def test_wrong_actual_lan_address_never_starts_caddy(tmp_path):
    host(tmp_path)
    calls = []
    with pytest.raises(ValueError, match='address_not_ready'):
        Console(tmp_path, recording_runner(calls, '192.168.99.1'), os.getgid()).provision(
            STATE.mac, STATE.address)
    assert ['systemctl', 'restart', 'caddy'] not in calls


def test_ifupdown_uplink_is_foreign_only_when_named_in_host_config(tmp_path):
    """A Debian ifupdown lease must not be replaced by panel networkd config."""
    etc = tmp_path / 'etc'
    netplan = etc / 'netplan'  # Absent on the affected Debian host.
    networkd = etc / 'systemd/network'
    networkd.mkdir(parents=True)
    ifupdown = etc / 'network'
    ifupdown.mkdir()
    interfaces = ifupdown / 'interfaces'
    snippets = ifupdown / 'interfaces.d'
    snippets.mkdir()
    ours = networkd / '10-vs-router-ens192.network'
    ours.write_text('[Match]\nName=ens192\n')

    def candidates():
        return list(host_config_candidates(netplan, (networkd,), ifupdown_dir=ifupdown))

    # Our existing networkd file is never mistaken for an outside owner.
    assert dict(candidates()) == {str(ours): '[Match]\nName=ens192\n'}
    assert foreign_owner('ens192', candidates()) is False
    interfaces.write_text('allow-hotplug ens192\niface ens192 inet dhcp\n')
    found = candidates()
    assert dict(found)[str(interfaces)] == interfaces.read_text()
    assert foreign_owner('ens192', found) is True
    assert foreign_owner('ens19', found) is False
    record = SimpleNamespace(interface='ens192')
    assert unmanaged_host_interfaces('panel', record,
                                     foreign_owner=lambda name: foreign_owner(name, found)) == \
        frozenset({'ens192'})

    interfaces.write_text('iface eth0 inet dhcp\n')
    assert foreign_owner('ens192', candidates()) is False
    interfaces.write_text('iface ens19 inet dhcp\n')
    assert foreign_owner('ens192', candidates()) is False
    interfaces.unlink()
    snippet = snippets / 'uplink'
    snippet.write_text('allow-hotplug ens192\niface ens192 inet dhcp\n')
    found = candidates()
    assert dict(found)[str(snippet)] == snippet.read_text()
    assert foreign_owner('ens192', found) is True
    snippet.unlink()
    found = candidates()
    assert found == [(str(ours), ours.read_text())]
    assert foreign_owner('ens192', found) is False
    assert unmanaged_host_interfaces('panel', record,
                                     foreign_owner=lambda name: foreign_owner(name, found)) == \
        frozenset()


# --- ADR-0017: single-uplink (one-NIC VPS) management -----------------------

VPS = Management(interface='eth0', mac='02:00:00:00:00:01',
                 address='92.51.36.131/24', mode='single-uplink')
# The install-time reserve name the online installer seeds (ADR-0017).
RESERVE = VPS.model_copy(update={'hostname': '92.51.36.131.nip.io'})


def one_port(tmp_path):
    port = tmp_path / 'sys/class/net/eth0'
    (port / 'device').mkdir(parents=True)
    (port / 'address').write_text('02:00:00:00:00:01\n')
    (port / 'type').write_text('1\n')
    return tmp_path / 'sys/class/net'


def vps_wan():
    return Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp'}],
        'ssh': {'interfaces': ['eth0'], 'wan_confirmed_interfaces': ['eth0']},
    })


def test_single_uplink_identity_accepts_one_wired_port(tmp_path):
    sysnet = one_port(tmp_path)
    verify_identity(VPS, sysnet)
    # The same single port is not enough for a separate-lan panel.
    with pytest.raises(ValueError, match='management.identity_mismatch'):
        verify_identity(Management(interface='eth0', mac='02:00:00:00:00:01',
                                   address='192.168.10.1/24'), sysnet)
    # A MAC that is not the port's own is still refused.
    with pytest.raises(ValueError, match='management.identity_mismatch'):
        verify_identity(VPS.model_copy(update={'mac': '02:00:00:00:00:99'}), sysnet)


def test_single_uplink_management_allows_a_dhcp_wan_uplink():
    validate_management(vps_wan(), VPS)
    with pytest.raises(ValueError, match='management.dhcp_forbidden'):
        validate_management(vps_wan(), VPS.model_copy(update={'mode': 'separate-lan'}))


def test_single_uplink_static_uplink_must_own_the_panel_address():
    static = Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'static',
                        'addresses': ['92.51.36.131/24']}],
    })
    validate_management(static, VPS)
    other = static.model_copy(update={'interfaces': tuple(
        i.model_copy(update={'addresses': ('92.51.36.200/24',)}) for i in static.interfaces)})
    with pytest.raises(ValueError, match='management.endpoint_required'):
        validate_management(other, VPS)


def test_single_uplink_reserves_443_from_port_forwards():
    forwarded = Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp'}],
        'port_forwards': [{'name': 'p', 'interface': 'eth0', 'protocol': 'tcp',
                           'external_port': 443, 'target': '10.0.0.2', 'target_port': 443}],
    })
    with pytest.raises(ValueError, match='management.port_reserved'):
        validate_management(forwarded, VPS)


def test_single_uplink_site_on_the_panel_address_is_allowed():
    version = ConfigurationVersion(configuration=Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'static',
                        'addresses': ['92.51.36.131/24']}],
        'sites': [{'name': 'web', 'hostname': 'web.example.org', 'upstream': '10.0.0.2:443',
                   'certificate_mode': 'http01', 'wan_address': '92.51.36.131'}],
    }))
    validate_site_bindings(version, VPS)
    with pytest.raises(ValueError, match='management.site_binding_conflict'):
        validate_site_bindings(version, VPS.model_copy(update={'mode': 'separate-lan'}))


def test_caddy_publishes_panel_with_acme_hostname_and_secret_path():
    state = VPS.model_copy(update={'hostname': '92.51.36.131.nip.io',
                                   'path_prefix': '/uOE3flWG7hvM'})
    config = generate_caddy_json(ConfigurationVersion(), state)
    server = config['apps']['http']['servers']['management']
    assert server['listen'] == ['92.51.36.131:443']
    assert server['tls_connection_policies'] == [{'default_sni': '92.51.36.131.nip.io'}]
    # ACME HTTP-01: the name is automated and no local-CA cert is loaded.
    tls = config['apps']['tls']['certificates']
    assert '92.51.36.131.nip.io' in tls['automate']
    assert 'load_files' not in tls
    assert config['apps']['tls']['automation']['policies'][0]['issuers'][0]['module'] == 'acme'
    assert config['apps']['http']['servers']['management_acme']['listen'] == ['92.51.36.131:80']
    # The panel and API live under the prefix; the root 404s; /health stays open.
    assert server['routes'][0]['match'] == [{'path': ['/health']}]
    assert server['routes'][1]['match'] == [{'path': ['/uOE3flWG7hvM/*']}]
    assert server['routes'][1]['handle'][0] == {'handler': 'rewrite',
                                                'strip_path_prefix': '/uOE3flWG7hvM'}
    assert server['routes'][2]['handle'][0]['status_code'] == 404


def test_caddy_panel_without_hostname_keeps_the_local_ca():
    config = generate_caddy_json(ConfigurationVersion(), VPS)
    server = config['apps']['http']['servers']['management']
    assert server['listen'] == ['92.51.36.131:443']
    assert server['routes'] == [{'handle': [{'handler': 'reverse_proxy', 'upstreams': [
        {'dial': 'unix//run/vs-router/web/web.sock'}]}]}]
    assert server['tls_connection_policies'][0]['certificate_selection'] == {'any_tag': ['management']}
    assert config['apps']['tls']['certificates']['load_files'][0]['tags'] == ['management']
    assert 'automate' not in config['apps']['tls']['certificates']
    assert 'management_acme' not in config['apps']['http']['servers']


# --- ADR-0017: headless one-NIC provisioning --------------------------------

def vps_host(tmp_path):
    port = tmp_path / 'sys/class/net/eth0'
    (port / 'device').mkdir(parents=True)
    (port / 'address').write_text('02:00:00:00:00:01\n')
    (port / 'type').write_text('1\n')
    (tmp_path / 'etc/caddy').mkdir(parents=True)


def vps_runner(calls, iface='eth0', address='92.51.36.131'):
    def run(argv):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps([{'ifname': iface, 'addr_info': [
            {'family': 'inet', 'local': address, 'prefixlen': 24}]}]))
    return run


def test_single_uplink_provision_uses_the_live_lease_and_keeps_ssh(tmp_path):
    vps_host(tmp_path)
    calls = []
    console = Console(tmp_path, vps_runner(calls), os.getgid())
    state, fingerprint = console.provision_single_uplink(
        hostname='92.51.36.131.nip.io', ssh_port=2222)
    assert (state.mode, state.interface, state.address) == ('single-uplink', 'eth0', '92.51.36.131/24')
    record = json.loads((tmp_path / 'var/lib/vs-router-bootstrap/management.json').read_text())
    assert record['mode'] == 'single-uplink' and record['hostname'] == '92.51.36.131.nip.io'
    # No ISO-path markers are required.
    assert not (tmp_path / 'var/lib/vs-router-bootstrap/installer-uplink').exists()
    rules = (tmp_path / 'var/lib/vs-router-bootstrap/management.nft').read_text()
    assert 'tcp dport 443 accept' in rules
    assert 'tcp dport 80 accept' in rules
    assert 'tcp dport 2222 accept' in rules
    caddy = json.loads((tmp_path / 'etc/caddy/caddy.json').read_text())
    assert caddy['apps']['http']['servers']['management_acme']['listen'] == ['92.51.36.131:80']
    assert any(c[0] == 'curl' for c in calls)


def test_single_uplink_provision_stores_both_public_names(tmp_path, capsys):
    from vs_router.management import publication_names, read_management

    vps_host(tmp_path)
    calls = []
    state, _ = Console(tmp_path, vps_runner(calls), os.getgid()).provision_single_uplink(
        hostname='92.51.36.131.nip.io', custom_hostname='panel.example.com')
    stored = read_management(tmp_path / 'var/lib/vs-router-bootstrap/management.json')
    assert stored is not None
    assert stored == state
    assert stored.hostname == '92.51.36.131.nip.io'
    assert stored.custom_hostname == 'panel.example.com'
    assert publication_names(stored) == ('92.51.36.131.nip.io', 'panel.example.com')
    probes = [c for c in calls if c[0] == 'curl']
    assert len(probes) == 1
    # The name being published is the one verified — the operator's own domain
    # here — reached over the local management address so NAT cannot hide it.
    assert probes[0][-1] == 'https://panel.example.com/health'
    assert probes[0][probes[0].index('--resolve') + 1] == 'panel.example.com:443:92.51.36.131'
    stderr = capsys.readouterr().err
    assert stderr == 'Panel readiness verified via local 92.51.36.131.\n'
    assert 'WARNING' not in stderr


def test_single_uplink_provision_refuses_duplicate_names_before_writing(tmp_path):
    vps_host(tmp_path)
    calls = []
    console = Console(tmp_path, vps_runner(calls), os.getgid())
    with pytest.raises(ValueError, match='^management.hostname_duplicate$'):
        console.provision_single_uplink(address=VPS.address, hostname='panel.example.com',
                                        custom_hostname='panel.example.com')
    assert not (tmp_path / 'var/lib/vs-router-bootstrap/management.json').exists()
    assert not (tmp_path / 'etc/caddy/caddy.json').exists()
    assert calls == []


@pytest.mark.parametrize('hostname', ['panel.example.com', '203.0.113.9.nip.io'])
def test_single_uplink_provision_warns_about_non_host_reserve(tmp_path, capsys, hostname):
    vps_host(tmp_path)
    state, _ = Console(tmp_path, vps_runner([]), os.getgid()).provision_single_uplink(
        hostname=hostname)
    warning = capsys.readouterr().err
    assert 'WARNING' in warning
    assert f'--custom-hostname {hostname}' in warning
    assert '--hostname 92.51.36.131.nip.io' in warning
    record = json.loads((tmp_path / 'var/lib/vs-router-bootstrap/management.json').read_text())
    assert record['hostname'] == state.hostname == hostname
    assert record['custom_hostname'] is None


def test_single_uplink_provision_does_not_warn_about_host_reserve(tmp_path, capsys):
    vps_host(tmp_path)
    state, _ = Console(tmp_path, vps_runner([]), os.getgid()).provision_single_uplink(
        hostname='92.51.36.131.nip.io')
    stderr = capsys.readouterr().err
    assert stderr == 'Panel readiness verified via local 92.51.36.131.\n'
    assert 'WARNING' not in stderr
    assert state.custom_hostname is None


@pytest.mark.parametrize('field', ['hostname', 'custom_hostname'])
def test_single_uplink_provision_validates_both_names_before_writing(tmp_path, field):
    from pydantic import ValidationError

    vps_host(tmp_path)
    calls = []
    console = Console(tmp_path, vps_runner(calls), os.getgid())
    with pytest.raises(ValidationError):
        console.provision_single_uplink(address=VPS.address, **{field: 'not a name'})
    assert not (tmp_path / 'var/lib/vs-router-bootstrap/management.json').exists()
    assert calls == []


@pytest.mark.parametrize('extra', [[], ['--check']])
def test_management_cli_refuses_custom_name_without_single_uplink(monkeypatch, capsys, extra):
    from vs_router.agent import management_console

    monkeypatch.setattr('sys.argv', ['management_console', '--custom-hostname',
                                    'panel.example.com', *extra])
    monkeypatch.setattr(management_console, 'Console',
                        lambda: pytest.fail('invalid CLI must not construct a host console'))
    monkeypatch.setattr(management_console, 'check',
                        lambda: pytest.fail('invalid CLI must not check host identity'))
    assert management_console.main() == 1
    assert 'management.custom_hostname_requires_single_uplink' in capsys.readouterr().err


@pytest.mark.parametrize('hostname,custom_hostname,primary', [
    ('92.51.36.131.nip.io', 'panel.example.com', 'panel.example.com'),
    ('92.51.36.131.nip.io', None, '92.51.36.131.nip.io'),
    (None, 'panel.example.com', 'panel.example.com'),
    (None, None, '92.51.36.131'),
])
def test_management_cli_prints_both_name_slots_and_primary_url(
        tmp_path, monkeypatch, capsys, hostname, custom_hostname, primary):
    from vs_router.agent import management_console

    vps_host(tmp_path)
    console = Console(tmp_path, vps_runner([]), os.getgid())
    monkeypatch.setattr(management_console, 'Console', lambda: console)
    monkeypatch.setattr(management_console.os, 'geteuid', lambda: 0)
    argv = ['management_console', '--single-uplink', '--path-prefix', '/panelpath']
    if hostname is not None:
        argv += ['--hostname', hostname]
    if custom_hostname is not None:
        argv += ['--custom-hostname', custom_hostname]
    monkeypatch.setattr('sys.argv', argv)
    assert management_console.main() == 0
    output = capsys.readouterr()
    assert f'Reserve hostname: {hostname or "(none)"}' in output.out
    assert f'Custom hostname: {custom_hostname or "(none)"}' in output.out
    assert f'Panel: https://{primary}/panelpath/' in output.out
    assert output.err == 'Panel readiness verified via local 92.51.36.131.\n'
    assert 'WARNING' not in output.err


def test_single_uplink_provision_publishes_both_acme_subjects(tmp_path):
    vps_host(tmp_path)
    state, _ = Console(tmp_path, vps_runner([]), os.getgid()).provision_single_uplink(
        hostname='92.51.36.131.nip.io', custom_hostname='panel.example.com')
    caddy = json.loads((tmp_path / 'etc/caddy/caddy.json').read_text())
    assert caddy == generate_caddy_json(ConfigurationVersion(), state)
    names = ['92.51.36.131.nip.io', 'panel.example.com']
    assert caddy['apps']['tls']['certificates']['automate'] == names
    policy = caddy['apps']['tls']['automation']['policies'][0]
    assert policy['subjects'] == names
    assert policy['issuers'][0]['module'] == 'acme'
    # Both subjects use the same HTTP-01 listener and firewall opening.
    assert caddy['apps']['http']['servers']['management_acme']['listen'] == ['92.51.36.131:80']
    rules = (tmp_path / 'var/lib/vs-router-bootstrap/management.nft').read_text()
    assert 'iifname "eth0" ip daddr 92.51.36.131 tcp dport 80 accept' in rules


@pytest.mark.parametrize('dry_run', [False, True])
def test_online_installer_forwards_custom_hostname_without_host_actions(dry_run):
    from pathlib import Path

    source = (Path(__file__).parents[1] / 'packaging/online-install.sh').read_text()
    # Run only argument parsing and the publication block, with python3 replaced
    # by an argv recorder. Never execute the privileged installer or console.
    arguments = source[:source.index('\nrun() {')]
    publish = source[source.index('# --- 6. Publish'):source.index('# --- 7. Verify')]
    code = arguments + '\npython3() { printf "ARG:%s\\n" "$@"; }\n' + publish
    argv = ['sh', '-c', code, 'online-install.sh', '--hostname', '92.51.36.131.nip.io',
            '--custom-hostname', 'panel.example.com']
    if dry_run:
        argv.append('--dry-run')
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    if dry_run:
        assert '+ management_console --single-uplink --ssh-port 22' in result.stdout
        assert '--hostname 92.51.36.131.nip.io' in result.stdout
        assert '--custom-hostname panel.example.com' in result.stdout
        assert 'ARG:' not in result.stdout
    else:
        assert result.stdout.splitlines() == [
            'ARG:-m', 'ARG:vs_router.agent.management_console', 'ARG:--single-uplink',
            'ARG:--ssh-port', 'ARG:22', 'ARG:--hostname', 'ARG:92.51.36.131.nip.io',
            'ARG:--custom-hostname', 'ARG:panel.example.com',
        ]


def test_single_uplink_provision_refuses_a_second_port(tmp_path):
    host(tmp_path)  # two wired ports
    console = Console(tmp_path, recording_runner([]), os.getgid())
    with pytest.raises(ValueError, match='management.single_port_required'):
        console.provision_single_uplink()


def test_single_uplink_provision_rejects_a_wrong_interface(tmp_path):
    vps_host(tmp_path)
    console = Console(tmp_path, vps_runner([]), os.getgid())
    with pytest.raises(ValueError, match='management.identity_mismatch'):
        console.provision_single_uplink(interface='eth9')


def test_single_uplink_provision_refuses_after_an_apply(tmp_path):
    vps_host(tmp_path)
    markers = tmp_path / 'etc/vs-router'
    markers.mkdir(parents=True)
    (markers / 'marker.json').write_text('{}')
    console = Console(tmp_path, vps_runner([]), os.getgid())
    with pytest.raises(ValueError, match='management.already_applied'):
        console.provision_single_uplink()


def test_panel_probe_target_trusts_acme_for_a_public_hostname():
    from vs_router.management import Management, panel_probe_target

    host = Management(interface='eth0', mac='02:00:00:00:00:01',
                      address='92.51.36.131/24', mode='single-uplink',
                      hostname='92.51.36.131.nip.io')
    url, ca = panel_probe_target(host)
    # ACME-signed certificate: system store, not the local CA, and SNI by name.
    assert (url, ca) == ('https://92.51.36.131.nip.io/health', None)

    lan = Management(interface='eth1', mac='02:00:00:00:00:02', address='192.168.10.1/24')
    url, ca = panel_probe_target(lan)
    assert url == 'https://192.168.10.1/health'
    assert ca is not None and ca.name == 'ca.crt'


# --- ADR-0025: publish the panel under an operator-supplied domain ----------

def panel_runner(calls, *, reachable=True):
    """Record host commands; simulate an HTTPS endpoint that may never answer."""
    def run(argv):
        calls.append(argv)
        if argv[0] == 'curl' and not reachable:
            raise subprocess.CalledProcessError(22, argv)
        return SimpleNamespace(stdout='')
    return run


def test_criterion_1_nat_local_probe_before_public(tmp_path, capsys):
    nat = RESERVE.model_copy(update={'address': '10.15.15.15/24',
                                     'hostname': '185.160.216.214.nip.io'})
    calls = []
    def run(argv):
        calls.append(argv)
        if '--resolve' not in argv:
            raise subprocess.CalledProcessError(28, argv)
        return SimpleNamespace(stdout='')

    Console(tmp_path, run, os.getgid()).probe_panel(nat, attempts=1)
    assert calls == [[
        'curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
        '--max-time', '5', '--resolve', '185.160.216.214.nip.io:443:10.15.15.15',
        'https://185.160.216.214.nip.io/health',
    ]]
    assert all('--cacert' not in call and '-k' not in call and '--insecure' not in call
               for call in calls)
    assert capsys.readouterr().err == 'Panel readiness verified via local 10.15.15.15.\n'


def test_criterion_2_all_targets_fail_then_publication_rolls_back(tmp_path, monkeypatch):
    _applied, state_dir = vps_applied(tmp_path)
    management_path = state_dir / 'management.json'
    caddy_path = tmp_path / 'etc/caddy/caddy.json'
    original_caddy = b'{ "prior": "retain exact bytes" }\n'
    caddy_path.write_bytes(original_caddy)
    original_record = management_path.read_bytes()
    calls, failures, sleeps, resolved = [], [], [], []
    def run(argv):
        calls.append(argv)
        if argv[0] == 'curl':
            error = subprocess.CalledProcessError(28, argv)
            failures.append(error)
            raise error
        return SimpleNamespace(stdout='')

    monkeypatch.setattr('vs_router.agent.management_console.time.sleep', sleeps.append)
    console = Console(tmp_path, run, os.getgid(), resolver=resolved.append)
    with pytest.raises(subprocess.CalledProcessError) as exc:
        console.probe_panel(RESERVE, attempts=60, delay=2)
    assert exc.value is failures[-1]
    probes = [call for call in calls if call[0] == 'curl']
    assert len(probes) == 120
    assert [('--resolve' in call) for call in probes] == [True, False] * 60
    assert all(call[-1] == 'https://92.51.36.131.nip.io/health' for call in probes)
    assert all(call[call.index('--resolve') + 1] == '92.51.36.131.nip.io:443:92.51.36.131'
               for call in probes[::2])
    assert sleeps == [2] * 59

    calls.clear()
    failures.clear()
    sleeps.clear()
    with pytest.raises(ValueError, match='^management.domain_unverified$') as exc:
        console.publish_panel_domain(CUSTOM)
    assert exc.value.__cause__ is failures[-1]
    assert resolved == [CUSTOM]
    probes = [call for call in calls if call[0] == 'curl']
    assert len(probes) == 180
    assert [('--resolve' in call) for call in probes] == [True, False, True] * 60
    # The newly published name first (locally, then as published), the reserve
    # afterwards over the local address: a second name that stopped answering
    # must not pass as a healthy publication.
    assert [call[-1] for call in probes[:3]] == [f'https://{CUSTOM}/health'] * 2 + \
        ['https://92.51.36.131.nip.io/health']
    assert probes[0][probes[0].index('--resolve') + 1] == f'{CUSTOM}:443:92.51.36.131'
    # The reserve is checked over the local address as well, so a published name
    # whose certificate or routing broke cannot pass unnoticed behind a healthy one.
    assert probes[2][probes[2].index('--resolve') + 1] == '92.51.36.131.nip.io:443:92.51.36.131'
    assert sleeps == [2] * 59
    assert management_path.read_bytes() == original_record
    assert caddy_path.read_bytes() == original_caddy
    assert calls.count(['systemctl', 'restart', 'caddy']) == 2


def test_criterion_3_publish_nat_success_keeps_custom_domain(tmp_path, capsys):
    nat = RESERVE.model_copy(update={'address': '10.15.15.15/24',
                                     'hostname': '185.160.216.214.nip.io'})
    _applied, state_dir = vps_applied(tmp_path, state=nat)
    calls, resolved = [], []
    def run(argv):
        calls.append(argv)
        if argv[0] == 'curl' and '--resolve' not in argv:
            raise subprocess.CalledProcessError(28, argv)
        return SimpleNamespace(stdout='')

    console = Console(tmp_path, run, os.getgid(), resolver=resolved.append)
    updated = console.publish_panel_domain(CUSTOM)
    assert resolved == [CUSTOM]
    assert updated.hostname == nat.hostname
    assert updated.custom_hostname == CUSTOM
    assert json.loads((state_dir / 'management.json').read_text()) == updated.model_dump()
    caddy_path = tmp_path / 'etc/caddy/caddy.json'
    assert json.loads(caddy_path.read_text()) == generate_caddy_json(
        console.applied_version(), updated)
    assert calls.count(['systemctl', 'restart', 'caddy']) == 1
    probes = [call for call in calls if call[0] == 'curl']
    assert len(probes) == 1
    # The domain just published is what gets verified, not the untouched reserve.
    assert probes[0][-1] == f'https://{CUSTOM}/health'
    assert probes[0][probes[0].index('--resolve') + 1] == f'{CUSTOM}:443:10.15.15.15'
    assert capsys.readouterr().err == 'Panel readiness verified via local 10.15.15.15.\n'


def test_criterion_4_separate_lan_uses_one_ca_probe(tmp_path, capsys):
    calls = []
    Console(tmp_path, panel_runner(calls), os.getgid()).probe_panel(STATE, attempts=1)
    assert calls == [[
        'curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
        '--max-time', '5', '--cacert', str(tmp_path / 'etc/caddy/management/ca.crt'),
        'https://192.168.10.1/health',
    ]]
    assert '--resolve' not in calls[0]
    assert capsys.readouterr().err == 'Panel readiness verified via local 192.168.10.1.\n'


def test_criterion_5_panel_probe_targets_preserve_publication_contract():
    from vs_router.management import TLS_DIR, panel_probe_target, panel_probe_targets

    both = RESERVE.model_copy(update={'custom_hostname': CUSTOM})
    reserve_url = 'https://92.51.36.131.nip.io/health'
    custom_url = f'https://{CUSTOM}/health'
    # The name that was just published is probed first (locally, then as
    # published); the reserve then follows over the local address.
    assert panel_probe_targets(both) == (
        (custom_url, None, f'{CUSTOM}:443:92.51.36.131'),
        (custom_url, None, None),
        (reserve_url, None, '92.51.36.131.nip.io:443:92.51.36.131'),
    )
    assert panel_probe_targets(RESERVE) == (
        (reserve_url, None, '92.51.36.131.nip.io:443:92.51.36.131'),
        (reserve_url, None, None),
    )
    assert panel_probe_target(both) == (custom_url, None)
    custom = VPS.model_copy(update={'custom_hostname': CUSTOM})
    assert panel_probe_targets(custom) == (
        (custom_url, None, f'{CUSTOM}:443:92.51.36.131'),
        (custom_url, None, None),
    )
    assert panel_probe_targets(VPS) == ((panel_probe_target(VPS)[0], TLS_DIR / 'ca.crt', None),)
    assert panel_probe_targets(STATE) == ((panel_probe_target(STATE)[0], TLS_DIR / 'ca.crt', None),)
    # One name repeated in both slots is one name, probed once.
    assert panel_probe_targets(both.model_copy(update={
        'custom_hostname': both.hostname})) == panel_probe_targets(RESERVE)


def test_panel_probe_public_fallback_and_retry_order(tmp_path, monkeypatch, capsys):
    calls, sleeps = [], []
    def run(argv):
        calls.append(argv)
        if len(calls) <= 3:
            raise subprocess.CalledProcessError(28, argv)
        return SimpleNamespace(stdout='')

    monkeypatch.setattr('vs_router.agent.management_console.time.sleep', sleeps.append)
    Console(tmp_path, run, os.getgid()).probe_panel(RESERVE, attempts=2, delay=7)
    assert [('--resolve' in call) for call in calls] == [True, False, True, False]
    assert all(call[-1] == 'https://92.51.36.131.nip.io/health' for call in calls)
    assert sleeps == [7]
    assert capsys.readouterr().err == 'Panel readiness verified via public.\n'


def vps_applied(tmp_path, ssh_interfaces=('eth0',), state=RESERVE):
    """A one-NIC record (with the nip.io reserve) plus an applied snapshot.

    ``ssh_interfaces`` is what the applied configuration allows SSH on: a real
    one-NIC host reaches the operator over the uplink, and publishing regenerates
    the live firewall from this snapshot.
    """
    vps_host(tmp_path)
    applied = tmp_path / 'etc/vs-router/applied'
    applied.mkdir(parents=True)
    version = ConfigurationVersion(configuration=Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'static',
                        'addresses': [state.address]}],
        'ssh': {'interfaces': list(ssh_interfaces),
                'wan_confirmed_interfaces': list(ssh_interfaces)}}))
    (applied / 'snapshot.json').write_text(version.model_dump_json())
    state_dir = tmp_path / 'var/lib/vs-router-bootstrap'
    state_dir.mkdir(parents=True)
    (state_dir / 'management.json').write_text(state.model_dump_json())
    return applied, state_dir


def test_publish_panel_domain_refuses_when_the_applied_rules_close_ssh(tmp_path):
    """Publishing rewrites the live firewall from the applied configuration; a
    configuration that allows no SSH on the management interface would lock the
    operator out, so the change is refused before anything is written."""
    applied, state_dir = vps_applied(tmp_path, ssh_interfaces=())
    before = (state_dir / 'management.json').read_text()
    console = Console(tmp_path, panel_runner([]), os.getgid(), resolver=lambda name: None)
    with pytest.raises(ValueError, match='management.ssh_unprotected'):
        console.publish_panel_domain('rg3.poshl9k.ru')
    # Nothing was published and no firewall was rewritten.
    assert (state_dir / 'management.json').read_text() == before
    assert not (applied / 'nftables.conf').exists()
    assert not (tmp_path / 'etc/caddy/caddy.json').exists()


def test_publish_panel_domain_serves_the_custom_name_beside_the_reserve(tmp_path, capsys):
    applied, state_dir = vps_applied(tmp_path)
    calls = []
    console = Console(tmp_path, panel_runner(calls), os.getgid(),
                      resolver=lambda name: None)
    updated = console.publish_panel_domain(CUSTOM)
    assert updated.custom_hostname == CUSTOM
    record = json.loads((state_dir / 'management.json').read_text())
    # The install-time reserve name (nip.io) is kept, the custom name is added.
    assert record['hostname'] == '92.51.36.131.nip.io'
    assert record['custom_hostname'] == CUSTOM
    caddy = json.loads((tmp_path / 'etc/caddy/caddy.json').read_text())
    automate = caddy['apps']['tls']['certificates']['automate']
    assert set(automate) == {'92.51.36.131.nip.io', CUSTOM}
    assert set(caddy['apps']['tls']['automation']['policies'][0]['subjects']) == set(automate)
    assert caddy['apps']['http']['servers']['management_acme']['listen'] == ['92.51.36.131:80']
    assert 'iifname "eth0" ip daddr 92.51.36.131 tcp dport 80 counter accept comment "management_acme"' in (applied / 'nftables.conf').read_text()
    probes = [c for c in calls if c[0] == 'curl']
    assert len(probes) == 1
    # The name that was just published is the one verified.
    assert probes[0][-1] == f'https://{CUSTOM}/health'
    assert probes[0][probes[0].index('--resolve') + 1] == f'{CUSTOM}:443:92.51.36.131'
    stderr = capsys.readouterr().err
    assert stderr == 'Panel readiness verified via local 92.51.36.131.\n'
    assert 'WARNING' not in stderr
    # Clearing the custom name keeps the reserve: still ACME, still :80.
    back = console.publish_panel_domain(None)
    assert back.custom_hostname is None
    record = json.loads((state_dir / 'management.json').read_text())
    assert record['hostname'] == '92.51.36.131.nip.io' and record['custom_hostname'] is None
    caddy = json.loads((tmp_path / 'etc/caddy/caddy.json').read_text())
    assert caddy['apps']['tls']['certificates']['automate'] == ['92.51.36.131.nip.io']
    assert 'management_acme' in caddy['apps']['http']['servers']
    assert 'management_acme' in (applied / 'nftables.conf').read_text()


def test_publish_panel_domain_reverts_when_the_name_never_answers(tmp_path, monkeypatch):
    _applied, state_dir = vps_applied(tmp_path)
    monkeypatch.setattr('vs_router.agent.management_console.time.sleep', lambda _seconds: None)
    console = Console(tmp_path, panel_runner([], reachable=False), os.getgid(),
                      resolver=lambda name: None)
    with pytest.raises(ValueError, match='management.domain_unverified'):
        console.publish_panel_domain('rg3.poshl9k.ru')
    # The previous publication is intact: reserve kept, custom never added.
    record = json.loads((state_dir / 'management.json').read_text())
    assert record['hostname'] == '92.51.36.131.nip.io' and record['custom_hostname'] is None
    # There was no Caddy config before, so the failed publication leaves none.
    assert not (tmp_path / 'etc/caddy/caddy.json').exists()


def test_publish_panel_domain_rejects_an_unresolvable_name(tmp_path):
    _applied, state_dir = vps_applied(tmp_path)

    def unresolvable(name):
        raise OSError('name not known')

    console = Console(tmp_path, panel_runner([]), os.getgid(), resolver=unresolvable)
    with pytest.raises(ValueError, match='management.domain_unresolved'):
        console.publish_panel_domain('rg3.poshl9k.ru')
    # Nothing was written: the unreachable name never touched the live endpoint.
    record = json.loads((state_dir / 'management.json').read_text())
    assert record['custom_hostname'] is None
    assert not (tmp_path / 'etc/caddy/caddy.json').exists()


def test_publish_panel_domain_requires_a_management_record(tmp_path):
    console = Console(tmp_path, panel_runner([]), os.getgid())
    with pytest.raises(ValueError, match='management.state_missing'):
        console.publish_panel_domain('rg3.poshl9k.ru')


def test_publication_names_favour_the_custom_name_but_keep_the_reserve():
    from vs_router.management import publication_names, panel_probe_target

    both = VPS.model_copy(update={'hostname': '92.51.36.131.nip.io',
                                  'custom_hostname': 'rg3.poshl9k.ru'})
    assert publication_names(both) == ('92.51.36.131.nip.io', 'rg3.poshl9k.ru')
    # A duplicate name (custom == reserve) is served once.
    assert publication_names(both.model_copy(update={'custom_hostname': '92.51.36.131.nip.io'})) \
        == ('92.51.36.131.nip.io',)
    # No names at all: IP endpoint with the local CA.
    assert publication_names(VPS) == ()
    assert panel_probe_target(VPS)[0] == 'https://92.51.36.131/health'
    # Probe prefers the operator's own name, else the reserve.
    assert panel_probe_target(both)[0] == 'https://rg3.poshl9k.ru/health'
    assert panel_probe_target(VPS.model_copy(update={'hostname': '92.51.36.131.nip.io'}))[0] \
        == 'https://92.51.36.131.nip.io/health'


def test_nftables_opens_acme_port_for_either_public_name():
    version = ConfigurationVersion(configuration=Configuration.model_validate({
        'interfaces': [{'name': 'eth0', 'zone': 'wan', 'addressing': 'static',
                        'addresses': ['92.51.36.131/24']}]}))
    rule = 'iifname "eth0" ip daddr 92.51.36.131 tcp dport 80 counter accept comment "management_acme"'
    # Reserve alone, and custom alone, both need the ACME listener.
    assert rule in generate_nftables(version, RESERVE)
    assert rule in generate_nftables(version, VPS.model_copy(update={'custom_hostname': 'rg3.poshl9k.ru'}))
    assert 'ip daddr 92.51.36.131 tcp dport 80 drop' in generate_nftables(version, RESERVE)
    # Without any public name the exception is absent (fail-closed).
    assert 'tcp dport 80' not in generate_nftables(version, VPS)


def test_panel_domain_params_enforce_the_hostname_contract():
    from pydantic import ValidationError
    from vs_router.agent.rpc import PanelDomainParams

    assert PanelDomainParams().hostname is None
    assert PanelDomainParams(hostname='rg3.poshl9k.ru').hostname == 'rg3.poshl9k.ru'
    with pytest.raises(ValidationError):
        PanelDomainParams(hostname='not a name')
    with pytest.raises(ValidationError):
        PanelDomainParams(hostname='-bad.example')


def test_agent_unit_may_write_the_management_record():
    """Publishing rewrites the host-owned record (ADR-0025) from INSIDE the agent.

    The agent runs under ``ProtectSystem=strict``; without the bootstrap state
    directory in ``ReadWritePaths`` the write fails with ``EROFS`` and surfaces
    only as a bare ``agent.internal_error`` (observed on the live VPS).
    """
    from pathlib import Path

    unit = (Path(__file__).parents[1] / 'packaging' / 'vs-router-agent.service').read_text()
    paths = next(line for line in unit.splitlines() if line.startswith('ReadWritePaths='))
    assert '/var/lib/vs-router-bootstrap' in paths.split()
