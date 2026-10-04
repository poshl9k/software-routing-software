"""All host effects use temporary trees or injected executors; no live services."""
import json
import os
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from vs_router.management import Management, verify_identity, validate_management
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.generators.caddy import generate_caddy_json
from vs_router.generators.nftables import generate_nftables
from vs_router.agent.management_console import Console
from vs_router.agent.apply import ApplyEngine, ApplyError, APPLIED_DIR
from test_agent_apply import FakeFS, FakeExecutor

STATE = Management(interface='eth1', mac='02:00:00:00:00:02', address='192.168.10.1/24')


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


def test_panel_exists_without_sites_and_rejects_wildcard():
    config = generate_caddy_json(version(), STATE)
    panel = config['apps']['http']['servers']['management']
    assert panel['listen'] == ['192.168.10.1:443']
    assert panel['routes'][0]['handle'][0]['upstreams'][0]['dial'].startswith('unix//')
    site = {'name': 'app', 'hostname': 'app.example.com', 'upstream': '127.0.0.1:9000', 'certificate_mode': 'passthrough'}
    with pytest.raises(ValueError, match='site_binding_conflict'):
        generate_caddy_json(version(sites=[site]), STATE)
    site['wan_address'] = '203.0.113.2'
    site['certificate_mode'] = 'http01'
    configured = version(sites=[site], interfaces=[
        {'name': 'eth0', 'zone': 'wan', 'addresses': ['203.0.113.2/24']},
        {'name': 'eth1', 'zone': 'lan', 'addresses': [STATE.address]}])
    assert len(generate_caddy_json(configured, STATE)['apps']['http']['servers']) >= 2


@pytest.mark.parametrize('changes', [
    {'interfaces': []}, {'panel_port': 8443},
    {'interfaces': [{'name': 'eth1', 'zone': 'wan', 'addresses': [STATE.address]}]},
    {'port_forwards': [{'name': 'hijack', 'interface': 'eth0', 'protocol': 'tcp',
                        'external_port': 443, 'target': '192.168.10.2', 'target_port': 443}]},
])
def test_guard_rejects_before_mutations(changes):
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(), management_provider=lambda: STATE)
    with pytest.raises(ApplyError, match='management.access_invalid'):
        engine.apply_version(version(**changes).model_dump(mode='json'))
    assert not fs.files


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
    import ssl
    from urllib import request
    from vs_router.agent import daemon
    from vs_router.management import TLS_DIR
    monkeypatch.setattr('vs_router.management.host_management', lambda: STATE)
    calls = []
    context = object()
    monkeypatch.setattr(ssl, 'create_default_context',
                        lambda cafile: calls.append(cafile) or context)
    response = MagicMock()
    response.__enter__.return_value.status = 200
    opener = MagicMock()
    opener.open.return_value = response
    monkeypatch.setattr(request, 'build_opener',
                        lambda *handlers: calls.append(handlers) or opener)
    assert daemon.panel_probe() is True
    assert calls[0] == str(TLS_DIR / 'ca.crt')
    assert len(calls[1]) == 2
    assert calls[1][1]._context is context
    opener.open.assert_called_once_with('https://192.168.10.1/health', timeout=3)


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
    assert calls == [['/usr/sbin/nft', '-f', str(tmp_path / 'management.nft')], 'proxy', 'ssh']


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
