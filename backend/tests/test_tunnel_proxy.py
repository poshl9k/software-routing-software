import base64
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from vs_router.schema import ConfigurationVersion, Tunnel
from vs_router.secrets import encrypt_secret
from vs_router.generators.wireguard import (generate_wg_conf, generate_wg_bundle,
    serialize_wireguard, deserialize_wireguard)
from vs_router.generators.caddy import generate_caddy_json, generate_caddy_bundle, serialize_caddy
from vs_router.agent.services import WireGuardReloader, CaddyReloader
from vs_router.agent.apply import ApplyEngine, ApplyError, APPLIED_DIR
from test_agent_apply import FakeFS, FakeExecutor


@pytest.fixture
def config(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    def secret(value):
        return encrypt_secret(value, key).model_dump()
    tunnel = dict(name='vpn', interface='wg0', role='server', protocol='wg',
        private_key=secret(base64.b64encode(bytes(range(32))).decode()), listen_port=51820,
        allowed_ips=['10.66.66.0/24'], peers=[dict(name='alice', public_key='PUBLIC', allowed_ips=['10.66.66.2/32'])])
    sites = [dict(name=mode, hostname=mode+'.example.com', upstream='127.0.0.1:8080',
                  wan_address='203.0.113.1', certificate_mode=mode)
             for mode in ('http01', 'dns01', 'manual', 'passthrough')]
    sites[1]['dns_api_token'] = secret('dns-token')
    sites[2].update(certificate=secret('CERTIFICATE'), private_key=secret('PRIVATE KEY'))
    return dict(id=1, configuration=dict(interfaces=[
        dict(name='wan0', zone='wan', addresses=['203.0.113.1/24']),
        dict(name='wg0', zone='lan', addresses=['10.66.66.1/24'])], tunnels=[tunnel], sites=sites))


@pytest.mark.parametrize('protocol', ['wg', 'awg'])
@pytest.mark.parametrize('role', ['server', 'client'])
def test_tunnel_golden(config, protocol, role):
    t = config['configuration']['tunnels'][0]
    t['protocol'] = protocol
    t['obfuscation'] = dict(Jc=4, Jmin=40, Jmax=70, S1=15, S2=95,
                            H1=1234567, H2=2345678, H3=3456789, H4=4567890)
    if role == 'client':
        t.update(role=role, peers=[], endpoint='203.0.113.1:51820', server_public_key='SERVER',
                 allowed_ips=['0.0.0.0/0'], keepalive=25)
    version = ConfigurationVersion.model_validate(config)
    files = generate_wg_bundle(version, {})
    text = serialize_wireguard(files)
    assert deserialize_wireguard(text) == files
    assert 'Address =' not in files['vpn.conf']
    assert text == (Path(__file__).parent / 'golden' / f'{protocol}-{role}.bundle').read_text()


def test_caddy_golden(config):
    version = ConfigurationVersion.model_validate(config)
    result = generate_caddy_json(version)
    assert json.dumps(result, indent=2, sort_keys=True)+'\n' == (Path(__file__).parent / 'golden/caddy.json').read_text()
    l4 = result['apps']['layer4']['servers']['wan0']
    assert isinstance(l4['routes'][0]['handle'][0]['upstreams'][0]['dial'], list)
    assert 'passthrough.example.com' not in result['apps']['tls']['certificates']['automate']
    assert 'internal' not in json.dumps(result)
    assert serialize_caddy(generate_caddy_bundle(version)).startswith('### FILE: caddy.json\n')


@pytest.mark.parametrize('alive', [True, False])
@pytest.mark.parametrize('protocol', ['wg', 'awg'])
def test_reload_tunnel(config, alive, protocol):
    fs, executor = FakeFS(), FakeExecutor()
    t = config['configuration']['tunnels'][0]
    t.update(role='client', protocol=protocol, peers=[], endpoint='203.0.113.1:51820',
             server_public_key='SERVER', allowed_ips=['0.0.0.0/0', '2001:db8::/64'],
             obfuscation=dict(Jc=4, S1=15, S2=95, H1=1, H2=2, H3=3, H4=4))
    source = APPLIED_DIR / 'wireguard.conf'
    fs.write(source, serialize_wireguard(generate_wg_bundle(ConfigurationVersion.model_validate(config), {})))
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        return SimpleNamespace(returncode=int(not alive and argv[:2] == ['systemctl', 'is-active']))
    executor.run = run
    # Force the userspace daemon path; kernel selection is covered separately.
    WireGuardReloader(executor, fs, sleep=lambda _: None,
                      kernel_probe=lambda *_: False)(source)
    calls = [a for a, _ in executor.calls]
    assert (['systemctl', 'restart', f'vs-router-{protocol}@wg0.service'] in calls) == (not alive)
    setconf = [protocol, 'setconf', 'wg0', '/etc/vs-router/wireguard/vpn.conf']
    assert setconf in calls
    assert calls.index(setconf) < calls.index(['ip', 'addr', 'replace', '10.66.66.1/24', 'dev', 'wg0'])
    assert ['ip', '-4', 'route', 'replace', 'default', 'dev', 'wg0', 'metric', '100'] in calls
    assert ['ip', '-6', 'route', 'replace', '2001:db8::/64', 'dev', 'wg0'] in calls
    fs.write(source, serialize_wireguard({'manifest.json': '{}\n'}))
    WireGuardReloader(executor, fs, kernel_probe=lambda *_: False)(source)
    assert ['systemctl', 'disable', '--now', f'vs-router-{protocol}@wg0.service'] in [a for a, _ in executor.calls]


def test_reload_tunnel_uses_kernel_when_available(config):
    fs, executor = FakeFS(), FakeExecutor()
    t = config['configuration']['tunnels'][0]
    t.update(role='client', protocol='wg', peers=[], endpoint='203.0.113.1:51820',
             server_public_key='SERVER', allowed_ips=['0.0.0.0/0'], obfuscation={})
    source = APPLIED_DIR / 'wireguard.conf'
    fs.write(source, serialize_wireguard(generate_wg_bundle(ConfigurationVersion.model_validate(config), {})))
    present = set()
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv[:3] == ['ip', 'link', 'show']:
            return SimpleNamespace(returncode=0 if argv[4] in present else 1)
        return SimpleNamespace(returncode=0)
    executor.run = run
    WireGuardReloader(executor, fs, sleep=lambda _: None, kernel_probe=lambda *_: True)(source)
    calls = [a for a, _ in executor.calls]
    assert ['ip', 'link', 'add', 'dev', 'wg0', 'type', 'wireguard'] in calls
    assert ['systemctl', 'enable', 'vs-router-wg@wg0.service'] not in calls
    assert ['wg', 'setconf', 'wg0', '/etc/vs-router/wireguard/vpn.conf'] in calls
    assert ['ip', 'addr', 'replace', '10.66.66.1/24', 'dev', 'wg0'] in calls


@pytest.mark.parametrize('failure', [None, 'validate', 'http'])
def test_caddy_reload(config, failure):
    fs, executor = FakeFS(), FakeExecutor()
    source = APPLIED_DIR / 'caddy.conf'
    fs.write(source, serialize_caddy(generate_caddy_bundle(ConfigurationVersion.model_validate(config))))
    called = []
    def http(request, timeout):
        called.append(request)
        assert request.full_url == 'http://127.0.0.1:2019/load'
        assert request.get_method() == 'POST'
        assert json.loads(request.data) == json.loads(fs.read(Path('/etc/caddy/caddy.json')))
        response = io.BytesIO(b'')
        response.status = 500 if failure == 'http' else 200
        return response
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        return SimpleNamespace(returncode=int(failure == 'validate' and argv[0] == 'caddy'))
    executor.run = run
    adapter = CaddyReloader(executor, fs, http)
    if failure:
        with pytest.raises(ApplyError):
            adapter(source)
    else:
        adapter(source)
    assert bool(called) == (failure != 'validate')
    assert fs.read(Path('/etc/caddy/vs-router/manual.key')) == 'PRIVATE KEY\n'


def test_apply_bundles_and_rollback(config):
    fs, executor = FakeFS(), FakeExecutor()
    def http(*args, **kwargs):
        response = io.BytesIO(b'')
        response.status = 200
        return response
    engine = ApplyEngine(filesystem=fs, executor=executor, reload_commands={
        'wireguard': WireGuardReloader(executor, fs), 'caddy': CaddyReloader(executor, fs, http)})
    assert engine.apply_version(config).status == 'confirmed'
    original = fs.read(Path('/etc/vs-router/wireguard/vpn.conf'))
    assert engine.apply_version({'id': 2, 'configuration': {}}, True).status == 'pending'
    assert engine.rollback('test').status == 'rolled_back'
    assert fs.read(Path('/etc/vs-router/wireguard/vpn.conf')) == original


def test_missing_secret_key_is_sanitized(config, monkeypatch):
    monkeypatch.delenv('VS_ROUTER_SECRET_KEY')
    with pytest.raises(ValueError, match='secret.decryption_failed'):
        generate_wg_conf(Tunnel.model_validate(config['configuration']['tunnels'][0]), {})


@pytest.mark.parametrize('text', ['### FILE: ../escape\nx', '### FILE: a\nx\n### FILE: a\ny', 'unmarked'])
def test_bundle_rejects_invalid(text):
    with pytest.raises(ValueError):
        deserialize_wireguard(text)


def test_export_with_encrypted_peer_key(config):
    import os
    peer_secret = encrypt_secret('CLIENT_PRIVATE', os.environ['VS_ROUTER_SECRET_KEY'].encode())
    version = ConfigurationVersion.model_validate(config)
    files = generate_wg_bundle(version, {'vpn': {'peer_private_keys': {'alice': peer_secret}}})
    assert 'PrivateKey = CLIENT_PRIVATE' in files['vpn.peer-alice.conf']
    assert 'TEMPLATE' not in files['vpn.peer-alice.conf']
    assert 'Endpoint = 203.0.113.1:51820' in files['vpn.peer-alice.conf']


@pytest.mark.parametrize('role', ['server', 'client'])
def test_peers_without_allowedips_get_an_address(config, role):
    """A server peer (or client) with no AllowedIPs must produce a valid line:
    the peer is auto-allocated a /32 in the tunnel subnet, never a dangling key."""
    data = json.loads(json.dumps(config))
    tunnel = data['configuration']['tunnels'][0]
    tunnel['allowed_ips'] = []
    for peer in tunnel['peers']:
        peer['allowed_ips'] = []
    if role == 'client':
        tunnel.update(role='client', peers=[], endpoint='203.0.113.1:51820',
                      server_public_key='SERVER')
    files = generate_wg_bundle(ConfigurationVersion.model_validate(data), {})
    lines = files['vpn.conf'].splitlines()
    assert not any(line.replace(' ', '') == 'AllowedIPs=' for line in lines)
    if role == 'server':
        # server keeps .1, the peer takes .2 in the same /24
        assert 'AllowedIPs = 10.66.66.2/32' in lines
        assert 'Address = 10.66.66.2/32' in files['vpn.peer-alice.conf']


def test_each_server_tunnel_gets_its_own_subnet(config):
    data = json.loads(json.dumps(config))
    second = json.loads(json.dumps(data['configuration']['tunnels'][0]))
    second.update(name='vpn2', interface='wg1', allowed_ips=[])
    second['peers'][0].update(name='bob', allowed_ips=[])
    data['configuration']['tunnels'].append(second)
    data['configuration']['interfaces'].append({'name': 'wg1', 'zone': 'lan'})
    files = generate_wg_bundle(ConfigurationVersion.model_validate(data), {})
    manifest = json.loads(files['manifest.json'])
    # wg0 has an explicit address; the address-less wg1 takes the next pool slot.
    assert manifest['wg0']['addresses'] == ['10.66.66.1/24']
    assert manifest['wg1']['addresses'] == ['10.66.67.1/24']
    assert 'AllowedIPs = 10.66.67.2/32' in files['vpn2.conf']


def test_server_tunnel_opens_its_listen_port_on_the_wan(config):
    """A server tunnel with `open_port` gets an INPUT accept for udp/<port> on
    the WAN zone; turning it off removes the generated rule."""
    from vs_router.generators import generate_nftables
    output = generate_nftables(ConfigurationVersion.model_validate(config))
    assert 'iifname { "wan0" } udp dport 51820 counter accept comment "tunnel_vpn"' in output
    data = json.loads(json.dumps(config))
    data['configuration']['tunnels'][0]['open_port'] = False
    assert 'tunnel_vpn' not in generate_nftables(ConfigurationVersion.model_validate(data))


def test_server_endpoint_is_advertised_to_clients(config):
    """A server's own endpoint (IP/hostname) replaces the WAN-derived value in
    the client export; a bare host gets the listen port appended."""
    data = json.loads(json.dumps(config))
    data['configuration']['tunnels'][0]['endpoint'] = 'vpn.example.org'
    files = generate_wg_bundle(ConfigurationVersion.model_validate(data), {})
    peer = files['vpn.peer-alice.conf']
    assert 'Endpoint = vpn.example.org:51820' in peer
    assert 'WAN_ENDPOINT' not in peer
    data['configuration']['tunnels'][0]['endpoint'] = 'vpn.example.org:8443'
    files = generate_wg_bundle(ConfigurationVersion.model_validate(data), {})
    assert 'Endpoint = vpn.example.org:8443' in files['vpn.peer-alice.conf']


def test_materialize_addresses_fills_tunnel_and_peer(config):
    """The stored configuration carries the deterministic addresses so every
    client shows them; explicit values are preserved (idempotent)."""
    from vs_router.generators.wireguard import materialize_addresses
    data = json.loads(json.dumps(config))
    tunnel = data['configuration']['tunnels'][0]
    tunnel['allowed_ips'] = []
    for peer in tunnel['peers']:
        peer['allowed_ips'] = []
    for interface in data['configuration']['interfaces']:
        if interface['name'] == 'wg0':
            interface['addresses'] = []
    version = ConfigurationVersion.model_validate(data)
    filled = materialize_addresses(version.configuration)
    device = next(i for i in filled.interfaces if i.name == 'wg0')
    assert list(device.addresses) == ['10.66.66.1/24']
    assert list(filled.tunnels[0].peers[0].allowed_ips) == ['10.66.66.2/32']
    again = materialize_addresses(filled)
    assert next(i for i in again.interfaces if i.name == 'wg0').addresses == device.addresses
    assert again.tunnels[0].peers[0].allowed_ips == filled.tunnels[0].peers[0].allowed_ips


def test_server_peer_export_without_wan_address_is_a_template(config):
    """A DHCP/addressless WAN has no endpoint to derive: the router-side server
    config must still apply, and the client export degrades to a template."""
    data = json.loads(json.dumps(config))
    # The Caddy sites bind a WAN address; drop them so only the WAN addressing
    # change is under test.
    data['configuration']['sites'] = []
    for interface in data['configuration']['interfaces']:
        if interface.get('zone') == 'wan':
            interface['addresses'] = []
            interface['addressing'] = 'dhcp'
    files = generate_wg_bundle(ConfigurationVersion.model_validate(data), {})
    peer = files['vpn.peer-alice.conf']
    assert 'Endpoint = <WAN_ENDPOINT>' in peer
    assert 'TEMPLATE' in peer and 'WAN_ENDPOINT' in peer
    # The server config itself carries no endpoint and is unaffected.
    assert 'PrivateKey' in files['vpn.conf']
    assert 'Endpoint' not in files['vpn.conf']
    assert 'manifest.json' in files


def test_tunnel_start_readiness_and_failure(config, tmp_path):
    from vs_router.agent.tunnel_start import configure
    files = generate_wg_bundle(ConfigurationVersion.model_validate(config), {})
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    executor = FakeExecutor()
    # No link yet: the userspace daemon has to come up before `wg show` answers.
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        return SimpleNamespace(returncode=1 if argv[:3] == ['ip', 'link', 'show'] else 0)
    executor.run = run
    configure('wg0', executor, tmp_path, lambda _: None)
    assert executor.calls[0][0] == ['ip', 'link', 'show', 'dev', 'wg0']
    assert executor.calls[1][0] == ['wg', 'show', 'wg0']
    assert executor.calls[2][0] == ['wg', 'setconf', 'wg0', str(tmp_path / 'vpn.conf')]
    # A daemon that never becomes ready must fail the phase, not pass silently.
    broken = FakeExecutor()
    broken.fail = True
    with pytest.raises(ApplyError):
        configure('wg0', broken, tmp_path, lambda _: None)


def test_tunnel_start_skips_wait_for_existing_link(config, tmp_path):
    """An in-kernel device already exists; `wg show` answers immediately."""
    from vs_router.agent.tunnel_start import configure
    files = generate_wg_bundle(ConfigurationVersion.model_validate(config), {})
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    executor = FakeExecutor()
    configure('wg0', executor, tmp_path, lambda _: None)
    calls = [argv for argv, _ in executor.calls]
    assert ['wg', 'show', 'wg0'] not in calls
    assert calls[0] == ['ip', 'link', 'show', 'dev', 'wg0']
    assert calls[1] == ['wg', 'setconf', 'wg0', str(tmp_path / 'vpn.conf')]


def test_tunnel_reload_setconf_failure(config):
    fs, executor = FakeFS(), FakeExecutor()
    source = APPLIED_DIR / 'wireguard.conf'
    fs.write(source, serialize_wireguard(generate_wg_bundle(ConfigurationVersion.model_validate(config), {})))
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        return SimpleNamespace(returncode=int('setconf' in argv))
    executor.run = run
    with pytest.raises(ApplyError):
        WireGuardReloader(executor, fs)(source)
    assert not any('replace' in a for a, _ in executor.calls)


def test_boot_only_restores_files(config, tmp_path, monkeypatch):
    from vs_router.agent import boot_restore
    import grp
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path))
    version = ConfigurationVersion.model_validate(config)
    (tmp_path / 'wireguard.conf').write_text(serialize_wireguard(generate_wg_bundle(version, {})))
    (tmp_path / 'caddy.conf').write_text(serialize_caddy(generate_caddy_bundle(version)))
    fs = FakeFS()
    fs.write(tmp_path / 'wireguard.conf', (tmp_path / 'wireguard.conf').read_text())
    fs.write(tmp_path / 'caddy.conf', (tmp_path / 'caddy.conf').read_text())
    # Files only: this host has no kernel support, so no link is created.
    monkeypatch.setattr('vs_router.agent.apply.LocalFileSystem', lambda: fs)
    executor = FakeExecutor()
    monkeypatch.setattr('vs_router.agent.services.SubprocessExecutor', lambda: executor)
    monkeypatch.setattr(WireGuardReloader, 'probe_kernel_wireguard',
                        staticmethod(lambda executor, protocol='wg': False))
    monkeypatch.setattr(CaddyReloader, '__init__', lambda self, **kw: (
        setattr(self, 'fs', fs), setattr(self, 'config_path', Path('/caddy.json')),
        setattr(self, 'cert_dir', Path('/certs')))[-1])
    monkeypatch.setattr(grp, 'getgrnam', lambda _: SimpleNamespace(gr_gid=123))
    monkeypatch.setattr(boot_restore.os, 'chown', lambda *args: None)
    monkeypatch.setattr(boot_restore.os, 'chmod', lambda *args: None)
    monkeypatch.setattr(boot_restore, 'run', lambda *_: pytest.fail('must not start services'))
    assert boot_restore.restore_tunnel_proxy_files() == 0
    assert 'Address =' not in fs.read(Path('/etc/vs-router/wireguard/vpn.conf'))
    assert json.loads(fs.read(Path('/caddy.json')))['apps']['layer4']
    assert not any(argv[:3] == ['ip', 'link', 'add'] for argv, _ in executor.calls)


def test_boot_restores_kernel_tunnel_without_a_daemon(config, tmp_path, monkeypatch):
    """An in-kernel device has no unit, so boot must recreate the link."""
    from vs_router.agent import boot_restore
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path))
    version = ConfigurationVersion.model_validate(config)
    (tmp_path / 'wireguard.conf').write_text(serialize_wireguard(generate_wg_bundle(version, {})))
    fs = FakeFS()
    fs.write(tmp_path / 'wireguard.conf', (tmp_path / 'wireguard.conf').read_text())
    # WireGuardReloader.install() writes to config_dir via LocalFileSystem;
    # monkeypatch it so the restore path never touches the real filesystem.
    monkeypatch.setattr('vs_router.agent.apply.LocalFileSystem', lambda: fs)
    # The interface does not exist yet; ip link show must return non-zero so
    # configure_kernel creates the link before calling setconf.
    executor = FakeExecutor()
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv[:3] == ['ip', 'link', 'show']:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)
    executor.run = run
    monkeypatch.setattr('vs_router.agent.services.SubprocessExecutor', lambda: executor)
    monkeypatch.setattr(WireGuardReloader, 'probe_kernel_wireguard',
                        staticmethod(lambda executor, protocol='wg': True))
    monkeypatch.setattr(boot_restore.os, 'chown', lambda *args: None)
    assert boot_restore.restore_tunnel_proxy_files() == 0
    calls = [tuple(argv) for argv, _ in executor.calls]
    assert ('ip', 'link', 'add', 'dev', 'wg0', 'type', 'wireguard') in calls
    assert ('wg', 'setconf', 'wg0', '/etc/vs-router/wireguard/vpn.conf') in calls
    assert ('ip', 'addr', 'replace', '10.66.66.1/24', 'dev', 'wg0') in calls
    assert not any(argv[:1] == ('systemctl',) for argv in calls)


def test_caddy_unbound_sites_share_primary_wan(config):
    for site in config['configuration']['sites'][1:]:
        site.pop('wan_address')
    result = generate_caddy_json(ConfigurationVersion.model_validate(config))
    assert len(result['apps']['layer4']['servers']) == 1
