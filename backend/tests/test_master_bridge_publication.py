"""A host-owned master bridge publication must not expose local portal routes."""
import io
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_router.agent.master_bridge_publication import MARKER, configure_publication, publish_bridge
from vs_router.agent.services import CaddyReloader
from vs_router.db import MasterBridgeSetting
from vs_router.generators.caddy import serialize_caddy
from vs_router.internal_app import MASTER_TOKEN_KEY, _read_master_tokens
from vs_router.master_bridge_bootstrap import install_token
from test_agent_apply import FakeFS


@pytest.fixture
def caddy_config():
    return {'apps': {'http': {'servers': {'management': {'routes': [
        {'match': [{'host': ['rg3.poshl9k.ru']}], 'handle': [{'handler': 'reverse_proxy',
            'upstreams': [{'dial': 'unix//run/vs-router/web/web.sock'}]}]},
    ]}}}, 'tls': {'certificates': {'automate': ['rg3.poshl9k.ru']}}}}


def test_publication_only_allows_master_source_and_shadows_panel(caddy_config):
    original = json.dumps(caddy_config)
    updated = publish_bridge(caddy_config, {'hostname': 'rg3.poshl9k.ru',
                                              'source_ip': '85.209.159.130'})
    assert json.dumps(caddy_config) == original
    routes = updated['apps']['http']['servers']['management']['routes']
    assert routes[0]['match'] == [{'host': ['rg3.poshl9k.ru'],
                                    'path': ['/internal/master/*'],
                                    'remote_ip': {'ranges': ['85.209.159.130/32']}}]
    assert routes[0]['handle'][0]['upstreams'] == [{'dial': 'unix//run/vs-router/web/master.sock'}]
    assert routes[1]['match'] == [{'host': ['rg3.poshl9k.ru'], 'path': ['/internal/master/*']}]
    assert routes[1]['handle'] == [{'handler': 'static_response', 'status_code': 403}]
    assert routes[2] == caddy_config['apps']['http']['servers']['management']['routes'][0]
    assert publish_bridge(updated, {'hostname': 'rg3.poshl9k.ru',
                                     'source_ip': '85.209.159.130'}) == updated


@pytest.mark.parametrize('setting', [
    {'hostname': 'evil.example', 'source_ip': '85.209.159.130'},
    {'hostname': 'rg3.poshl9k.ru', 'source_ip': 'not-an-ip'},
    {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130; allow all'},
])
def test_publication_rejects_invalid_marker(caddy_config, setting):
    with pytest.raises(ValueError):
        publish_bridge(caddy_config, setting)


def test_caddy_adapter_applies_host_marker_even_to_old_snapshot(caddy_config):
    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    fs.write(MARKER, json.dumps({'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}))
    files = CaddyReloader(filesystem=fs).install(source)
    updated = json.loads(files['caddy.json'])
    assert updated == json.loads(fs.read(Path('/etc/caddy/caddy.json')))
    assert updated['apps']['http']['servers']['management']['routes'][0]['match'][0]['remote_ip'] == {
        'ranges': ['85.209.159.130/32']}
    fs.write(MARKER, json.dumps({'hostname': 'not-on-panel.example', 'source_ip': '85.209.159.130'}))
    # A rollback to a pre-domain snapshot must restore the panel, not fail it.
    restored = CaddyReloader(filesystem=fs).install(source)
    assert json.loads(restored['caddy.json']) == caddy_config
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == caddy_config
    fs.write(MARKER, '{malformed')
    assert json.loads(CaddyReloader(filesystem=fs).install(source)['caddy.json']) == caddy_config


def test_boot_restore_skips_optional_bridge_on_old_hostname(tmp_path, monkeypatch, caddy_config):
    from vs_router.agent import boot_restore
    import grp
    import os
    fs = FakeFS()
    old = json.loads(json.dumps(caddy_config))
    old['apps']['tls']['certificates']['automate'] = ['old.example']
    source = tmp_path / 'caddy.conf'
    source.write_text(serialize_caddy({'caddy.json': json.dumps(old)}))
    fs.write(source, source.read_text())
    fs.write(MARKER, json.dumps({'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}))
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path))
    monkeypatch.setattr('vs_router.agent.apply.LocalFileSystem', lambda: fs)
    monkeypatch.setattr('vs_router.agent.services.LocalFileSystem', lambda: fs)
    monkeypatch.setattr(grp, 'getgrnam', lambda _: type('Group', (), {'gr_gid': 1})())
    monkeypatch.setattr(os, 'chown', lambda *_: None, raising=False)
    monkeypatch.setattr(os, 'chmod', lambda *_: None)
    assert boot_restore.restore_tunnel_proxy_files() == 0
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == old


def test_public_bridge_app_rejects_local_portal_routes():
    from vs_router.master_bridge_app import create_master_bridge_app
    from vs_router.db import Base
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    app = create_master_bridge_app(engine=engine)
    paths = {route.path for route in app.routes}
    assert '/internal/master/state' in paths
    assert '/internal/master/token-rotate' in paths
    assert not any(path.startswith('/internal/portal/') for path in paths)
    with TestClient(app) as client:
        assert client.get('/internal/portal/subscribers/example/state').status_code == 404
        assert client.get('/internal/master/state').status_code == 403


def test_token_bootstrap_is_one_time_and_encrypted(monkeypatch):
    from vs_router.db import Base
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    token = 'a' * 43
    install_token(engine, io.BytesIO((token + '\n').encode()))
    with Session(engine) as db:
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        assert row is not None
        assert token not in json.dumps(row.value)
        assert _read_master_tokens(db) == (token, '')
    with pytest.raises(ValueError, match='already installed'):
        install_token(engine, io.BytesIO(('b' * 43 + '\n').encode()))
    with pytest.raises(ValueError, match='invalid'):
        install_token(engine, io.BytesIO(b'wrong\n'))
    with Session(engine) as db:
        assert _read_master_tokens(db) == (token, '')


def test_configure_publication_updates_caddy_and_is_idempotent(caddy_config):
    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    fs.write(Path('/etc/caddy/caddy.json'), json.dumps(caddy_config))
    setting = {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}
    calls = []

    def reload(path):
        calls.append(path)
        return CaddyReloader(filesystem=fs).install(path)

    assert configure_publication(fs, source, setting, reload) == {
        'published': True, **setting}
    assert configure_publication(fs, source, setting, reload) == {
        'published': True, **setting}
    assert len(calls) == 2
    assert json.loads(fs.read(MARKER)) == setting
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == publish_bridge(caddy_config, setting)


def test_configure_publication_refuses_live_caddy_drift(caddy_config):
    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    drifted = json.loads(json.dumps(caddy_config))
    drifted['apps']['http']['servers']['management']['routes'].append(
        {'match': [{'host': ['other.example']}], 'handle': [{'handler': 'static_response'}]})
    fs.write(Path('/etc/caddy/caddy.json'), json.dumps(drifted))
    calls = []

    with pytest.raises(ValueError, match='master_bridge.caddy_drift'):
        configure_publication(fs, source, {'hostname': 'rg3.poshl9k.ru',
                                            'source_ip': '85.209.159.130'},
                              lambda path: calls.append(path))
    assert calls == []
    with pytest.raises(FileNotFoundError):
        fs.read(MARKER)


def test_configure_publication_restores_marker_and_panel_after_reload_failure(caddy_config):
    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    fs.write(Path('/etc/caddy/caddy.json'), json.dumps(caddy_config))
    calls = []

    def reload(path):
        calls.append(path)
        result = CaddyReloader(filesystem=fs).install(path)
        if len(calls) == 1:
            raise RuntimeError('synthetic reload failure')
        return result

    with pytest.raises(ValueError, match='master_bridge.publication_failed'):
        configure_publication(fs, source,
                              {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'},
                              reload)
    assert len(calls) == 2
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == caddy_config
    with pytest.raises(FileNotFoundError):
        fs.read(MARKER)


def test_master_bridge_publication_rpc_uses_typed_host_marker(caddy_config):
    from types import SimpleNamespace
    from vs_router.agent import daemon
    from vs_router.agent.apply import APPLIED_DIR
    from vs_router.agent.rpc import build_request

    fs = FakeFS()
    source = APPLIED_DIR / 'caddy.conf'
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    fs.write(Path('/etc/caddy/caddy.json'), json.dumps(caddy_config))
    calls = []

    def reload(path):
        calls.append(path)
        return CaddyReloader(filesystem=fs).install(path)

    engine = SimpleNamespace(fs=fs, reload_commands={'caddy': reload}, status=lambda: None)
    handlers = daemon.make_handlers(engine, None)
    params = {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}
    response = daemon.dispatch(
        build_request('set_master_bridge_publication', params).model_dump_json(), handlers)
    assert response.error is None
    assert response.result == {'published': True, **params}
    assert calls == [source]

    pending_engine = SimpleNamespace(
        fs=fs, reload_commands={'caddy': reload}, status=lambda: {'status': 'pending'})
    pending_handlers = daemon.make_handlers(pending_engine, None)
    pending = daemon.dispatch(build_request(
        'set_master_bridge_publication', params).model_dump_json(), pending_handlers)
    assert pending.error.message == 'agent.apply_pending'
    assert calls == [source]

    status = daemon.dispatch(build_request(
        'master_bridge_publication_status', {}).model_dump_json(), handlers)
    assert status.error is None
    assert status.result == {'publication_state': 'configured_on_disk'}

    invalid = daemon.dispatch(build_request(
        'set_master_bridge_publication', {'hostname': params['hostname'],
                                          'source_ip': 'not-an-ip'}).model_dump_json(), handlers)
    assert invalid.error.message == 'master_bridge.publication_invalid'
    assert calls == [source]


def test_configure_publication_recovers_candidate_after_failed_marker_restore(caddy_config):
    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    previous = {'hostname': 'rg3.poshl9k.ru', 'source_ip': '192.0.2.20'}
    setting = {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}
    fs.write(MARKER, json.dumps(previous))
    previous_config = publish_bridge(caddy_config, previous)
    candidate = publish_bridge(caddy_config, setting)
    fs.write(Path('/etc/caddy/caddy.json'), json.dumps(previous_config))
    interrupted_calls = []

    def interrupt(path):
        interrupted_calls.append(path)
        if len(interrupted_calls) == 1:
            CaddyReloader(filesystem=fs).install(path)
        raise RuntimeError('synthetic reload interruption')

    with pytest.raises(ValueError, match='master_bridge.restore_failed'):
        configure_publication(fs, source, setting, interrupt)
    assert json.loads(fs.read(MARKER)) == previous
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == candidate

    retry_calls = []

    def recover(path):
        retry_calls.append(path)
        return CaddyReloader(filesystem=fs).install(path)

    assert configure_publication(fs, source, setting, recover) == {
        'published': True, **setting}
    assert retry_calls == [source]
    assert json.loads(fs.read(MARKER)) == setting
    assert json.loads(fs.read(Path('/etc/caddy/caddy.json'))) == candidate


def test_publication_status_reports_disk_state_without_claiming_connectivity(caddy_config):
    from vs_router.agent.master_bridge_publication import publication_status

    fs = FakeFS()
    source = Path('/etc/vs-router/applied/caddy.conf')
    fs.write(source, serialize_caddy({'caddy.json': json.dumps(caddy_config)}))
    live_path = Path('/etc/caddy/caddy.json')
    fs.write(live_path, json.dumps(caddy_config))
    assert publication_status(fs, source) == {'publication_state': 'absent'}

    fs.write(MARKER, '{malformed')
    assert publication_status(fs, source) == {'publication_state': 'invalid_marker'}

    setting = {'hostname': 'rg3.poshl9k.ru', 'source_ip': '85.209.159.130'}
    fs.write(MARKER, json.dumps(setting))
    assert publication_status(fs, source) == {'publication_state': 'drift'}
    fs.write(live_path, json.dumps(publish_bridge(caddy_config, setting)))
    assert publication_status(fs, source) == {'publication_state': 'configured_on_disk'}
