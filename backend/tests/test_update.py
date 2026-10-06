"""Online release update: manifest validation, status comparison, guarded apply."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vs_router.agent import update as update_module
from vs_router.agent import daemon
from vs_router.agent.rpc import build_request
from test_api import api, sign_in

COMMIT = 'a' * 40
OTHER = 'b' * 40
SHA = 'c' * 64


def manifest(**overrides):
    data = {'commit': COMMIT, 'semver': '0.2.0',
            'source_url': f'https://example.invalid/vs-router-{COMMIT}.tar.gz',
            'source_sha256': SHA, 'min_os': 'debian-13'}
    data.update(overrides)
    return json.dumps(data)


def opener_for(payload):
    return lambda url, timeout: payload


def test_read_config_from_file_and_env(tmp_path, monkeypatch):
    path = tmp_path / 'update.json'
    path.write_text(json.dumps({'manifest_url': 'https://example.invalid/release.json'}))
    monkeypatch.delenv('VS_ROUTER_UPDATE_MANIFEST_URL', raising=False)
    assert update_module.read_config(path) == {'manifest_url': 'https://example.invalid/release.json'}
    monkeypatch.setenv('VS_ROUTER_UPDATE_MANIFEST_URL', 'https://env.invalid/release.json')
    assert update_module.read_config(path) == {'manifest_url': 'https://env.invalid/release.json'}


@pytest.mark.parametrize('content', [None, '', 'not json', '[]', '{}', '{"manifest_url": 5}'])
def test_config_missing_or_malformed_is_unset(tmp_path, content, monkeypatch):
    monkeypatch.delenv('VS_ROUTER_UPDATE_MANIFEST_URL', raising=False)
    path = tmp_path / 'update.json'
    if content is not None:
        path.write_text(content)
    assert update_module.read_config(path) == {'manifest_url': None}


def test_fetch_manifest_requires_https_and_valid_fields():
    with pytest.raises(update_module.ApplyError) as error:
        update_module.fetch_manifest('http://example.invalid/release.json', opener_for(manifest()))
    assert error.value.code == 'update.manifest_invalid'
    with pytest.raises(update_module.ApplyError):
        update_module.fetch_manifest('https://x/release.json', opener_for(manifest(commit='nope')))
    with pytest.raises(update_module.ApplyError):
        update_module.fetch_manifest('https://x/release.json', opener_for(manifest(source_url='http://x/a.tgz')))
    with pytest.raises(update_module.ApplyError):
        update_module.fetch_manifest('https://x/release.json', opener_for(manifest(source_sha256='short')))
    with pytest.raises(update_module.ApplyError):
        update_module.fetch_manifest('https://x/release.json', opener_for('not json'))


def test_fetch_manifest_returns_normalized_fields():
    result = update_module.fetch_manifest('https://x/release.json', opener_for(manifest()))
    assert result['commit'] == COMMIT
    assert result['semver'] == '0.2.0'
    assert result['source_sha256'] == SHA
    assert result['source_url'].endswith(f'vs-router-{COMMIT}.tar.gz')


def test_status_without_config_is_read_only(tmp_path, monkeypatch):
    monkeypatch.delenv('VS_ROUTER_UPDATE_MANIFEST_URL', raising=False)
    monkeypatch.setattr(update_module, 'read_release', lambda: {'commit': COMMIT, 'semver': '0.1.0'})
    status = update_module.release_status(tmp_path / 'missing.json', tmp_path / 'no-state.json',
                                          unit_active=False)
    assert status['configured'] is False
    assert status['available'] is None and status['update_available'] is False
    assert status['current'] == {'commit': COMMIT, 'semver': '0.1.0'}


def test_status_compares_installed_with_published(tmp_path, monkeypatch):
    monkeypatch.delenv('VS_ROUTER_UPDATE_MANIFEST_URL', raising=False)
    monkeypatch.setattr(update_module, 'read_release', lambda: {'commit': COMMIT, 'semver': '0.1.0'})
    config = tmp_path / 'update.json'
    config.write_text(json.dumps({'manifest_url': 'https://example.invalid/release.json'}))
    newer = update_module.release_status(config, tmp_path / 'no-state.json',
                                         opener=opener_for(manifest(commit=OTHER, semver='0.2.0')),
                                         unit_active=False)
    assert newer['update_available'] is True
    assert newer['available'] == {'commit': OTHER, 'semver': '0.2.0'}
    same = update_module.release_status(config, tmp_path / 'no-state.json',
                                        opener=opener_for(manifest(commit=COMMIT)),
                                        unit_active=False)
    assert same['update_available'] is False


def test_status_reports_fetch_failure_without_raising(tmp_path):
    config = tmp_path / 'update.json'
    config.write_text(json.dumps({'manifest_url': 'https://example.invalid/release.json'}))

    def boom(url, timeout):
        raise OSError('no route')

    status = update_module.release_status(config, tmp_path / 'no-state.json',
                                          opener=boom, unit_active=False)
    assert status['error'] == 'update.manifest_unavailable'
    assert status['available'] is None


def test_read_state_validates_the_recorded_outcome(tmp_path):
    path = tmp_path / 'state.json'
    path.write_text(json.dumps({'status': 'success', 'release': COMMIT,
                                'started_at': '2026-10-06T00:00:00Z',
                                'finished_at': '2026-10-06T00:10:00Z', 'exit_code': 0}))
    state = update_module.read_state(path)
    assert state is not None and state['status'] == 'success'
    path.write_text(json.dumps({'status': 'bogus'}))
    assert update_module.read_state(path) is None
    assert update_module.read_state(tmp_path / 'missing.json') is None


def test_apply_update_requires_a_pinned_commit(tmp_path, monkeypatch):
    monkeypatch.setenv('VS_ROUTER_UPDATE_MANIFEST_URL', 'https://example.invalid/release.json')
    with pytest.raises(update_module.ApplyError) as error:
        update_module.apply_update('not-a-commit', unit_active=False, spawn=lambda *a: None)
    assert error.value.code == 'update.invalid_release'


def test_apply_update_requires_configuration(monkeypatch):
    monkeypatch.delenv('VS_ROUTER_UPDATE_MANIFEST_URL', raising=False)
    monkeypatch.setattr(update_module, 'CONFIG_FILE', Path('/nonexistent/update.json'))
    with pytest.raises(update_module.ApplyError) as error:
        update_module.apply_update(COMMIT, unit_active=False, spawn=lambda *a: None)
    assert error.value.code == 'update.not_configured'


def test_apply_update_rejects_a_mismatch_and_running_unit(monkeypatch):
    monkeypatch.setenv('VS_ROUTER_UPDATE_MANIFEST_URL', 'https://example.invalid/release.json')
    spawns = []
    with pytest.raises(update_module.ApplyError) as error:
        update_module.apply_update(COMMIT, opener=opener_for(manifest(commit=OTHER)),
                                   unit_active=False, spawn=lambda *a: spawns.append(a))
    assert error.value.code == 'update.release_mismatch'
    assert spawns == []
    with pytest.raises(update_module.ApplyError) as busy:
        update_module.apply_update(COMMIT, unit_active=True, spawn=lambda *a: spawns.append(a))
    assert busy.value.code == 'update.already_running'
    assert spawns == []


def test_apply_update_starts_a_verified_update(monkeypatch):
    monkeypatch.setenv('VS_ROUTER_UPDATE_MANIFEST_URL', 'https://example.invalid/release.json')
    spawns = []
    result = update_module.apply_update(COMMIT, opener=opener_for(manifest()),
                                        unit_active=False, spawn=lambda *a: spawns.append(a))
    assert result == {'started': True, 'release': COMMIT}
    assert spawns == [(COMMIT, 'https://example.invalid/release.json')]


def test_rpc_rejects_a_malformed_release():
    assert build_request('apply_update', {'release': COMMIT}).method == 'apply_update'
    with pytest.raises(ValidationError):
        build_request('apply_update', {'release': 'nope'})


def test_daemon_registers_the_update_handlers():
    handlers = daemon.make_handlers(engine=None, database=None)
    assert 'update_status' in handlers and 'apply_update' in handlers


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_update_endpoints_require_admin(api, monkeypatch):
    client, engine, _ = api
    assert (await client.get('/api/update')).status_code == 401
    assert (await client.post('/api/update', json={'release': COMMIT})).status_code == 401
    await sign_in(client)
    calls = []

    def fake_call(method, body):
        calls.append((method, body))
        return {'configured': True, 'current': None}

    monkeypatch.setattr(update_module_api(), 'agent_call', fake_call)
    response = await client.get('/api/update')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == {'configured': True, 'current': None}
    posted = await client.post('/api/update', json={'release': COMMIT})
    assert posted.status_code == 200
    assert calls[1][0] == 'apply_update'


async def test_update_post_validates_the_release(api):
    client, _, _ = api
    await sign_in(client)
    assert (await client.post('/api/update', json={'release': 'nope'})).status_code == 422


async def test_update_endpoint_maps_agent_failure_to_503(api, monkeypatch):
    client, _, _ = api
    await sign_in(client)

    def unavailable(method, body):
        raise OSError('no socket')

    monkeypatch.setattr(update_module_api(), 'agent_call', unavailable)
    assert (await client.get('/api/update')).status_code == 503


def update_module_api():
    from vs_router.api import update as module
    return module
