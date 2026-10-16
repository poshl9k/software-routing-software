"""Profile contracts use temporary files and injected capabilities; no root/network."""
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from test_agent_apply import FakeExecutor, FakeFS, snapshot
from test_api import anyio_backend, api, sign_in
from vs_router import profile
from vs_router.agent import apply as apply_mod, daemon
from vs_router.agent.apply import APPLIED_DIR, FILES, PHASE_TOOLS, ApplyEngine, ApplyError, host_files
from vs_router.agent.rpc import build_request
from vs_router.db import ConfigurationRow, save_version
from vs_router.schema import ConfigurationVersion

pytestmark = pytest.mark.anyio


def test_criterion_1_read_missing_unknown_unreadable(tmp_path, monkeypatch):
    path = tmp_path / 'profile'
    assert profile.read_profile(path) is None
    path.write_text('unknown\n')
    assert profile.read_profile(path) is None
    path.write_bytes(b'\xff')
    assert profile.read_profile(path) is None
    assert profile.read_profile(tmp_path) is None
    monkeypatch.setattr(Path, 'read_text', Mock(side_effect=PermissionError('denied')))
    assert profile.read_profile(path) is None


def test_criterion_2_atomic_write_roundtrip_and_reject_unknown(tmp_path, monkeypatch):
    path = tmp_path / 'nested/profile'
    for value in profile.PROFILES:
        profile.record_profile(value, path)
        assert profile.read_profile(path) == value
        assert path.read_text() == value + '\n'
    original = path.read_bytes()
    original_stat = path.stat()
    with pytest.raises(ValueError, match=r'^profile\.unknown$'):
        profile.record_profile('invalid', path)
    assert path.read_bytes() == original
    assert path.stat() == original_stat
    absent = tmp_path / 'must-not-create/profile'
    with pytest.raises(ValueError, match=r'^profile\.unknown$'):
        profile.record_profile('invalid', absent)
    assert not absent.parent.exists()

    real_replace = profile.os.replace
    def replace(source, destination):
        assert Path(source).parent == path.parent
        assert path.read_bytes() == original
        assert Path(source).read_text() == 'router\n'
        real_replace(source, destination)
    monkeypatch.setattr(profile.os, 'replace', replace)
    profile.record_profile('router', path)
    assert profile.read_profile(path) == 'router'
    monkeypatch.setattr(profile.os, 'replace', Mock(side_effect=OSError('replace failed')))
    with pytest.raises(OSError, match='replace failed'):
        profile.record_profile('panel', path)
    assert profile.read_profile(path) == 'router'
    assert list(path.parent.iterdir()) == [path]


def test_criterion_3_configuration_profile_is_additive():
    assert ConfigurationVersion.model_validate(snapshot()).profile == 'router'
    assert ConfigurationVersion.model_validate(dict(snapshot(), profile='panel')).profile == 'panel'
    with pytest.raises(ValueError):
        ConfigurationVersion.model_validate(dict(snapshot(), profile='invalid'))


def test_criterion_4_profile_mismatch_has_no_system_effects(monkeypatch):
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         management_provider=lambda: pytest.fail('guard must run first'),
                         panel_probe=lambda: pytest.fail('guard must precede the network probe'))
    with pytest.raises(ApplyError) as failure:
        engine.apply_version(dict(snapshot(), profile='panel'))
    assert failure.value.code == 'configuration.profile_mismatch'
    assert fs.files == {}
    assert executor.calls == []


@pytest.mark.parametrize('marker,dhcp,conflict', [
    ('panel', True, 'profile.capability_mismatch'),
    ('router', False, 'profile.capability_mismatch'),
    ('panel', False, None), ('router', True, None),
    (None, False, None), (None, True, None),
])
def test_criterion_5_capability_guard_and_legacy(monkeypatch, marker, dhcp, conflict):
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: marker)
    monkeypatch.setattr(apply_mod.shutil, 'which',
                        lambda name: f'/usr/sbin/{name}' if dhcp else None)
    assert profile.capability_conflict(marker, dhcp) == conflict
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which))
    document = dict(snapshot(), profile=marker or 'panel')
    if conflict:
        with pytest.raises(ApplyError) as failure:
            engine.apply_version(document)
        assert failure.value.code == conflict
        assert fs.files == {}
        assert executor.calls == []
    else:
        assert engine.apply_version(document).status == 'confirmed'


async def test_criterion_6_host_profile_authenticated_live_rpc(api, monkeypatch, tmp_path):
    from vs_router.api import versions

    client, database, _ = api
    path = tmp_path / 'profile'
    read_profile = profile.read_profile
    monkeypatch.setattr(profile, 'read_profile', lambda: read_profile(path))
    handlers = daemon.make_handlers(ApplyEngine(filesystem=FakeFS(), executor=FakeExecutor()), database)
    calls = []

    class Transport:
        def __init__(self, socket_path):
            pass
        def send(self, message):
            calls.append(json.loads(message))
            self.response = daemon.dispatch(message, handlers)
        def recv(self):
            return self.response.model_dump_json(exclude_unset=True).encode()
        def close(self):
            pass

    monkeypatch.setattr(versions, 'UnixSocketTransport', Transport)
    assert (await client.get('/api/host/profile')).status_code == 401
    assert calls == []
    await sign_in(client)
    for marker, dhcp in ((None, False), ('panel', False), ('panel', True), ('router', True)):
        if marker is not None:
            profile.record_profile(marker, path)
        monkeypatch.setattr(daemon.shutil, 'which',
                            lambda name: f'/usr/sbin/{name}' if dhcp else None)
        response = await client.get('/api/host/profile')
        assert response.status_code == 200
        assert response.json() == {'profile': marker, 'declared': marker is not None, 'dhcp': dhcp}
        assert calls[-1]['method'] == 'profile'
        assert calls[-1]['params'] == {}
    with pytest.raises(ValueError):
        build_request('profile', {'profile': 'panel'})
    monkeypatch.setattr(Transport, 'send', Mock(side_effect=OSError('unreachable')))
    response = await client.get('/api/host/profile')
    assert response.status_code == 503
    assert response.json()['code'] == 'agent.unavailable'
    monkeypatch.setattr(Transport, 'send', Mock(side_effect=RuntimeError('private details')))
    response = await client.get('/api/host/profile')
    assert response.status_code == 503
    assert response.json()['code'] == 'host.interfaces_unavailable'
    assert 'private details' not in response.text


def test_criterion_7_cli_show_write_and_unset(tmp_path):
    path = tmp_path / 'profile'
    def run(*args):
        return subprocess.run([sys.executable, '-m', 'vs_router.profile', '--path', str(path), *args],
                              capture_output=True, text=True, timeout=10)
    result = run('show')
    assert result.returncode == 0
    assert result.stdout == 'unset\n'
    for value in profile.PROFILES:
        assert run('write', value).returncode == 0
        result = run('show')
        assert result.returncode == 0
        assert result.stdout == value + '\n'
    original = path.read_bytes()
    assert run('write', 'unknown').returncode != 0
    assert path.read_bytes() == original
    path.write_text('invalid')
    assert run('show').stdout == 'unset\n'
    path.unlink()
    path.mkdir()
    assert run('write', 'router').returncode != 0


@pytest.mark.parametrize('dhcp', [False, True])
def test_criterion_8_legacy_host_files_and_apply_unchanged(monkeypatch, dhcp):
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: None)
    which = lambda name: f'/usr/sbin/{name}' if dhcp else None
    files = host_files(which=which)
    assert set(files) == (set(FILES) if dhcp else set(FILES) - set(PHASE_TOOLS))
    monkeypatch.setattr(apply_mod, 'capability_conflict',
                        lambda *args: pytest.fail('no profile guard on a legacy host'))
    fs, executor = FakeFS(), FakeExecutor()
    result = ApplyEngine(filesystem=fs, executor=executor, files=files).apply_version(snapshot())
    assert result.status == 'confirmed'
    assert set(result.phases) == set(files)
    assert (APPLIED_DIR / 'kea.json' in fs.files) is dhcp


def test_profile_migration_existing_rows_and_storage_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv('VS_ROUTER_DATABASE_URL', raising=False)
    config = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    config.set_main_option('sqlalchemy.url', f"sqlite:///{tmp_path / 'profile.db'}")
    command.upgrade(config, '0003')
    database = create_engine(config.get_main_option('sqlalchemy.url'))
    try:
        with database.begin() as connection:
            connection.execute(text("INSERT INTO configuration_versions (id, status, configuration, created_at) "
                                    "VALUES (1, 'confirmed', '{}', '2026-01-01 00:00:00')"))
        command.upgrade(config, 'head')
        with Session(database) as session:
            assert session.get(ConfigurationRow, 1).snapshot().profile == 'router'
            save_version(session, ConfigurationVersion(id=2, profile='panel'))
            session.commit()
        with Session(database) as session:
            assert session.get(ConfigurationRow, 2).snapshot().profile == 'panel'
        with database.begin() as connection:
            connection.execute(text("INSERT INTO configuration_versions (id, status, configuration, created_at) "
                                    "VALUES (3, 'confirmed', '{}', '2026-01-01 00:00:00')"))
            assert connection.execute(text('SELECT profile FROM configuration_versions WHERE id=3')).scalar_one() == 'router'
        command.check(config)
        command.downgrade(config, '0003')
        with database.connect() as connection:
            assert 'profile' not in connection.execute(text('SELECT * FROM configuration_versions')).keys()
    finally:
        database.dispose()


async def test_profile_survives_draft_alias_import_and_backup(api):
    client, database, _ = api
    await sign_in(client)
    with Session(database) as session:
        save_version(session, ConfigurationVersion(id=1, status='confirmed', profile='panel'))
        session.commit()
    response = await client.post('/api/draft')
    assert response.status_code == 201
    assert response.json()['profile'] == 'panel'
    assert (await client.delete('/api/draft')).status_code == 204
    response = await client.post('/api/aliases/import', json={'aliases': []})
    assert response.status_code == 200
    versions = (await client.get('/api/versions')).json()
    assert versions[0]['profile'] == 'panel'
    archive = (await client.get('/api/backup/export')).json()
    assert archive['versions'][-1]['profile'] == 'panel'
    assert (await client.delete('/api/draft')).status_code == 204
    assert (await client.post('/api/backup/restore', json=archive)).status_code == 200
    assert (await client.get('/api/versions')).json()[0]['profile'] == 'panel'
    assert (await client.delete('/api/draft')).status_code == 204
    archive['versions'][-1]['profile'] = 'invalid'
    assert (await client.post('/api/backup/restore', json=archive)).status_code == 400
