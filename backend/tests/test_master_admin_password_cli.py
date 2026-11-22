"""Console-only master admin credential rotation and cross-worker revocation."""
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from argon2 import PasswordHasher, Type
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vs_master.app import create_master_app
from vs_master.auth import ADMIN_PASSWORD_KEY
from vs_master.models import Audit, Base, Setting, make_engine

OLD_PASSWORD = 'old-synthetic-admin-password'
NEW_PASSWORD = 'new-synthetic-admin-password'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def database(tmp_path, monkeypatch):
    url = f'sqlite:///{tmp_path / "master.db"}'
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    engine = make_engine()
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Setting(key=ADMIN_PASSWORD_KEY,
                       value=PasswordHasher(type=Type.ID).hash(OLD_PASSWORD)))
        db.commit()
    yield engine, url
    engine.dispose()


@pytest.mark.anyio
async def test_password_change_invalidates_sessions_in_independent_workers(database):
    engine, url = database
    other_engine = make_engine(url)
    try:
        async with AsyncExitStack() as stack:
            clients = [await stack.enter_async_context(AsyncClient(
                transport=ASGITransport(app=create_master_app(engine=worker_engine)),
                base_url='https://master.test')) for worker_engine in (engine, other_engine)]
            for client in clients:
                assert (await client.post('/api/admin/login', json={
                    'password': OLD_PASSWORD})).status_code == 200
                assert (await client.get('/api/admin/me')).status_code == 200
            result = run_console()
            assert result.returncode == 0, result.stderr
            for client in clients:
                assert (await client.get('/api/admin/me')).status_code == 401
                assert (await client.get('/api/master-admin/subscribers')).status_code == 401
                assert (await client.post('/api/admin/login', json={
                    'password': OLD_PASSWORD})).status_code == 401
                assert (await client.post('/api/admin/login', json={
                    'password': NEW_PASSWORD})).status_code == 200
                assert (await client.get('/api/admin/me')).status_code == 200
    finally:
        other_engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize('rehash', [False, True])
async def test_login_racing_password_reset_cannot_restore_old_credentials(database, monkeypatch, rehash):
    engine, url = database
    other_engine = make_engine(url)
    app = create_master_app(engine=engine)
    original_verify = app.state.auth.hasher.verify
    replacement_hash = PasswordHasher(type=Type.ID).hash(NEW_PASSWORD)

    def verify_and_rotate(self, password_hash, password):
        result = original_verify(password_hash, password)
        with Session(other_engine) as db:
            setting = db.get(Setting, ADMIN_PASSWORD_KEY)
            assert setting is not None
            setting.value = replacement_hash
            db.commit()
        return result

    monkeypatch.setattr(PasswordHasher, 'verify', verify_and_rotate)
    monkeypatch.setattr(PasswordHasher, 'check_needs_rehash', lambda self, _: rehash)
    try:
        async with AsyncClient(transport=ASGITransport(app=app),
                               base_url='https://master.test') as client:
            result = await client.post('/api/admin/login', json={'password': OLD_PASSWORD})
            assert result.status_code in (200, 401)
            assert (await client.get('/api/admin/me')).status_code == 401
        with Session(engine) as db:
            setting = db.get(Setting, ADMIN_PASSWORD_KEY)
            assert setting is not None and setting.value == replacement_hash
    finally:
        other_engine.dispose()


def run_console(*, passwords=(NEW_PASSWORD, NEW_PASSWORD), confirmation='yes', tty=True,
                arguments=()):
    # Exercise the actual python -m entry point in a separate process, replacing
    # only the terminal interaction. The database and Argon2 remain real.
    script = '''
import builtins, getpass, json, os, runpy, sys
answers = iter(json.loads(os.environ.pop('TEST_PASSWORDS')))
sys.stdin.isatty = lambda: os.environ.pop('TEST_TTY') == '1'
getpass.getpass = lambda prompt: next(answers)
builtins.input = lambda prompt: os.environ.pop('TEST_CONFIRMATION')
sys.argv = ['vs_master.change_admin_password'] + json.loads(os.environ.pop('TEST_ARGUMENTS'))
runpy.run_module('vs_master.change_admin_password', run_name='__main__')
'''
    env = {**os.environ,
           'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src'),
           'TEST_PASSWORDS': json.dumps(passwords),
           'TEST_CONFIRMATION': confirmation,
           'TEST_TTY': '1' if tty else '0',
           'TEST_ARGUMENTS': json.dumps(arguments)}
    return subprocess.run([sys.executable, '-c', script], env=env, text=True,
                          capture_output=True, timeout=30)


def test_console_command_rotates_existing_admin_without_disclosing_credentials(database, caplog):
    engine, _ = database
    result = run_console()
    assert result.returncode == 0, result.stderr
    with Session(engine) as db:
        setting = db.get(Setting, ADMIN_PASSWORD_KEY)
        assert setting is not None
        stored = setting.value
        assert stored.startswith('$argon2id$')
        assert PasswordHasher().verify(stored, NEW_PASSWORD)
        rows = list(db.scalars(select(Audit).where(Audit.action == 'admin.password.change')))
        assert len(rows) == 1
        assert rows[0].actor == 'console' and rows[0].detail is None
    output = result.stdout + result.stderr + caplog.text
    assert 'password changed' in output.lower()
    assert 'sessions revoked' in output.lower()
    assert all(secret not in output for secret in (OLD_PASSWORD, NEW_PASSWORD, stored))


@pytest.mark.parametrize('options,message', [
    ({'passwords': (NEW_PASSWORD, OLD_PASSWORD)}, 'do not match'),
    ({'passwords': ('short', 'short')}, '8 to 1024'),
    ({'passwords': ('x' * 1025, 'x' * 1025)}, '8 to 1024'),
    ({'passwords': ('', '')}, '8 to 1024'),
    ({'confirmation': 'no'}, 'Cancelled'),
    ({'confirmation': ''}, 'Cancelled'),
    ({'tty': False}, 'interactive server terminal'),
    ({'arguments': ('--password', NEW_PASSWORD)}, 'No arguments accepted'),
])
def test_console_rejections_do_not_change_database(database, options, message):
    engine, _ = database
    with Session(engine) as db:
        before = db.scalar(select(Setting.value).where(Setting.key == ADMIN_PASSWORD_KEY))
    result = run_console(**options)
    assert result.returncode == 1
    assert message in result.stderr
    assert NEW_PASSWORD not in result.stdout + result.stderr
    with Session(engine) as db:
        assert db.scalar(select(Setting.value).where(Setting.key == ADMIN_PASSWORD_KEY)) == before
        assert list(db.scalars(select(Audit))) == []


def test_console_requires_explicit_service_database(database, monkeypatch, tmp_path):
    monkeypatch.delenv('VS_MASTER_DATABASE_URL')
    monkeypatch.chdir(tmp_path)
    result = run_console()
    assert result.returncode == 1
    assert 'Set VS_MASTER_DATABASE_URL' in result.stderr
    assert not (tmp_path / 'vs-master.db').exists()


def test_console_does_not_initialize_missing_admin(database):
    engine, _ = database
    with Session(engine) as db:
        setting = db.get(Setting, ADMIN_PASSWORD_KEY)
        assert setting is not None
        db.delete(setting)
        db.commit()
    result = run_console()
    assert result.returncode == 1
    assert 'not initialized' in result.stderr
    with Session(engine) as db:
        assert db.get(Setting, ADMIN_PASSWORD_KEY) is None
        assert list(db.scalars(select(Audit))) == []


def test_console_audit_failure_rolls_back_password_and_redacts_database_error(database):
    engine, _ = database
    with engine.begin() as connection:
        connection.execute(text('''CREATE TRIGGER reject_password_audit
            BEFORE INSERT ON master_audit BEGIN
            SELECT RAISE(ABORT, 'synthetic-private-database-error'); END'''))
    with Session(engine) as db:
        before = db.scalar(select(Setting.value).where(Setting.key == ADMIN_PASSWORD_KEY))
    result = run_console()
    assert result.returncode == 1
    assert 'Password change failed' in result.stderr
    assert 'synthetic-private-database-error' not in result.stderr
    assert '$argon2' not in result.stderr and 'Traceback' not in result.stderr
    with Session(engine) as db:
        assert db.scalar(select(Setting.value).where(Setting.key == ADMIN_PASSWORD_KEY)) == before
        assert list(db.scalars(select(Audit))) == []


@pytest.mark.parametrize('interruption', ['eof', 'interrupt', 'echo-warning'])
def test_console_input_failure_is_safe(database, monkeypatch, capsys, interruption):
    from vs_master import change_admin_password as cli
    import warnings

    def interrupted_input(prompt):
        if interruption == 'echo-warning':
            warnings.warn('terminal echo unavailable', cli.getpass.GetPassWarning)
            pytest.fail('getpass fallback must not consume a password')
        raise EOFError if interruption == 'eof' else KeyboardInterrupt

    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(cli.getpass, 'getpass', interrupted_input)
    assert cli.main([]) == 1
    output = capsys.readouterr()
    assert 'Cancelled' in output.err
    engine, _ = database
    with Session(engine) as db:
        assert list(db.scalars(select(Audit))) == []
        setting = db.get(Setting, ADMIN_PASSWORD_KEY)
        assert setting is not None and PasswordHasher().verify(setting.value, OLD_PASSWORD)


@pytest.mark.anyio
async def test_same_password_reset_still_revokes_sessions(database):
    engine, _ = database
    async with AsyncClient(transport=ASGITransport(app=create_master_app(engine=engine)),
                           base_url='https://master.test') as client:
        assert (await client.post('/api/admin/login', json={
            'password': OLD_PASSWORD})).status_code == 200
        result = run_console(passwords=(OLD_PASSWORD, OLD_PASSWORD))
        assert result.returncode == 0, result.stderr
        assert (await client.get('/api/admin/me')).status_code == 401
        assert (await client.post('/api/admin/login', json={
            'password': OLD_PASSWORD})).status_code == 200


def test_no_admin_password_recovery_web_route():
    from fastapi.routing import APIRoute
    from vs_master.auth import router
    assert {route.path for route in router.routes if isinstance(route, APIRoute)} == {
        '/setup', '/login', '/logout', '/me'}
