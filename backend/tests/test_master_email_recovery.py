"""Subscriber-only recovery: real SQLite transactions and HTTP boundaries."""
import asyncio
import threading
from pathlib import Path
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vs_master.accounts import COOKIE, portal_link_token
from vs_master.app import create_master_app
from vs_master.models import Account, Audit, Base, EmailRateLimit, Setting, make_engine

NOW = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
OLD_PASSWORD = 'original-test-password'
NEW_PASSWORD = 'replacement-test-password'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def rig(tmp_path, monkeypatch):
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('VS_MASTER_PUBLIC_URL', 'https://portal.example')
    monkeypatch.setenv('VS_MASTER_SMTP_HOST', 'smtp.example')
    monkeypatch.setenv('VS_MASTER_SMTP_FROM', 'noreply@example.org')
    monkeypatch.setenv('VS_MASTER_SMTP_SECURITY', 'starttls')
    engine = make_engine(f"sqlite:///{tmp_path / 'email.db'}")
    Base.metadata.create_all(engine)
    clock = [NOW]
    app = create_master_app(engine=engine, clock=lambda: clock[0])
    with Session(engine) as db:
        db.add(Account(id=1, display_name='Alice', telegram_chat_id='101',
                       password_hash=app.state.portal_auth.hasher.hash(OLD_PASSWORD)))
        db.add(Setting(key='admin_password_hash', value='admin-unchanged'))
        db.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://master.test') as client:
        response = await client.post('/api/portal/login', json={
            'username': 'Alice', 'password': OLD_PASSWORD})
        assert response.status_code == 200
        yield client, engine, clock, app
    engine.dispose()


def deliver(engine, now, monkeypatch):
    from vs_master import mail
    messages = []
    monkeypatch.setattr(mail, 'send_mail', lambda config, recipient, body: messages.append((recipient, body)))
    mail.process_email_outbox(engine, now=now)
    assert len(messages) == 1
    return messages[0][1].split('#token=')[1].split()[0], messages[0]


@pytest.mark.anyio
async def test_verified_email_reset_revokes_other_workers_but_not_permanent_links(rig, monkeypatch):
    client, engine, clock, app = rig
    response = await client.post('/api/portal/email/request', json={'email': ' Alice@Example.org '})
    assert response.status_code == 202, response.text
    assert response.json() == {'status': 'queued'}
    assert response.headers['cache-control'] == 'no-store'
    assert (await client.get('/api/portal/me')).json()['account']['email'] is None
    token, message = deliver(engine, clock[0], monkeypatch)
    assert message[0] == 'alice@example.org'
    assert 'https://portal.example/portal/email/confirm#token=' in message[1]
    assert 'master.test' not in message[1]
    with engine.connect() as conn:
        assert conn.scalar(text('SELECT token_hash FROM master_email_proofs')) == sha256(token.encode()).hexdigest()
    confirmed = await client.post('/api/portal/email/confirm', json={'token': token})
    assert confirmed.status_code == 204
    assert (await client.post('/api/portal/email/confirm', json={'token': token})).status_code == 400
    assert (await client.get('/api/portal/me')).json()['account']['email'] == 'alice@example.org'

    stable = portal_link_token(engine, 1, clock[0])
    second_app = create_master_app(engine=engine, clock=lambda: clock[0])
    async with AsyncClient(transport=ASGITransport(app=second_app), base_url='https://master.test') as other:
        assert (await other.post('/api/portal/login', json={'username': 'Alice', 'password': OLD_PASSWORD})).status_code == 200
        found = await client.post('/api/portal/password/forgot', json={'email': 'ALICE@example.org'})
        unknown = await client.post('/api/portal/password/forgot', json={'email': 'missing@example.org'})
        assert found.status_code == unknown.status_code == 202
        assert found.json() == unknown.json() == {'status': 'accepted'}
        reset_token, message = deliver(engine, clock[0], monkeypatch)
        assert 'https://portal.example/portal/password/reset#token=' in message[1]
        reset = await client.post('/api/portal/password/reset', json={'token': reset_token, 'password': NEW_PASSWORD})
        assert reset.status_code == 204, reset.text
        assert (await other.get('/api/portal/me')).status_code == 401
    assert (await client.get('/api/portal/me')).status_code == 401
    assert (await client.post('/api/portal/password/reset', json={'token': reset_token, 'password': 'another-valid-password'})).status_code == 400
    assert (await client.post('/api/portal/login', json={'username': 'Alice', 'password': OLD_PASSWORD})).status_code == 401
    assert (await client.post('/api/portal/login', json={'username': 'Alice', 'password': NEW_PASSWORD})).status_code == 200
    assert portal_link_token(engine, 1, clock[0]) == stable
    with Session(engine) as db:
        assert db.get(Account, 1).password_revision == 1
        assert db.get(Setting, 'admin_password_hash').value == 'admin-unchanged'
        audits = str([(a.actor, a.action, a.detail) for a in db.scalars(select(Audit))])
        assert token not in audits and reset_token not in audits and NEW_PASSWORD not in audits


@pytest.mark.anyio
async def test_request_requires_auth_and_config_and_cross_origin_is_rejected(rig, monkeypatch):
    client, engine, clock, app = rig
    denied = await client.post('/api/portal/email/request', json={'email': 'a@example.org'},
                               headers={'Origin': 'https://attacker.example'})
    assert denied.status_code == 403
    client.cookies.clear()
    assert (await client.post('/api/portal/email/request', json={'email': 'a@example.org'})).status_code == 401
    monkeypatch.delenv('VS_MASTER_SMTP_HOST')
    for email in ['a@example.org', 'unknown@example.org']:
        response = await client.post('/api/portal/password/forgot', json={'email': email})
        assert response.status_code == 503
        assert response.json()['error']['code'] == 'portal.email_unavailable'
        assert response.headers['cache-control'] == 'no-store'
    assert (await client.post('/api/admin/password/forgot', json={'email': 'a@example.org'})).status_code == 404


@pytest.mark.anyio
async def test_forgot_rate_limits_each_email_independently(rig):
    client, engine, _, _ = rig
    for _ in range(4):
        response = await client.post('/api/portal/password/forgot',
                                     json={'email': 'nobody@example.org'})
        # Public receipt stays generic even after the address bucket is used up.
        assert response.status_code == 202
    assert (await client.post('/api/portal/password/forgot',
                              json={'email': 'other@example.org'})).status_code == 202
    with Session(engine) as db:
        counts = {row.key: row.count for row in db.scalars(select(EmailRateLimit))}
    limited = sha256(b'forgot:email:nobody@example.org').hexdigest()
    separate = sha256(b'forgot:email:other@example.org').hexdigest()
    assert counts[limited] == 4
    assert counts[separate] == 1


def test_upgrade_old_registration_preserves_rows_and_email_cascades(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from alembic.migration import MigrationContext
    from alembic.autogenerate import compare_metadata
    from alembic.script import ScriptDirectory
    from sqlalchemy import inspect
    from vs_master.models import EmailOutbox, EmailProof
    from vs_router.secrets import encrypt_secret
    from vs_portal.security import get_secret_key
    from vs_master.accounts import register_telegram

    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    url = f"sqlite:///{tmp_path / 'upgrade.db'}"
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master/alembic.ini'))
    command.upgrade(config, '0019_master')
    engine = make_engine(url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO master_accounts (id, display_name, telegram_chat_id, password_hash, status, created_at) VALUES (1, 'Existing', '123', 'old-hash', 'active', '2026-11-22')"))
    command.upgrade(config, 'head')
    assert 'master_email_outbox' in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT version_num FROM alembic_version')) == ScriptDirectory.from_config(config).get_current_head()
        assert connection.execute(text('SELECT email, password_revision, password_hash FROM master_accounts')).one() == (None, 0, 'old-hash')
        # Existing migrations contain legacy metadata differences; inspect only this slice.
        changes = compare_metadata(MigrationContext.configure(connection), Base.metadata)
        assert not [c for c in changes if any('master_email' in str(x) or 'password_revision' in str(x) for x in c)]
    account_id, created = register_telegram(engine, {'text': '/start', 'chat': {'type': 'private', 'id': 456}, 'from': {'id': 456}})
    assert created
    with Session(engine) as db:
        account = db.get(Account, account_id)
        assert account.email is None and account.password_revision == 0
        db.add(EmailProof(token_hash='f' * 64, account_id=account_id, kind='verify', email='test@example.org', password_revision=0, expires_at=NOW + timedelta(minutes=30)))
        db.flush()
        db.add(EmailOutbox(token_hash='f' * 64, body_secret=encrypt_secret('test', get_secret_key()), next_attempt_at=NOW))
        db.commit()
        db.delete(account)
        db.commit()
        assert not list(db.scalars(select(EmailProof)))
        assert not list(db.scalars(select(EmailOutbox)))
        assert db.execute(text('PRAGMA foreign_key_check')).all() == []
    engine.dispose()
    command.downgrade(config, '0019_master')
    command.upgrade(config, 'head')


@pytest.mark.anyio
async def test_worker_runs_mail_even_when_device_processing_fails(monkeypatch):
    from vs_master import worker_main, mail
    main_thread = threading.get_ident()
    observed, sleeps = [], []
    def failed_device(engine):
        raise RuntimeError('private-node-data')
    def email(engine):
        observed.append(threading.get_ident())
        if len(observed) == 1:
            raise RuntimeError('private-mail-data')
    async def sleep(interval):
        sleeps.append(interval)
        if len(sleeps) == 2:
            raise asyncio.CancelledError
    monkeypatch.setattr(worker_main, 'process_pending', failed_device)
    monkeypatch.setattr(mail, 'process_email_outbox', email)
    # Import at call time or alias at module scope are both supported.
    if hasattr(worker_main, 'process_email_outbox'):
        monkeypatch.setattr(worker_main, 'process_email_outbox', email)
    with pytest.raises(asyncio.CancelledError):
        await worker_main.serve(object(), interval=1, sleep=sleep)
    assert len(observed) == 2
    assert all(t != main_thread for t in observed)

