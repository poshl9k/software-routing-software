"""Portal auth/schema acceptance: independent DB, one-use invites, sessions and audit."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from vs_portal.app import create_app
from vs_portal.auth import COOKIE, LOGIN_WINDOW, TTL
from vs_portal.models import (Account, Audit, Base, Device, Invite, Subscription,
                              Tariff, make_engine)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def portal(monkeypatch):
    now = [datetime(2026, 10, 23, tzinfo=timezone.utc)]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    monkeypatch.setenv('VS_PORTAL_INTERNAL_SECRET', 'test-internal-secret')
    panel_calls = []
    busy = [False]
    state = {'subscription': {'status': 'active'}, 'devices': [],
             'tunnel': {'name': 'vpn', 'protocol': 'awg', 'public_key': 'SERVER',
                        'endpoint': 'vpn.example:51820', 'dns_servers': ['10.0.0.1'],
                        'allowed_ips': ['0.0.0.0/0'], 'listen_port': 51820,
                        'subnet': '10.66.1.0/24', 'keepalive': 25,
                        'obfuscation': {'Jc': '8', 'Jmin': '25', 'Jmax': '87',
                                        'S1': '97', 'S2': '60', 'H1': '462728319', 'H2': '1'}}}

    def panel(request):
        assert request.headers['X-VS-Portal-Secret'] == 'test-internal-secret'
        panel_calls.append((request.method, request.url.path, request.content))
        if request.url.path.endswith('/state'):
            return httpx.Response(200, json=state)
        if busy[0]:
            return httpx.Response(409, json={'error': {'code': 'apply.busy'}})
        if request.url.path.endswith('/device-op'):
            import json
            payload = json.loads(request.content)
            device = {'name': f"portal_{payload['device_id']}", 'public_key': 'CLIENT',
                      'private_key': 'client-private', 'preshared_key': 'client-psk',
                      'allowed_ips': ['10.66.1.2/32']}
            return httpx.Response(200, json={'status': 'applied', 'device': device})
        return httpx.Response(200, json={'status': 'applied'})

    engine = make_engine('sqlite://')
    config = Config(str(Path(__file__).parents[1] / 'alembic-portal' / 'alembic.ini'))
    with engine.begin() as conn:
        config.attributes['connection'] = conn
        command.upgrade(config, 'head')
    with Session(engine) as db:
        db.add(Tariff(id=1, name='Base', device_limit=2, term_days=30,
                      created_at=now[0]))
        db.flush()
        db.add(Subscription(subscriber_name='alice', tariff_id=1,
                            expires_at=now[0] + timedelta(days=30), status='active',
                            updated_at=now[0]))
        db.add(Invite(token='invite', subscriber_name='alice',
                      expires_at=now[0] + timedelta(days=1), created_at=now[0]))
        db.commit()
    app = create_app(engine, clock=lambda: now[0], internal_transport=httpx.MockTransport(panel))
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://portal.test') as client:
        yield client, engine, now, panel_calls, busy, state, app
    engine.dispose()


async def activate(portal):
    client = portal[0]
    result = await client.post('/api/portal/invite/activate', json={'token': 'invite', 'password': 'password123'})
    assert result.status_code == 200, result.text
    result = await client.post('/api/portal/login', json={'username': 'alice', 'password': 'password123'})
    assert result.status_code == 200, result.text
    return result


async def test_criterion_1_seven_tables_constraints_and_utc_migration(portal):
    _, engine, now, *_ = portal
    assert set(inspect(engine).get_table_names()) == set(Base.metadata.tables) | {'alembic_version'}
    with Session(engine) as db:
        invite = db.get(Invite, 'invite')
        assert invite.expires_at.tzinfo == timezone.utc
        assert db.get(Subscription, 'alice').expires_at.tzinfo == timezone.utc
        assert db.get(Tariff, 1).device_limit == 2
    config = Config(str(Path(__file__).parents[1] / 'alembic-portal' / 'alembic.ini'))
    with engine.begin() as conn:
        config.attributes['connection'] = conn
        command.downgrade(config, 'base')
    assert set(inspect(engine).get_table_names()) == {'alembic_version'}


async def test_criterion_1_invite_one_use_revoke_expiry_and_preset_password(portal):
    client, engine, now, *_ = portal
    with Session(engine) as db:
        db.add(Invite(token='revoked', subscriber_name='alice', expires_at=now[0] + timedelta(days=1),
                      used_at=now[0], created_at=now[0]))
        db.add(Invite(token='expired', subscriber_name='alice', expires_at=now[0], created_at=now[0]))
        from argon2 import PasswordHasher, Type
        db.add(Invite(token='preset', subscriber_name='alice',
                      password_hash=PasswordHasher(type=Type.ID).hash('ready-password'),
                      expires_at=now[0] + timedelta(days=1), created_at=now[0]))
        db.commit()
    for token in ('revoked', 'expired'):
        assert (await client.post('/api/portal/invite/activate',
                                  json={'token': token, 'password': 'password123'})).status_code == 400
    assert (await client.post('/api/portal/invite/activate', json={'token': 'invite'})).status_code == 422
    assert (await client.post('/api/portal/invite/activate', json={'token': 'preset'})).status_code == 200
    assert (await client.post('/api/portal/login', json={'username': 'alice',
                                                        'password': 'ready-password'})).status_code == 200
    assert (await client.post('/api/portal/invite/activate', json={'token': 'preset'})).status_code == 400
    with Session(engine) as db:
        assert db.get(Account, 'alice').password_hash.startswith('$argon2id$')
        assert db.get(Invite, 'preset').used_at is not None


async def test_criterion_1_missing_subscriber_cannot_activate(portal):
    client, engine, now, _, _, state, _ = portal
    with Session(engine) as db:
        db.add(Invite(token='orphan', subscriber_name='ghost',
                      expires_at=now[0] + timedelta(days=1), created_at=now[0]))
        db.commit()
    original = state['subscription']
    state['subscription'] = None
    result = await client.post('/api/portal/invite/activate', json={
        'token': 'orphan', 'password': 'password123'})
    assert result.status_code == 404 and result.json()['error']['code'] == 'portal.subscriber_not_found'
    with Session(engine) as db:
        assert db.get(Account, 'ghost') is None
        assert db.get(Invite, 'orphan').used_at is None
    state['subscription'] = original


async def test_criterion_4_nested_errors_origin_and_no_store(portal):
    client = portal[0]
    assert (await client.get('/api/portal/me')).json()['error']['code'] == 'auth.required'
    denied = await client.post('/api/portal/invite/activate', json={'token': 'invite', 'password': 'secret123'},
                               headers={'Origin': 'https://evil.test'})
    assert denied.status_code == 403 and denied.json()['error']['code'] == 'request.cross_origin'
    assert (await client.post('/api/portal/invite/activate', json={'token': 'invite',
                               'password': 'secret123'}, headers={'Sec-Fetch-Site': 'cross-site'})).status_code == 403
    await activate(portal)
    me = await client.get('/api/portal/me')
    assert me.headers['Cache-Control'] == 'no-store'
    assert me.json()['subscription']['tariff']['device_limit'] == 2
    assert (await client.get('/api/setup')).status_code == 404
    assert (await client.get('/internal/portal/subscribers/alice/state')).status_code == 404


async def test_criterion_5_internal_transport_fail_closed_and_nested_errors(portal, monkeypatch):
    from vs_portal.internal import InternalClient
    from vs_router.api.errors import APIError
    import httpx
    seen = []
    def backend(request):
        seen.append(request)
        return httpx.Response(409, json={'error': {'code': 'apply.busy'}})
    internal = InternalClient(transport=httpx.MockTransport(backend))
    with pytest.raises(APIError) as exc:
        internal.device_op('alice', {'op': 'create', 'device_id': 1})
    assert exc.value.code == 'apply.busy' and exc.value.status == 409
    assert seen[0].headers['X-VS-Portal-Secret'] == 'test-internal-secret'
    assert seen[0].url.path == '/internal/portal/subscribers/alice/device-op'
    monkeypatch.delenv('VS_PORTAL_INTERNAL_SECRET')
    monkeypatch.setenv('VS_PORTAL_INTERNAL_SECRET_FILE', '/nonexistent/secret')
    with pytest.raises(APIError) as exc:
        internal.state('alice')
    assert exc.value.status == 503
    monkeypatch.setenv('VS_PORTAL_INTERNAL_URL', 'http://127.0.0.1:8000')
    with pytest.raises(APIError):
        InternalClient()
    monkeypatch.setenv('VS_PORTAL_INTERNAL_URL', 'http://portal-internal.sock')
    assert isinstance(InternalClient().transport, httpx.HTTPTransport)


async def test_criterion_9_login_rate_audit_sessions_reset(portal):
    client, engine, now, *_ = portal
    await activate(portal)
    token = client.cookies.get(COOKIE)
    response = await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'password123'})
    cookie = response.headers['set-cookie'].lower()
    assert all(piece in cookie for piece in ('secure', 'httponly', 'samesite=lax', 'max-age=28800'))
    for _ in range(5):
        assert (await client.post('/api/portal/login', json={
            'username': 'alice', 'password': 'wrong'})).status_code == 401
    assert (await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'password123'})).status_code == 429
    now[0] += timedelta(seconds=LOGIN_WINDOW)
    assert (await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'password123'})).status_code == 200
    with Session(engine) as db:
        db.add(Invite(token='reset', subscriber_name='alice', expires_at=now[0] + timedelta(days=1),
                      created_at=now[0]))
        db.commit()
    previous = client.cookies.get(COOKIE)
    assert (await client.post('/api/portal/invite/activate', json={
        'token': 'reset', 'password': 'new-password'})).status_code == 200
    assert (await client.get('/api/portal/me', headers={'cookie': f'{COOKIE}={previous}'})).status_code == 401
    assert (await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'password123'})).status_code == 401
    assert (await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'new-password'})).status_code == 200
    assert (await client.post('/api/portal/logout')).status_code == 204
    assert (await client.get('/api/portal/me')).status_code == 401
    with Session(engine) as db:
        actions = list(db.scalars(select(Audit.action)))
        assert {'activate', 'login.failure', 'login.success', 'logout'} <= set(actions)
        assert all('password' not in (item.detail or '') for item in db.scalars(select(Audit)))
