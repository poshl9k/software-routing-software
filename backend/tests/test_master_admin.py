"""Master admin app contract: auth, registry, subscribers, secrets and audit."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.app import create_master_app
from vs_master.auth import ADMIN_PASSWORD_KEY, COOKIE, LOGIN_WINDOW, TTL
from vs_master.bridge import BridgeError
from vs_master.models import (Account, Audit, Base, Device, Node, Setting, Subscription,
                              Tariff, make_engine)
from vs_router.secrets import decrypt_secret, encrypt_secret

pytestmark = pytest.mark.anyio
PASSWORD = 'master-test-password'
NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def master(monkeypatch):
    clock = [NOW]
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    app = create_master_app(engine=engine, clock=lambda: clock[0])
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url='https://master.test') as client:
        yield client, engine, clock, key, app
    engine.dispose()


async def initialize(client):
    response = await client.post('/api/admin/setup', json={'password': PASSWORD})
    assert response.status_code == 201, response.text
    response = await client.post('/api/admin/login', json={
        'username': 'admin', 'password': PASSWORD})
    assert response.status_code == 200, response.text
    return response


async def create_tariff(client, name='Base', *, limit=3, days=30, price=9.99):
    response = await client.post('/api/master-admin/tariffs', json={
        'name': name, 'device_limit': limit, 'term_days': days, 'price_amount': price})
    assert response.status_code == 201, response.text
    return response.json()


async def create_node(client, name='rg2', url='https://rg2.example/internal', capacity=20):
    response = await client.post('/api/master-admin/nodes', json={
        'name': name, 'bridge_url': url, 'capacity': capacity})
    assert response.status_code == 201, response.text
    return response


async def test_criterion_1_auth_setup_rate_limit_sessions_cookie_and_audit(master):
    client, engine, clock, _, app = master
    assert app.state.engine is engine
    assert (await client.get('/api/admin/me')).status_code == 401
    setup = await client.post('/api/admin/setup', json={'password': PASSWORD})
    assert setup.status_code == 201 and setup.json() == {'username': 'admin'}
    assert (await client.post('/api/admin/setup', json={'password': PASSWORD})).status_code == 409
    with Session(engine) as db:
        stored = db.get(Setting, ADMIN_PASSWORD_KEY)
        assert stored.value.startswith('$argon2id$') and PASSWORD not in stored.value

    logged = await client.post('/api/admin/login', json={'password': PASSWORD})
    assert logged.status_code == 200
    cookie = logged.headers['set-cookie'].lower()
    assert all(item in cookie for item in (
        COOKIE, 'secure', 'httponly', 'samesite=lax', 'max-age=28800'))
    assert (await client.get('/api/admin/me')).json() == {'username': 'admin'}
    assert (await client.post('/api/admin/logout')).status_code == 204
    assert (await client.get('/api/admin/me')).status_code == 401

    for _ in range(5):
        result = await client.post('/api/admin/login', json={
            'username': 'admin', 'password': 'wrong-password'})
        assert result.status_code == 401
    limited = await client.post('/api/admin/login', json={
        'username': 'admin', 'password': PASSWORD})
    assert limited.status_code == 429
    assert limited.json()['error']['code'] == 'auth.rate_limited'
    clock[0] += timedelta(seconds=LOGIN_WINDOW)
    assert (await client.post('/api/admin/login', json={
        'username': 'admin', 'password': PASSWORD})).status_code == 200
    clock[0] += timedelta(seconds=TTL)
    assert (await client.get('/api/admin/me')).status_code == 401

    with Session(engine) as db:
        rows = list(db.scalars(select(Audit)))
        assert {'admin.setup', 'login.success', 'login.failure', 'logout'} <= {
            row.action for row in rows}
        assert all(row.actor == 'admin' for row in rows)
        assert all(PASSWORD not in (row.detail or '') and 'wrong-password' not in (row.detail or '')
                   for row in rows)


async def test_criterion_2_tariff_crud_duplicate_and_in_use(master):
    client, engine, *_ = master
    await initialize(client)
    tariff = await create_tariff(client)
    url = f"/api/master-admin/tariffs/{tariff['id']}"
    assert (await client.get('/api/master-admin/tariffs')).json() == [tariff]
    assert (await client.get(url)).json() == tariff
    duplicate = await client.post('/api/master-admin/tariffs', json={
        'name': 'Base', 'device_limit': 1, 'term_days': 1})
    assert duplicate.status_code == 409
    assert duplicate.json()['error']['code'] == 'master.tariff_exists'
    assert (await client.patch(url, json={'device_limit': None})).status_code == 422
    patched = await client.patch(url, json={'name': 'Renamed', 'price_amount': None})
    assert patched.status_code == 200 and patched.json()['price_amount'] is None
    replaced = await client.put(url, json={
        'name': 'Final', 'device_limit': 7, 'term_days': 90, 'price_amount': 20})
    assert replaced.status_code == 200 and replaced.json()['term_days'] == 90

    with Session(engine) as db:
        account = Account(display_name='Alice', telegram_chat_id='100', password_hash='x')
        db.add(account)
        db.flush()
        db.add(Subscription(account_id=account.id, tariff_id=tariff['id'],
                            expires_at=NOW + timedelta(days=30), status='active', updated_at=NOW))
        db.commit()
    in_use = await client.delete(url)
    assert in_use.status_code == 409
    assert in_use.json()['error']['code'] == 'master.tariff_in_use'

    spare = await create_tariff(client, 'Spare')
    spare_url = f"/api/master-admin/tariffs/{spare['id']}"
    assert (await client.delete(spare_url)).status_code == 204
    assert (await client.get(spare_url)).status_code == 404
    with Session(engine) as db:
        actions = {row.action for row in db.scalars(select(Audit))}
        assert {'tariff.create', 'tariff.update', 'tariff.delete'} <= actions


async def test_criterion_3_nodes_token_once_safe_get_duplicate_patch_and_in_use(master):
    client, engine, _, key, _ = master
    await initialize(client)
    created = await create_node(client)
    data = created.json()
    token = data.pop('token')
    assert len(token) >= 43 and created.text.count(token) == 1
    safe_keys = {'id', 'name', 'bridge_url', 'capacity', 'enabled', 'state',
                 'active_peers', 'last_seen'}
    assert set(data) == safe_keys
    with Session(engine) as db:
        row = db.get(Node, data['id'])
        assert decrypt_secret(row.bridge_token, key) == token
        assert row.bridge_token.ciphertext != token

    listed = await client.get('/api/master-admin/nodes')
    assert listed.status_code == 200 and set(listed.json()[0]) == safe_keys
    assert token not in listed.text and 'ciphertext' not in listed.text
    duplicate = await client.post('/api/master-admin/nodes', json={
        'name': 'rg2', 'bridge_url': 'https://duplicate.example', 'capacity': 1})
    assert duplicate.status_code == 409
    assert duplicate.json()['error']['code'] == 'master.node_exists'
    assert (await client.post('/api/master-admin/nodes', json={
        'name': 'bad', 'bridge_url': 'ftp://bad.example', 'capacity': 1})).status_code == 422
    assert (await client.patch(f"/api/master-admin/nodes/{data['id']}",
                               json={'capacity': None})).status_code == 422
    patched = await client.patch(f"/api/master-admin/nodes/{data['id']}", json={
        'capacity': 30, 'bridge_url': 'http://rg2.internal', 'enabled': False})
    assert patched.status_code == 200
    assert (patched.json()['capacity'], patched.json()['enabled']) == (30, False)

    with Session(engine) as db:
        account = Account(display_name='Alice', telegram_chat_id='100', password_hash='x')
        db.add(account)
        db.flush()
        db.add(Device(account_id=account.id, node_id=data['id'], node_subscriber='alice',
                      label='Phone', status='inactive', allowed_ips=[]))
        db.commit()
    blocked = await client.delete(f"/api/master-admin/nodes/{data['id']}")
    assert blocked.status_code == 409
    assert blocked.json()['error']['code'] == 'master.node_in_use'
    spare = (await create_node(client, 'rg3')).json()
    spare_token = spare.pop('token')
    assert (await client.delete(f"/api/master-admin/nodes/{spare['id']}")).status_code == 204
    with Session(engine) as db:
        actions = {row.action for row in db.scalars(select(Audit))}
        assert {'node.create', 'node.update', 'node.delete'} <= actions
        assert all(token not in (row.detail or '') and spare_token not in (row.detail or '')
                   for row in db.scalars(select(Audit)))


async def test_criterion_4_rotation_current_auth_success_and_failures_are_atomic(master, monkeypatch):
    client, engine, _, key, _ = master
    await initialize(client)
    created = await create_node(client)
    node = created.json()
    onboarding_token = node['token']
    node_id = node['id']
    calls = []

    class SuccessfulBridge:
        def __init__(self, base_url, token):
            calls.append(('init', base_url, token))

        def rotate(self, new_token):
            calls.append(('rotate', new_token))
            return {'rotated': True}

    monkeypatch.setattr('vs_master.admin_api.BridgeClient', SuccessfulBridge)
    result = await client.post(f'/api/master-admin/nodes/{node_id}/rotate-token')
    assert result.status_code == 200 and result.json() == {'rotated': True}
    assert calls[0] == ('init', 'https://rg2.example/internal', onboarding_token)
    proposed = calls[1][1]
    assert proposed != onboarding_token
    with Session(engine) as db:
        successful_ciphertext = db.get(Node, node_id).bridge_token.ciphertext
        assert decrypt_secret(db.get(Node, node_id).bridge_token, key) == proposed

    class FailedBridge:
        error = BridgeError(403, 'node.auth_failed')

        def __init__(self, base_url, token):
            assert token == proposed

        def rotate(self, new_token):
            raise self.error

    monkeypatch.setattr('vs_master.admin_api.BridgeClient', FailedBridge)
    revoked = await client.post(f'/api/master-admin/nodes/{node_id}/rotate-token')
    assert revoked.status_code == 409
    assert revoked.json()['error']['code'] == 'master.node_token_revoked'
    with Session(engine) as db:
        assert db.get(Node, node_id).bridge_token.ciphertext == successful_ciphertext

    FailedBridge.error = BridgeError(503, 'node.unreachable')
    unreachable = await client.post(f'/api/master-admin/nodes/{node_id}/rotate-token')
    assert unreachable.status_code == 503
    assert unreachable.json()['error']['code'] == 'node.unreachable'
    with Session(engine) as db:
        assert db.get(Node, node_id).bridge_token.ciphertext == successful_ciphertext
        rotation_audits = list(db.scalars(select(Audit).where(
            Audit.action == 'node.rotate_token')))
        assert len(rotation_audits) == 1
        assert all(onboarding_token not in (row.detail or '') and proposed not in (row.detail or '')
                   for row in db.scalars(select(Audit)))


async def test_criterion_5_subscribers_hide_keys_and_subscription_create_renew_update(master):
    client, engine, _, key, _ = master
    await initialize(client)
    node_response = await create_node(client)
    node_payload = node_response.json()
    onboarding_token = node_payload['token']
    base = await create_tariff(client, 'Base', days=30)
    premium = await create_tariff(client, 'Premium', days=90)
    private = 'private-secret-material'
    preshared = 'preshared-secret-material'
    public = 'public-key-material'
    with Session(engine) as db:
        account = Account(display_name='Alice', telegram_chat_id='100',
                          password_hash='subscriber-password-hash', status='active', created_at=NOW)
        db.add(account)
        db.flush()
        db.add(Device(account_id=account.id, node_id=node_payload['id'], node_subscriber='alice',
                      name='peer-alice', label='Phone', public_key=public,
                      private_key=encrypt_secret(private, key),
                      preshared_key=encrypt_secret(preshared, key),
                      allowed_ips=['10.66.0.2/32'], status='active', created_at=NOW))
        db.commit()
        account_id = account.id

    collection = await client.get('/api/master-admin/subscribers')
    detail = await client.get(f'/api/master-admin/subscribers/{account_id}')
    assert collection.status_code == detail.status_code == 200
    assert collection.json()[0]['subscription'] is None
    device = detail.json()['devices'][0]
    assert device == {'id': device['id'], 'label': 'Phone', 'name': 'peer-alice',
                      'node_name': 'rg2', 'status': 'active',
                      'allowed_ips': ['10.66.0.2/32']}
    for response in (collection, detail, await client.get('/api/master-admin/nodes')):
        assert onboarding_token not in response.text
        assert 'ciphertext' not in response.text
        assert all(secret not in response.text for secret in (private, preshared, public,
                                                               'subscriber-password-hash'))
    missing = await client.get('/api/master-admin/subscribers/999')
    assert missing.status_code == 404
    assert missing.json()['error']['code'] == 'master.subscriber_not_found'

    url = f'/api/master-admin/subscribers/{account_id}/subscription'
    invalid = await client.put(url, json={'tariff_id': base['id']})
    assert invalid.status_code == 422
    invalid = await client.put(url, json={
        'tariff_id': base['id'], 'days': 1, 'expires_at': NOW.isoformat()})
    assert invalid.status_code == 422
    created = await client.put(url, json={'tariff_id': base['id'], 'days': 30})
    assert created.status_code == 200
    assert datetime.fromisoformat(created.json()['expires_at']) == NOW + timedelta(days=30)

    with Session(engine) as db:
        prior = db.scalar(select(Subscription).where(
            Subscription.account_id == account_id)).expires_at
    renewed = await client.put(url, json={'tariff_id': premium['id'], 'days': 5})
    assert renewed.status_code == 200
    assert renewed.json()['tariff_name'] == 'Premium'
    assert datetime.fromisoformat(renewed.json()['expires_at']) == prior + timedelta(days=5)
    explicit = NOW + timedelta(days=400)
    updated = await client.put(url, json={
        'tariff_id': base['id'], 'expires_at': explicit.isoformat()})
    assert updated.status_code == 200
    assert datetime.fromisoformat(updated.json()['expires_at']) == explicit
    with Session(engine) as db:
        subscriptions = list(db.scalars(select(Subscription).where(
            Subscription.account_id == account_id)))
        assert len(subscriptions) == 1
        actions = {row.action for row in db.scalars(select(Audit))}
        assert {'subscription.create', 'subscription.renew', 'subscription.update'} <= actions
        details = [row.detail or '' for row in db.scalars(select(Audit))]
        assert all(secret not in detail for detail in details
                   for secret in (onboarding_token, private, preshared, public,
                                  'subscriber-password-hash', PASSWORD))
