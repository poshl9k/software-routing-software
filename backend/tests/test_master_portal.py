"""Host-free acceptance tests for the ADR-0035 master subscriber portal."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.accounts import COOKIE as PORTAL_COOKIE
from vs_master.app import create_master_app
from vs_master.auth import COOKIE as ADMIN_COOKIE
from vs_master.bridge import BridgeError
from vs_master.models import (Account, Base, Device, DeviceOp, Node, Subscription,
                              Tariff, make_engine)
from vs_router.secrets import encrypt_secret

pytestmark = pytest.mark.anyio
NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
PORTAL_PASSWORD = 'subscriber-password'
PRIVATE = 'private-test-material'
PRESHARED = 'preshared-test-material'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def master_portal(monkeypatch):
    clock = [NOW]
    secret_key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', secret_key.decode())
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    app = create_master_app(engine=engine, clock=lambda: clock[0])
    states = {}
    calls = []
    pending_ops = set()

    class FakeBridgeClient:
        def __init__(self, base_url, token):
            self.base_url = base_url
            calls.append(('init', base_url, token))

        def state(self, subscriber):
            calls.append(('state', self.base_url, subscriber))
            result = states[(self.base_url, subscriber)]
            if isinstance(result, Exception):
                raise result
            return result

        def device_op(self, subscriber, payload):
            calls.append(('device_op', self.base_url, subscriber, payload.copy()))
            if payload['op'] in pending_ops:
                return {'status': 'pending'}
            if payload['op'] == 'create':
                return {'status': 'applied', 'device': {
                    'name': 'peer-created', 'public_key': 'client-public',
                    'private_key': PRIVATE, 'preshared_key': PRESHARED,
                    'allowed_ips': ['10.66.0.20/32'], 'tunnel': 'awg0'}}
            return {'status': 'applied'}

    monkeypatch.setattr('vs_master.portal_api.BridgeClient', FakeBridgeClient)
    with Session(engine) as db:
        tariff = Tariff(name='Base', device_limit=8, term_days=30, created_at=NOW)
        account = Account(display_name='Alice', telegram_chat_id='100',
                          password_hash=app.state.portal_auth.hasher.hash(PORTAL_PASSWORD),
                          status='active', created_at=NOW)
        node1 = Node(name='n1', bridge_url='https://n1',
                     bridge_token=encrypt_secret('token-one', secret_key), capacity=3,
                     enabled=True, state='ok', active_peers=0, created_at=NOW)
        node2 = Node(name='n2', bridge_url='https://n2',
                     bridge_token=encrypt_secret('token-two', secret_key), capacity=5,
                     enabled=True, state='ok', active_peers=0, created_at=NOW)
        db.add_all([tariff, account, node1, node2])
        db.flush()
        db.add(Subscription(account_id=account.id, tariff_id=tariff.id,
                            expires_at=NOW + timedelta(days=30), status='active',
                            updated_at=NOW))
        db.commit()
        ids = {'account': account.id, 'tariff': tariff.id,
               'node1': node1.id, 'node2': node2.id}
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url='https://master.test') as client:
        yield client, engine, clock, secret_key, app, states, calls, pending_ops, ids
    engine.dispose()


async def login(rig):
    response = await rig[0].post('/api/portal/login', json={
        'username': 'Alice', 'password': PORTAL_PASSWORD})
    assert response.status_code == 200, response.text
    return response


def tunnel_state(*, devices=None):
    return {'subscription': {'status': 'active'}, 'devices': devices or [],
            'tunnel': {'name': 'awg0', 'protocol': 'awg', 'public_key': 'server-public',
                       'endpoint': 'vpn.example:51820', 'dns_servers': ['10.0.0.1'],
                       'allowed_ips': ['0.0.0.0/0'], 'listen_port': 51820,
                       'subnet': '10.66.0.0/24', 'keepalive': 25,
                       'obfuscation': {'Jc': '8', 'Jmin': '25', 'Jmax': '87',
                                       'S1': '97', 'S2': '60',
                                       'H1': '462728319', 'H2': '1'}}}


def add_device(rig, *, node_key='node1', status='active', name='peer-one', label='Phone'):
    _, engine, _, key, _, _, _, _, ids = rig
    with Session(engine) as db:
        device = Device(account_id=ids['account'], node_id=ids[node_key],
                        node_subscriber=f"s{ids['account']}", name=name, label=label,
                        public_key='client-public', private_key=encrypt_secret(PRIVATE, key),
                        preshared_key=encrypt_secret(PRESHARED, key),
                        allowed_ips=['10.66.0.2/32'], status=status,
                        tunnel_name='awg0', created_at=NOW)
        db.add(device)
        db.commit()
        return device.id


async def test_criterion_1_login_valid_invalid_and_ambiguous(master_portal):
    client, engine, *_ = master_portal
    invalid = await client.post('/api/portal/login', json={
        'username': 'Alice', 'password': 'wrong'})
    assert invalid.status_code == 401
    assert invalid.json()['error']['code'] == 'auth.invalid_credentials'
    assert (await login(master_portal)).cookies.get(PORTAL_COOKIE)
    with Session(engine) as db:
        db.add(Account(display_name='Alice', telegram_chat_id='101',
                       password_hash=master_portal[4].state.portal_auth.hasher.hash(PORTAL_PASSWORD),
                       status='active', created_at=NOW))
        db.commit()
    ambiguous = await client.post('/api/portal/login', json={
        'username': 'Alice', 'password': PORTAL_PASSWORD})
    assert ambiguous.status_code == 409
    assert ambiguous.json()['error']['code'] == 'portal.name_ambiguous'


async def test_criterion_2_cookie_separation_and_me_expired_state(master_portal):
    client, engine, clock, *_ = master_portal
    assert (await client.post('/api/admin/setup', json={
        'password': 'administrator-password'})).status_code == 201
    assert (await client.post('/api/admin/login', json={
        'username': 'admin', 'password': 'administrator-password'})).status_code == 200
    await login(master_portal)
    assert client.cookies.get(ADMIN_COOKIE) and client.cookies.get(PORTAL_COOKIE)
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        subscription.expires_at = clock[0]
        db.commit()
    me = await client.get('/api/portal/me')
    assert me.status_code == 200
    assert me.json()['account'] == {'id': master_portal[-1]['account'],
                                    'display_name': 'Alice'}
    assert me.json()['subscription']['status'] == 'expired'
    assert me.json()['subscription']['tariff'] == {'name': 'Base'}


async def test_criterion_3_list_merges_node_state(master_portal):
    client, _, _, _, _, states, calls, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state(devices=[{
        'name': 'peer-one', 'applied': True, 'last_handshake': 1234}])
    await login(master_portal)
    response = await client.get('/api/portal/devices')
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['devices'][0] == {
        'id': device_id, 'name': 'peer-one', 'label': 'Phone',
        'public_key': 'client-public', 'allowed_ips': ['10.66.0.2/32'],
        'status': 'active', 'last_handshake': 1234, 'applied': True}
    assert body['subscription'] == {'status': 'active'}
    assert body['tunnel']['name'] == 'awg0'
    assert ('state', 'https://n1', f"s{ids['account']}") in calls


async def test_criterion_4_bridge_failure_makes_full_list_503(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = BridgeError(503, 'node.unreachable')
    await login(master_portal)
    response = await client.get('/api/portal/devices')
    assert response.status_code == 503
    assert response.json()['error']['code'] == 'portal.internal_unavailable'
    assert 'devices' not in response.json()


async def test_criterion_5_create_picks_freest_ok_node_and_refuses_none(master_portal):
    client, engine, _, _, _, states, calls, _, ids = master_portal
    states[('https://n2', f"s{ids['account']}")] = tunnel_state()
    await login(master_portal)
    created = await client.post('/api/portal/devices', json={'label': 'Laptop'})
    assert created.status_code == 200, created.text
    with Session(engine) as db:
        device = db.get(Device, created.json()['device_id'])
        assert device.node_id == ids['node2'] and device.status == 'active'
        assert device.name == 'peer-created'
        for node in db.scalars(select(Node)):
            node.state = 'down'
        db.commit()
    assert any(call[:3] == ('device_op', 'https://n2', f"s{ids['account']}") for call in calls)
    denied = await client.post('/api/portal/devices', json={'label': 'Tablet'})
    assert denied.status_code == 409
    assert denied.json()['error']['code'] == 'master.no_node_available'


async def test_criterion_6_queued_mutations_and_state_guards(master_portal):
    client, engine, _, _, _, _, _, pending_ops, _ = master_portal
    delete_id = add_device(master_portal, name='delete-me')
    deactivate_id = add_device(master_portal, name='deactivate-me', label='Laptop')
    activate_id = add_device(master_portal, status='inactive', name='activate-me', label='Tablet')
    await login(master_portal)
    pending_ops.add('delete')
    deleted = await client.delete(f'/api/portal/devices/{delete_id}')
    assert deleted.status_code == 202 and deleted.json()['status'] == 'pending'
    pending_ops.clear()
    deactivated = await client.post(f'/api/portal/devices/{deactivate_id}/deactivate')
    activated = await client.post(f'/api/portal/devices/{activate_id}/activate')
    assert deactivated.status_code == activated.status_code == 200
    assert (await client.post(f'/api/portal/devices/{deactivate_id}/deactivate')).status_code == 409
    assert (await client.post(f'/api/portal/devices/{activate_id}/activate')).status_code == 409
    assert (await client.post(f'/api/portal/devices/{delete_id}/activate')).json()[
        'error']['code'] == 'portal.operation_pending'
    with Session(engine) as db:
        assert {'delete', 'deactivate', 'activate'} <= {
            op.op for op in db.scalars(select(DeviceOp))}


async def test_criterion_7_conf_qr_amnezia_and_export_errors(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state()
    await login(master_portal)
    conf = await client.get(f'/api/portal/devices/{device_id}/export?format=conf')
    assert conf.status_code == 200, conf.text
    assert 'PrivateKey = ' + PRIVATE in conf.text
    assert 'PresharedKey = ' + PRESHARED in conf.text
    assert 'PublicKey = server-public' in conf.text
    assert conf.headers['Cache-Control'] == 'no-store'
    qr = await client.get(f'/api/portal/devices/{device_id}/export?format=qr')
    assert qr.status_code == 200 and qr.headers['content-type'] == 'image/png'
    amnezia = await client.get(f'/api/portal/devices/{device_id}/export?format=amnezia')
    assert amnezia.status_code == 200 and amnezia.text.startswith('vpn://')
    invalid = await client.get(f'/api/portal/devices/{device_id}/export?format=txt')
    assert invalid.status_code == 422
    assert invalid.json()['error']['code'] == 'portal.export_format'
    states[('https://n1', f"s{ids['account']}")] = {
        'subscription': {'status': 'active'}, 'devices': [], 'tunnel': None}
    missing = await client.get(f'/api/portal/devices/{device_id}/export')
    assert missing.status_code == 503
    assert missing.json()['error']['code'] == 'portal.export_unavailable'


async def test_criterion_8_expired_subscription_blocks_all_mutations_me_works(master_portal):
    client, engine, clock, *_ = master_portal
    active_id = add_device(master_portal, name='active-one')
    inactive_id = add_device(master_portal, status='inactive', name='inactive-one')
    await login(master_portal)
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        subscription.expires_at = clock[0]
        db.commit()
    responses = [
        await client.post('/api/portal/devices', json={'label': 'New'}),
        await client.delete(f'/api/portal/devices/{active_id}'),
        await client.post(f'/api/portal/devices/{inactive_id}/activate'),
        await client.post(f'/api/portal/devices/{active_id}/deactivate'),
    ]
    assert all(response.status_code == 403 for response in responses)
    assert all(response.json()['error']['code'] == 'portal.subscription_expired'
               for response in responses)
    assert (await client.get('/api/portal/me')).status_code == 200


async def test_criterion_9_json_gets_never_expose_secret_material(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state(devices=[{
        'name': 'peer-one', 'applied': True, 'last_handshake': None}])
    await login(master_portal)
    responses = [await client.get('/api/portal/me'),
                 await client.get('/api/portal/devices'),
                 await client.get('/health')]
    for response in responses:
        assert response.status_code == 200
        assert PRIVATE not in response.text and PRESHARED not in response.text
        assert 'ciphertext' not in response.text
