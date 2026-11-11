"""Host-free acceptance tests for the ADR-0035 master subscriber portal."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.accounts import COOKIE as PORTAL_COOKIE
from vs_master.app import create_master_app
from vs_master.auth import COOKIE as ADMIN_COOKIE
from vs_master.bridge import BridgeError
from vs_master.models import (PortalLink, Account, Base, Device, DeviceOp, DeviceSubscription, Node, RuleSet,
                              Setting, Subscription, Tariff, make_engine)
from hashlib import sha256
from vs_router.secrets import decrypt_secret, encrypt_secret

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
    assert me.json()['subscription']['tariff'] == {'name': 'Base', 'device_limit': 8, 'term_days': 30}


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
    amnezia_qr = await client.get(f'/api/portal/devices/{device_id}/export?format=amnezia-qr')
    assert amnezia_qr.status_code == 200, amnezia_qr.text
    assert amnezia_qr.headers['content-type'] == 'image/png'
    assert 'Content-Disposition' not in amnezia_qr.headers
    assert amnezia_qr.content[:4] == bytes([0x89]) + b'PNG'

    invalid = await client.get(f'/api/portal/devices/{device_id}/export?format=txt')
    assert invalid.status_code == 422
    assert invalid.json()['error']['code'] == 'portal.export_format'
    states[('https://n1', f"s{ids['account']}")] = {
        'subscription': {'status': 'active'}, 'devices': [], 'tunnel': None}
    missing = await client.get(f'/api/portal/devices/{device_id}/export')
    assert missing.status_code == 503
    assert missing.json()['error']['code'] == 'portal.export_unavailable'


def awg31_state():
    state = tunnel_state()
    state['tunnel'].update({
        'obfuscation': {'Jc': '8', 'Jmin': '25', 'Jmax': '87', 'S1': '97', 'S2': '60',
                        'S3': '97', 'S4': '97', 'H1': '462728319', 'H2': '1',
                        'H3': '2', 'H4': '3'},
        'header_protection_key': 'hpk-secret', 'random_trailers': True,
        'disable_cookies': True, 'mtu': 1380})
    return state


async def test_mihomo_export_routes_ru_directly_and_carries_awg31(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = awg31_state()
    await login(master_portal)
    response = await client.get(f'/api/portal/devices/{device_id}/export?format=mihomo')
    assert response.status_code == 200, response.text
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['content-type'].startswith('application/yaml')
    assert 'filename="peer-one.yaml"' in response.headers['content-disposition']
    text = response.text
    golden = (Path(__file__).parent / 'golden' / 'master-mihomo-awg31.yaml').read_text(encoding='utf-8')
    assert text == golden
    # Device identity and keys come from the master, the server key from the node.
    assert f'private-key: "{PRIVATE}"' in text
    assert f'preshared-key: "{PRESHARED}"' in text
    assert 'public-key: "server-public"' in text
    assert 'server: "vpn.example"' in text and 'port: 51820' in text
    assert 'ip: "10.66.0.2/32"' in text
    assert 'mtu: 1380' in text
    # AWG 3.1 must be selected explicitly, otherwise mihomo uses the legacy
    # implementation and rejects header protection and random trailers.
    assert 'amnezia-wg-option:' in text and 'version: 3' in text
    assert 'header-protection-key: "hpk-secret"' in text
    assert 'random-trailers: true' in text and 'disable-cookies: true' in text
    assert 'h1: 462728319' in text and 's4: 97' in text
    # Split contract: RU destinations leave through the subscriber's own
    # provider; only the rest enters the tunnel.
    assert 'enhanced-mode: "fake-ip"' in text
    assert '- "GEOIP,RU,DIRECT"' in text
    assert '- "MATCH,PROXY"' in text
    rules = text[text.index('rules:'):]
    assert rules.index('GEOIP,RU,DIRECT') < rules.index('MATCH,PROXY')


async def test_mihomo_export_pins_published_rule_providers(master_portal):
    client, engine, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state()
    with Session(engine) as db:
        db.add(Setting(key='master_public_url', value='https://my.example'))
        db.add(RuleSet(kind='domain', version='ru-2026-11-01', sha256='a' * 64, entries=2,
                       content='example.com\n+.example.net\n', created_at=NOW))
        db.add(RuleSet(kind='ipcidr', version='ru-ips-1', sha256='b' * 64, entries=1,
                       content='5.5.5.0/24\n', created_at=NOW))
        db.commit()
    await login(master_portal)
    response = await client.get(f'/api/portal/devices/{device_id}/export?format=mihomo')
    assert response.status_code == 200, response.text
    text = response.text
    assert 'rule-providers:' in text
    assert 'url: "https://my.example/api/rulesets/domain/ru-2026-11-01.yaml"' in text
    assert 'url: "https://my.example/api/rulesets/ipcidr/ru-ips-1.yaml"' in text
    assert 'behavior: "domain"' in text and 'behavior: "ipcidr"' in text
    rules = text[text.index('rules:'):text.index('dns:')]
    assert rules.index('RULE-SET,ru-domains,DIRECT') < rules.index('GEOIP,RU,DIRECT')
    assert rules.index('RULE-SET,ru-ips,DIRECT') < rules.index('MATCH,PROXY')


async def test_mihomo_export_omits_providers_without_public_url(master_portal):
    client, engine, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state()
    with Session(engine) as db:
        db.add(RuleSet(kind='domain', version='ru-2026-11-01', sha256='a' * 64, entries=1,
                       content='example.com\n', created_at=NOW))
        db.commit()
    await login(master_portal)
    response = await client.get(f'/api/portal/devices/{device_id}/export?format=mihomo')
    assert response.status_code == 200, response.text
    assert 'rule-providers' not in response.text


async def test_stable_cabinet_link_signs_in_repeatedly_and_rotates(master_portal):
    client, engine, _, secret_key, _, _, _, _, ids = master_portal
    await login(master_portal)
    assert (await client.post('/api/portal/link/rotate')).status_code == 204

    with Session(engine) as db:
        row = db.get(PortalLink, ids['account'])
        assert row is not None
        token = decrypt_secret(row.token_secret, secret_key)
        assert row.token_hash == sha256(token.encode()).hexdigest()

    # The stored link keeps working: no single-use proof, no expiry.
    for _ in range(2):
        assert (await client.post('/api/portal/login/link',
                                  json={'token': token})).status_code == 200
    me = await client.get('/api/portal/me')
    assert me.status_code == 200 and me.json()['account']['id'] == ids['account']

    assert (await client.post('/api/portal/link/rotate')).status_code == 204
    with Session(engine) as db:
        rotated = decrypt_secret(db.get(PortalLink, ids['account']).token_secret, secret_key)
    assert rotated != token
    assert (await client.post('/api/portal/login/link',
                              json={'token': token})).status_code == 401
    assert (await client.post('/api/portal/login/link',
                              json={'token': rotated})).status_code == 200


async def test_subscription_link_is_issued_once_serves_yaml_and_is_revocable(master_portal):
    client, engine, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = awg31_state()
    assert (await client.post(f'/api/portal/devices/{device_id}/subscription')).status_code == 401
    await login(master_portal)

    issued = await client.post(f'/api/portal/devices/{device_id}/subscription')
    assert issued.status_code == 201, issued.text
    url = issued.json()['url']
    assert url.startswith('https://master.test/api/portal/sub/')
    # The link is drawn as a QR for phone clients; only the issue response can
    # carry it because the master stores the token hash alone.
    assert issued.json()['qr'].startswith('data:image/png;base64,')
    assert issued.json()['clash_url'] == 'clash://install-config?url=' + url
    token = url.rsplit('/', 1)[-1]
    with Session(engine) as db:
        row = db.get(DeviceSubscription, device_id)
        assert row is not None and row.token_hash != token and len(row.token_hash) == 64

    served = await client.get(f'/api/portal/sub/{token}')
    assert served.status_code == 200, served.text
    assert served.headers['Cache-Control'] == 'no-store'
    assert 'amnezia-wg-option:' in served.text and 'GEOIP,RU,DIRECT' in served.text

    # The link is stable: asking again returns the same token, and the cabinet can
    # redisplay it (and its QR) because the token is stored encrypted as well.
    state = (await client.get(f'/api/portal/devices/{device_id}/subscription')).json()
    assert state['active'] is True and state['last_used_at'] is not None
    assert state['url'] == url and state['qr'].startswith('data:image/png;base64,')

    again = await client.post(f'/api/portal/devices/{device_id}/subscription')
    assert again.status_code == 200 and again.json()['created'] is False
    assert again.json()['url'] == url
    assert (await client.get(f'/api/portal/sub/{token}')).status_code == 200

    rotated = await client.post(f'/api/portal/devices/{device_id}/subscription/rotate')
    assert rotated.status_code == 200 and rotated.json()['created'] is True
    assert rotated.json()['url'] != url
    assert (await client.get(f'/api/portal/sub/{token}')).status_code == 404

    new_token = rotated.json()['url'].rsplit('/', 1)[-1]
    assert (await client.delete(f'/api/portal/devices/{device_id}/subscription')).status_code == 204
    assert (await client.get(f'/api/portal/sub/{new_token}')).status_code == 404


async def test_subscription_link_dies_with_expired_subscription_and_removed_device(master_portal):
    client, engine, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    states[('https://n1', f"s{ids['account']}")] = tunnel_state()
    await login(master_portal)
    token = (await client.post(
        f'/api/portal/devices/{device_id}/subscription')).json()['url'].rsplit('/', 1)[-1]
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription).where(Subscription.account_id == ids['account']))
        assert subscription is not None
        subscription.expires_at = NOW - timedelta(days=1)
        db.commit()
    expired = await client.get(f'/api/portal/sub/{token}')
    assert expired.status_code == 403
    assert expired.json()['error']['code'] == 'portal.subscription_expired'
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription).where(Subscription.account_id == ids['account']))
        assert subscription is not None
        subscription.expires_at = NOW + timedelta(days=30)
        device = db.get(Device, device_id)
        assert device is not None
        device.status = 'removed'
        db.commit()
    gone = await client.get(f'/api/portal/sub/{token}')
    assert gone.status_code == 404
    assert gone.json()['error']['code'] == 'portal.subscription_link_invalid'


async def test_mihomo_export_refuses_awg3_without_header_protection(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    state = awg31_state()
    state['tunnel']['header_protection_key'] = None
    states[('https://n1', f"s{ids['account']}")] = state
    await login(master_portal)
    response = await client.get(f'/api/portal/devices/{device_id}/export?format=mihomo')
    assert response.status_code == 503
    assert response.json()['error']['code'] == 'portal.export_unavailable'
    assert 'hpk-secret' not in response.text


async def test_mihomo_export_plain_wireguard_has_no_awg_block(master_portal):
    client, _, _, _, _, states, _, _, ids = master_portal
    device_id = add_device(master_portal)
    state = tunnel_state()
    state['tunnel']['protocol'] = 'wg'
    states[('https://n1', f"s{ids['account']}")] = state
    await login(master_portal)
    response = await client.get(f'/api/portal/devices/{device_id}/export?format=mihomo')
    assert response.status_code == 200, response.text
    assert 'amnezia-wg-option' not in response.text
    assert 'type: "wireguard"' in response.text



async def test_criterion_8_expired_subscription_blocks_all_mutations_me_works(master_portal):
    client, engine, clock, *_ = master_portal
    active_id = add_device(master_portal, name='active-one')
    inactive_id = add_device(master_portal, status='inactive', name='inactive-one')
    master_portal[5][('https://n1', f"s{master_portal[-1]['account']}")] = tunnel_state()
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
        await client.get(f'/api/portal/devices/{active_id}/export?format=conf'),
    ]
    assert responses[-1].status_code == 403, 'expired account must not retrieve private config'
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
