import asyncio
import socket
from contextlib import suppress
from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from httpx import AsyncClient, ASGITransport
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from vs_router.app import create_app
from vs_router.api.auth import COOKIE, TTL, LOGIN_WINDOW
from vs_router.db import ConfigurationRow, UserRow, save_version
from vs_router.schema import ConfigurationVersion
from vs_router.secrets import encrypt_secret
CREDS = {'username': 'admin', 'password': 'correct-password'}

@pytest.fixture
async def api(tmp_path):
    url = f"sqlite:///{tmp_path / 'api.db'}"
    config = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    config.set_main_option('sqlalchemy.url', url)
    command.upgrade(config, 'head')
    engine = create_engine(url, connect_args={'check_same_thread': False})
    now = [100.0]
    app = create_app(engine, clock=lambda: now[0])
    # Restricted sandboxes may allow socketpair() but forbid send(): asyncio's
    # thread-safe wakeup silently fails. A timer keeps real worker callbacks
    # moving without mocking FastAPI, SQLAlchemy or the thread pool.
    wakeup = None
    left, right = socket.socketpair()
    try:
        left.send(b"x")
    except PermissionError:
        async def tick():
            while True:
                await asyncio.sleep(0.01)
        wakeup = asyncio.create_task(tick())
    finally:
        left.close()
        right.close()
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://router.test') as client:
        yield (client, engine, now)
    if wakeup is not None:
        wakeup.cancel()
        with suppress(asyncio.CancelledError):
            await wakeup
    engine.dispose()

async def sign_in(client):
    assert (await client.post('/api/setup', json=CREDS)).status_code == 201
    response = await client.post('/api/auth/login', json=CREDS)
    assert response.status_code == 200
    return response

async def test_setup_login_logout_expiry(api):
    client, engine, now = api
    assert (await client.get('/api/auth/me')).status_code == 401
    cookie = (await sign_in(client)).headers['set-cookie'].lower()
    assert all((part in cookie for part in ('httponly', 'secure', 'samesite=strict', 'max-age=28800')))
    assert (await client.post('/api/setup', json=CREDS)).status_code == 409
    assert (await client.get('/api/auth/me')).json()['role'] == 'admin'
    with Session(engine) as db:
        assert db.scalar(select(UserRow)).password_hash.startswith('$argon2id$')
    old_token = client.cookies.get(COOKIE)
    assert (await client.post('/api/auth/logout')).status_code == 204
    assert (await client.get('/api/auth/me', headers={'cookie': f'{COOKIE}={old_token}'})).status_code == 401
    await client.post('/api/auth/login', json=CREDS)
    now[0] += TTL
    assert (await client.get('/api/auth/me')).status_code == 401

async def test_rate_limit(api):
    client, _, now = api
    await client.post('/api/setup', json=CREDS)
    for i in range(5):
        assert (await client.post('/api/auth/login', json={'username': f'unknown{i}', 'password': 'x'})).status_code == 401
    assert (await client.post('/api/auth/login', json=CREDS)).status_code == 429
    now[0] += LOGIN_WINDOW
    assert (await client.post('/api/auth/login', json=CREDS)).status_code == 200


async def test_keygen_endpoints(api):
    import base64
    client = api[0]
    assert (await client.post('/api/keygen/tunnel', json={'protocol': 'wg'})).status_code == 401
    await sign_in(client)
    wg = (await client.post('/api/keygen/tunnel', json={'protocol': 'wg'})).json()
    assert set(wg) == {'private_key', 'public_key'}
    for value in wg.values():
        assert len(value) == 44 and len(base64.b64decode(value, validate=True)) == 32
    awg = (await client.post('/api/keygen/tunnel', json={'protocol': 'awg'})).json()
    obf = awg['obfuscation']
    assert set(obf) == {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4'}
    assert all(type(v) is int for v in obf.values())
    assert 3 <= obf['Jc'] <= 10 and 30 <= obf['Jmin'] < obf['Jmax'] <= 120
    assert 10 <= obf['S1'] <= 30 and 80 <= obf['S2'] <= 120
    assert len({obf[f'H{i}'] for i in range(1, 5)}) == 4
    assert all(5 <= obf[f'H{i}'] <= 2_147_483_647 for i in range(1, 5))
    psk = (await client.post('/api/keygen/peer', json={})).json()['preshared_key']
    assert len(psk) == 44 and len(base64.b64decode(psk, validate=True)) == 32
ROUTES = [('get', '/api/versions', None), ('get', '/api/versions/1', None), ('get', '/api/draft/tproxy/preview', None), ('get', '/api/apply/status', None), ('get', '/api/backup/export', None), ('get', '/api/diff/1/2', None), ('post', '/api/draft', {}), ('put', '/api/draft', {}), ('delete', '/api/draft', None), ('post', '/api/draft/validate', None), ('post', '/api/apply', {'version_id': 1}), ('post', '/api/confirm', {'version_id': 1}), ('post', '/api/rollback', {}), ('post', '/api/backup/export', {'include_secrets': True, 'password': 'example-password'}), ('post', '/api/backup/restore', {'schema_version': 1, 'versions': []})]

@pytest.mark.parametrize('method,path,body', ROUTES)
async def test_auth_required(api, method, path, body):
    response = await api[0].request(method, path, json=body)
    assert response.status_code == 401
    assert set(response.json()) == {'code', 'message', 'details'}

async def test_operator_read_only(api):
    client, engine, _ = api
    await sign_in(client)
    await client.post('/api/draft', json={})
    with Session(engine) as db:
        db.scalar(select(UserRow)).role = 'operator'
        db.commit()
    assert (await client.get('/api/versions')).status_code == 200
    assert (await client.get('/api/draft/tproxy/preview')).status_code == 403
    assert (await client.get('/api/apply/status')).status_code == 403
    assert (await client.get('/api/backup/export')).status_code == 403
    for method, path, data in ROUTES:
        if method != 'get':
            assert (await client.request(method, path, json=data)).status_code == 403


async def test_apply_status_reads_agent_marker_without_db_fallback(api, monkeypatch):
    from vs_router.api import versions as routes
    client, _, _ = api
    await sign_in(client)
    calls = []
    marker = {'version_id': 2, 'status': 'pending', 'deadline': 1800000000,
              'applied_at': 1799999800, 'phases': {'nftables': 'applied'}}
    state: dict[str, dict | None] = {'result': marker}
    monkeypatch.setattr(routes, 'agent_call', lambda method, body:
                        calls.append((method, body.model_dump())) or state['result'])
    response = await client.get('/api/apply/status')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == marker
    assert calls == [('status', {})]
    state['result'] = None
    assert (await client.get('/api/apply/status')).json() is None

async def test_tproxy_draft_roundtrip_and_enable_rejected(api):
    client, _, _ = api
    await sign_in(client)
    response = await client.post('/api/draft', json={})
    assert response.status_code == 201
    config = response.json()['configuration']
    assert config['tproxy']['enabled'] is False
    config['interfaces'] = [{'name': 'eth1', 'zone': 'lan'}]
    config['tproxy']['ingress_interfaces'] = ['eth1']
    config['tproxy']['rules'] = [{'name': 'site', 'domain_suffix': ['example.org'], 'action': 'block'}]
    config['tproxy']['update_schedule']['mode'] = 'window'
    response = await client.put('/api/draft', json=config)
    assert response.status_code == 200
    saved = response.json()['configuration']['tproxy']
    assert saved['ingress_interfaces'] == ['eth1']
    assert saved['rules'][0]['action'] == 'block'
    assert saved['update_schedule']['mode'] == 'window'
    config['tproxy']['enabled'] = True
    response = await client.put('/api/draft', json=config)
    assert response.status_code == 422
    assert (await client.get('/api/versions')).json()[0]['configuration']['tproxy'] == saved


async def test_tproxy_preview_uses_saved_draft_without_side_effects(api):
    from vs_router.generators.singbox import generate_singbox
    client, _, _ = api
    await sign_in(client)
    assert (await client.get('/api/draft/tproxy/preview')).status_code == 404
    created = await client.post('/api/draft', json={'tproxy': {'rules': [
        {'name': 'blocked', 'domain_suffix': ['example.org'], 'action': 'block'},
    ]}})
    assert created.status_code == 201
    preview = await client.get('/api/draft/tproxy/preview')
    assert preview.status_code == 200
    assert preview.headers['cache-control'] == 'no-store'
    assert preview.json() == {
        'version_id': created.json()['id'],
        'singbox': generate_singbox(ConfigurationVersion.model_validate(created.json())),
    }
    assert 'private_key' not in preview.text and 'ciphertext' not in preview.text
    assert (await client.request('GET', '/api/draft/tproxy/preview', json={
        'rules': [{'name': 'override', 'action': 'direct'}],
    })).json() == preview.json()
    assert (await client.get('/api/versions')).json() == [created.json()]


async def test_versions_crud_diff_and_persistence(api):
    client, engine, _ = api
    await sign_in(client)
    with Session(engine) as db:
        save_version(db, ConfigurationVersion(id=1, status='confirmed', configuration={'panel_port': 8443}))
        db.commit()
    response = await client.post('/api/draft')
    assert response.status_code == 201
    assert response.json()['configuration']['panel_port'] == 8443
    assert (await client.post('/api/draft')).status_code == 409
    assert (await client.put('/api/draft', json={'panel_port': 9443})).status_code == 200
    assert (await client.get('/api/versions/2')).json()['configuration']['panel_port'] == 9443
    assert [v['id'] for v in (await client.get('/api/versions')).json()] == [2, 1]
    assert (await client.get('/api/diff/1/2')).json() == [{'op': 'replace', 'path': '/panel_port', 'before': 8443, 'after': 9443}]
    assert (await client.get('/api/diff/2/2')).json() == []
    assert (await client.get('/api/versions/999')).status_code == 404
    assert (await client.get('/api/diff/1/999')).status_code == 404
    assert (await client.get('/api/versions/0')).status_code == 422
    async with AsyncClient(transport=ASGITransport(app=create_app(engine)), base_url='https://router.test') as other:
        assert (await other.get('/api/versions')).status_code == 401
        await other.post('/api/auth/login', json=CREDS)
        assert (await other.get('/api/versions/2')).json()['status'] == 'draft'
    assert (await client.delete('/api/draft')).status_code == 204
    assert (await client.delete('/api/draft')).status_code == 404
    assert (await client.put('/api/draft', json={})).status_code == 404
    assert (await client.post('/api/draft/validate')).status_code == 404
    assert (await client.get('/api/versions/1')).json()['status'] == 'confirmed'

async def test_validation_and_generators(api, monkeypatch):
    from vs_router.api import configuration
    client, _, _ = api
    await sign_in(client)
    await client.post('/api/draft', json={})
    assert (await client.post('/api/draft/validate')).json() == {'valid': True, 'errors': [], 'warnings': []}
    invalid = {'interfaces': [{'name': 'eth0', 'zone': 'router'}]}
    assert (await client.put('/api/draft', json=invalid)).status_code == 422
    assert not (await client.post('/api/draft/validate', json=invalid)).json()['valid']
    called = []

    def failing(version):
        called.append(version)
        raise ValueError('secret-value')
    monkeypatch.setattr(configuration, 'generate_kea', failing)
    response = await client.post('/api/draft/validate')
    assert called and response.json()['errors'][0]['code'] == 'generator.failed'
    assert 'secret-value' not in response.text
    assert (await client.post('/api/apply', json={'version_id': 1})).status_code == 422

async def test_validation_warning(api):
    client, _, _ = api
    await sign_in(client)
    await client.post('/api/draft', json={})
    body = {'aliases': [{'name': 'many', 'type': 'port', 'elements': ['tcp/80'] * 10001}]}
    result = (await client.post('/api/draft/validate', json=body)).json()
    assert result['valid']
    assert result['warnings'][0]['code'] == 'alias.large'

def secret_config(secret):
    return {'interfaces': [{'name': 'wg0'}], 'tunnels': [{'name': 'vpn', 'interface': 'wg0', 'role': 'server', 'protocol': 'wg', 'listen_port': 51820, 'private_key': secret}]}

async def test_secrets_redacted_and_preserved(api):
    client, engine, _ = api
    await sign_in(client)
    key = Fernet.generate_key()
    secret1 = encrypt_secret('private-value-1', key).model_dump()
    secret2 = encrypt_secret('private-value-2', key).model_dump()
    with Session(engine) as db:
        save_version(db, ConfigurationVersion(id=1, status='confirmed', configuration=secret_config(secret1)))
        db.commit()
    response = await client.post('/api/draft', json=secret_config(secret2))
    assert response.status_code == 201
    public = response.json()['configuration']
    assert public['tunnels'][0]['private_key'] == {'redacted': True}
    for path in ('/api/versions', '/api/versions/2', '/api/diff/1/2', '/api/draft/tproxy/preview'):
        text = (await client.get(path)).text
        assert 'ciphertext' not in text and 'gAAAA' not in text and ('private-value' not in text)
    diff = (await client.get('/api/diff/1/2')).json()
    # The saved draft also carries the auto-materialized tunnel address, so the
    # secret change is one entry among several.
    assert any(entry['path'] == '/tunnels/0/private_key' for entry in diff)
    public['panel_port'] = 8443
    assert (await client.put('/api/draft', json=public)).status_code == 200
    with Session(engine) as db:
        assert db.get(ConfigurationRow, 2).configuration.tunnels[0].private_key.ciphertext == secret2['ciphertext']
    public['tunnels'][0].update(role='client', endpoint='vpn.test:51820', server_public_key='public')
    assert (await client.put('/api/draft', json=public)).json()['code'] == 'tunnel.role_immutable'
    public['tunnels'][0]['name'] = 'new_tunnel'
    assert (await client.put('/api/draft', json=public)).json()['code'] == 'secret.missing'

@pytest.mark.parametrize('path,body', [('/api/auth/login', {'username': 'x', 'password': 'secret', 'extra': 'private'}), ('/api/draft', {'interfaces': [{'name': 'eth0', 'addresses': ['private-secret']}]}), ('/api/apply', {'version_id': 'private-secret'}), ('/api/draft', {'tproxy': {'rules': [{'name': 'private_rule', 'ip_cidr': ['private-secret'], 'action': 'block'}]}})])
async def test_error_payloads_do_not_echo_input(api, path, body):
    client, _, _ = api
    await sign_in(client)
    response = await client.post(path, json=body)
    assert response.status_code == 422
    assert set(response.json()) == {'code', 'message', 'details'}
    assert 'private' not in response.text and '"input"' not in response.text

async def test_origin_protection(api):
    client, _, _ = api
    assert (await client.post('/api/setup', json=CREDS, headers={'Origin': 'https://evil.test'})).status_code == 403
    await sign_in(client)
    assert (await client.post('/api/draft', json={}, headers={'Origin': 'null'})).status_code == 403
    assert (await client.post('/api/draft', json={}, headers={'Origin': 'https://router.test'})).status_code == 201
    assert (await client.delete('/api/draft', headers={'Sec-Fetch-Site': 'cross-site'})).status_code == 403

async def test_agent_unavailable_leaves_state_unchanged(api, monkeypatch):
    client, _, _ = api
    await sign_in(client)
    await client.post('/api/draft', json={})
    monkeypatch.setenv('VS_ROUTER_AGENT_SOCKET', '/nonexistent-vs-router/agent.sock')
    before = (await client.get('/api/versions')).json()
    for path, body in [('apply', {'version_id': 1}), ('confirm', {'version_id': 1}), ('rollback', {})]:
        response = await client.post(f'/api/{path}', json=body)
        assert response.status_code == 503
        assert response.json()['code'] == 'agent.unavailable'
    assert (await client.post('/api/apply', json={'version_id': 999})).status_code == 404
    assert (await client.post('/api/apply', json={'version_id': 1, 'confirmation_timeout': 601})).status_code == 422
    assert (await client.post('/api/rollback', json={'command': 'reboot'})).status_code == 422
    assert (await client.get('/api/versions')).json() == before

async def test_concurrent_setup(api):
    client, engine, _ = api
    async with AsyncClient(transport=ASGITransport(app=create_app(engine)), base_url='https://router.test') as other:
        responses = await asyncio.gather(client.post('/api/setup', json=CREDS), other.post('/api/setup', json=CREDS))
        results = [response.status_code for response in responses]
    assert sorted(results) == [201, 409]

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"



async def test_alias_overlap_warning(api):
    client, _, _ = api
    await sign_in(client)
    await client.post("/api/draft", json={})
    response = await client.post("/api/draft/validate", json={"aliases": [
        {"name": "hosts", "type": "address", "elements": ["10.0.0.0/24", "10.0.0.1"]}]})
    assert response.json()["valid"]
    assert response.json()["warnings"] == [
        {"code": "alias.overlap", "message": "alias.overlap", "details": []}]


async def test_concurrent_draft(api):
    client, _, _ = api
    await sign_in(client)
    responses = await asyncio.gather(client.post("/api/draft", json={}),
                                     client.post("/api/draft", json={}))
    assert sorted(r.status_code for r in responses) == [201, 409]
    assert len((await client.get("/api/versions")).json()) == 1


async def test_secret_markers_follow_names_when_reordered(api):
    client, engine, _ = api
    await sign_in(client)
    key = Fernet.generate_key()
    first = encrypt_secret("one", key).model_dump()
    second = encrypt_secret("two", key).model_dump()
    body = secret_config(first)
    body["tunnels"].append(dict(body["tunnels"][0], name="vpn2", private_key=second))
    public = (await client.post("/api/draft", json=body)).json()["configuration"]
    public["tunnels"].reverse()
    assert (await client.put("/api/draft", json=public)).status_code == 200
    with Session(engine) as db:
        tunnels = db.get(ConfigurationRow, 1).configuration.tunnels
        assert tunnels[0].name == "vpn2"
        assert tunnels[0].private_key.ciphertext == second["ciphertext"]
        assert tunnels[1].private_key.ciphertext == first["ciphertext"]


async def test_users_constraints_and_no_password_exposure(api):
    from sqlalchemy.exc import IntegrityError
    client, engine, _ = api
    setup = await client.post("/api/setup", json=CREDS)
    assert set(setup.json()) == {"id", "username", "role"}
    with Session(engine) as db:
        db.add(UserRow(username="other", password_hash="hash", role="root"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.add(UserRow(username="admin", password_hash="hash", role="admin"))
        with pytest.raises(IntegrityError):
            db.commit()


async def test_agent_rpc_success(api, monkeypatch):
    from vs_router.api import versions
    calls = []
    class FakeClient:
        def __init__(self, transport):
            pass
        def call(self, method, params):
            calls.append((method, params.model_dump()))
            return {'status': 'ok'}
    monkeypatch.setattr(versions, 'AgentClient', FakeClient)
    client = api[0]
    await sign_in(client)
    await client.post('/api/draft', json={})
    for path, body in [('apply', {'version_id': 1}), ('confirm', {'version_id': 1}), ('rollback', {})]:
        response = await client.post('/api/' + path, json=body)
        assert response.status_code == 200
        assert response.json() == {'status': 'ok'}
    assert [c[0] for c in calls] == ['apply_version', 'confirm_version', 'rollback']


async def test_agent_fake_unavailable(api, monkeypatch):
    from vs_router.api import versions
    class UnavailableClient:
        def __init__(self, transport):
            pass
        def call(self, method, params):
            raise FileNotFoundError('private socket path')
    monkeypatch.setattr(versions, 'AgentClient', UnavailableClient)
    client = api[0]
    await sign_in(client)
    await client.post('/api/draft', json={})
    for path, body in [('apply', {'version_id': 1}), ('confirm', {'version_id': 1}), ('rollback', {})]:
        response = await client.post('/api/' + path, json=body)
        assert response.status_code == 503
        assert response.json() == {'code': 'agent.unavailable', 'message': 'agent.unavailable', 'details': []}


async def test_host_interfaces(api, monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import Mock
    from vs_router.api import host
    from vs_router.api.errors import APIError

    client = api[0]
    entries = [{'name': 'eth0', 'kind': 'physical', 'parent': None, 'operstate': 'UP'}]
    call = Mock(return_value=entries)
    monkeypatch.setattr(host, 'agent_call', call)
    assert (await client.get('/api/host/interfaces')).status_code == 401
    call.assert_not_called()
    await sign_in(client)
    response = await client.get('/api/host/interfaces')
    assert response.status_code == 200
    assert response.json() == entries
    call.assert_called_once_with('list_interfaces', {})
    call.side_effect = APIError(503, 'agent.unavailable')
    response = await client.get('/api/host/interfaces')
    assert response.status_code == 503
    assert response.json()['code'] == 'agent.unavailable'
    call.side_effect = RuntimeError('private failure')
    response = await client.get('/api/host/interfaces')
    assert response.status_code == 503
    assert response.json()['code'] == 'host.interfaces_unavailable'


async def test_host_addresses_endpoint(api, monkeypatch):
    from vs_router.api import host
    from unittest.mock import Mock
    from vs_router.api.errors import APIError
    client, _, _ = api
    live = {'eth0': ['192.168.122.253/24'], 'enp2s0': ['192.168.10.1/24']}
    call = Mock(return_value=live)
    monkeypatch.setattr(host, 'agent_call', call)
    assert (await client.get('/api/host/addresses')).status_code == 401
    call.assert_not_called()
    await sign_in(client)
    response = await client.get('/api/host/addresses')
    assert response.status_code == 200
    assert response.json() == live
    call.assert_called_once_with('list_addresses', {})
    call.side_effect = APIError(503, 'agent.unavailable')
    assert (await client.get('/api/host/addresses')).status_code == 503
    call.side_effect = RuntimeError('private failure')
    response = await client.get('/api/host/addresses')
    assert response.status_code == 503
    assert response.json()['code'] == 'host.interfaces_unavailable'


async def test_draft_save_materializes_tunnel_and_peer_addresses(api, monkeypatch):
    """Saving a draft stores the deterministic tunnel/peer addresses server-side,
    independent of the client build."""
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    client, _, _ = api
    await sign_in(client)
    body = {
        'schema_version': 1,
        'interfaces': [{'name': 'tun0', 'zone': 'lan'}],
        'tunnels': [{
            'name': 'vpn', 'interface': 'tun0', 'role': 'server', 'protocol': 'wg',
            'private_key': {'plaintext': 'k' * 44}, 'listen_port': 51820,
            'peers': [{'name': 'phone', 'public_key': 'P' * 44}],
        }],
    }
    response = await client.post('/api/draft', json=body)
    assert response.status_code == 201, response.text
    saved = response.json()['configuration']
    assert saved['interfaces'][0]['addresses'] == ['10.66.66.1/24']
    assert saved['tunnels'][0]['peers'][0]['allowed_ips'] == ['10.66.66.2/32']
