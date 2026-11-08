"""Master bridge endpoints on the node: bearer auth, token rotation, telemetry (ADR-0035 D2/D7)."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


from vs_router.internal_app import MASTER_TOKEN_KEY, _read_master_tokens, create_internal_app
from vs_router.secrets import encrypt_secret
from test_portal_internal import rig as node_rig


@pytest.fixture
def master_node(node_rig):
    seed_token(node_rig[2], TOKEN)
    from vs_router.internal_app import import_legacy_master_tokens
    import_legacy_master_tokens(node_rig[1], node_rig[2])
    return node_rig


def master_bridge(rig):
    """Exercise the real master HTTPS client against the real node app."""
    import httpx
    from vs_master.bridge import BridgeClient

    def dispatch(request):
        return rig[0].request(request.method, str(request.url),
                              headers=request.headers, content=request.content)

    return BridgeClient('http://testserver', TOKEN, transport=httpx.MockTransport(dispatch))


def test_master_create_without_node_portal_account(master_node):
    """A master grant provisions without a shadow local portal account.

    No node-side subscriber, Subscription or Device is seeded for s99.
    Do not fix this by inserting shadow subscriber records into portal SQLite.
    """
    from types import SimpleNamespace
    from vs_master.models import Account, Base, Node, Subscription, Tariff, make_engine
    from vs_master.worker import _payload
    from vs_router.api.keygen import generate_peer_keypair

    key = os.environ['VS_ROUTER_SECRET_KEY'].encode()
    master = make_engine('sqlite://')
    Base.metadata.create_all(master)
    with Session(master) as db:
        account = Account(id=99, display_name='New user', telegram_chat_id='9900', password_hash='test')
        node = Node(name='node', bridge_url='http://testserver', bridge_token=encrypt_secret(TOKEN, key))
        tariff = Tariff(name='base', device_limit=5, term_days=30)
        db.add_all([account, node, tariff])
        db.flush()
        db.add(Subscription(account_id=account.id, tariff_id=tariff.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
        db.commit()
    pair = generate_peer_keypair()
    device = SimpleNamespace(id=99, name='master_99', tunnel_name=None,
                             private_key=encrypt_secret(pair['private_key'], key),
                             public_key=pair['public_key'], preshared_key=None, allowed_ips=[])
    payload = _payload(SimpleNamespace(id=1, op='create', label='Phone'), device, key)
    payload['entitlement'] = grant()
    try:
        result = master_bridge(master_node).device_op('s99', payload)
        assert result['status'] == 'applied'
        assert result['device']['public_key'] == pair['public_key']
    finally:
        master.dispose()


def test_master_state_without_node_portal_account(master_node):
    """State does not require a local configuration subscriber."""
    result = master_bridge(master_node).state('s99')
    assert result['devices'] == []


def test_master_bearer_cannot_mutate_local_portal_device(master_node):
    """A master bearer must not acquire local-portal ownership by device ID."""
    from test_portal_internal import create

    identity = create(master_node)
    response = master_node[0].post('/internal/portal/subscribers/alice/device-op',
                                   headers=bearer(TOKEN),
                                   json={'op': 'create', 'device_id': identity})
    assert response.status_code == 403
    assert master_node[3] == []


def test_local_portal_secret_cannot_access_master_surface(master_node):
    """The local shared secret and master bearer are distinct principals."""
    from test_portal_internal import HEADERS

    response = master_node[0].get('/internal/master/state', headers=HEADERS)
    assert response.status_code == 403


def test_master_state_survives_missing_portal_database(master_node, tmp_path):
    """After legacy-token import, master traffic must not open portal SQLite."""
    client = master_node[0]
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    unavailable = create_engine(f"sqlite:///{tmp_path / 'absent' / 'portal.db'}")
    client.app.state.portal_engine = unavailable
    try:
        response = client.get('/internal/master/state', headers=bearer(TOKEN))
        assert response.status_code == 200
    finally:
        client.app.state.portal_engine = master_node[2]
        unavailable.dispose()


def test_master_bearer_does_not_require_local_portal_secret(master_node, monkeypatch):
    """A configured master token is independent of local portal setup."""
    monkeypatch.setattr('vs_router.internal_app.read_internal_secret', lambda: '')
    response = master_node[0].get('/internal/master/state', headers=bearer(TOKEN))
    assert response.status_code == 200


ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'master-token-0123456789abcdef'
NEXT = 'master-token-fedcba9876543210'


def bearer(value):
    return {'Authorization': f'Bearer {value}'}


@pytest.fixture
def rig(node_rig):

    return node_rig[0], node_rig[2]


def seed_token(portal, current, previous=None):
    with Session(portal) as db:
        value = {'current': encrypt_secret(current, os.environ['VS_ROUTER_SECRET_KEY'].encode()).model_dump(mode='json'),
                 'previous': encrypt_secret(previous, os.environ['VS_ROUTER_SECRET_KEY'].encode()).model_dump(mode='json') if previous else None}
        from vs_portal.models import Setting
        db.add(Setting(key=MASTER_TOKEN_KEY, value=json.dumps(value)))
        db.commit()


def test_bearer_grants_bridge_and_rotation_uses_current_token(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    from vs_router.internal_app import import_legacy_master_tokens
    import_legacy_master_tokens(client.app.state.engine, portal)
    # Bearer token authenticates only the dedicated master surface.
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    rotated = client.post('/internal/master/token-rotate', headers=bearer(TOKEN), json={'new_token': NEXT})
    assert rotated.status_code == 200 and rotated.json() == {'rotated': True}
    with Session(client.app.state.engine) as db:
        current, previous = _read_master_tokens(db)
    assert current == NEXT and previous == TOKEN
    # Old token still works for the bridge (transitional generation) ...
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    # ... but a second rotation attempt with the old token proposing a THIRD
    # token is revoked: only the master's confirmed retry (same new token) wins.
    third = 'master-token-abcdef0123456789'
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': third}).status_code == 403
    # Idempotent retry with the old token proposing the CURRENT new token.
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).json() == {'rotated': False}
    # Repeated rotation with the current token proposing the same token: no-op.
    assert client.post('/internal/master/token-rotate', headers=bearer(NEXT),
                       json={'new_token': NEXT}).json() == {'rotated': False}
    with Session(client.app.state.engine) as db:
        current, previous = _read_master_tokens(db)
    assert current == NEXT


def test_token_rotates_and_revokes_previous(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    from vs_router.internal_app import import_legacy_master_tokens
    import_legacy_master_tokens(client.app.state.engine, portal)
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).status_code == 200
    # Rotation is authenticated by the CURRENT token; a wrong current token is refused.
    stranger = 'master-token-zzzzzzzzzzzzzzzz'
    assert client.post('/internal/master/token-rotate', headers=bearer(stranger),
                       json={'new_token': NEXT}).status_code == 403


def test_no_token_configured_fails_closed(rig):
    client, portal = rig
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 403
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).status_code == 403


def test_master_state_counts_active_devices(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    from vs_router.internal_app import import_legacy_master_tokens
    import_legacy_master_tokens(client.app.state.engine, portal)
    from vs_portal.models import Device, Subscription, Tariff
    with Session(portal) as db:

        db.add(Device(subscriber_name='alice', label='Телефон', status='active', allowed_ips=[]))
        db.add(Device(subscriber_name='alice', label='Ноутбук', status='inactive', allowed_ips=[]))
        db.commit()
    body = client.get('/internal/master/state', headers=bearer(TOKEN)).json()
    # Local portal devices do not contribute to master-owned execution telemetry.
    assert body['active_devices'] == 0
    assert 'tunnels' in body


def grant(version=1, active=True):
    return {'version': version, 'status': 'active' if active else 'expired',
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=1 if active else -1)).isoformat()}


def new_payload(identity=99):
    from vs_router.api.keygen import generate_peer_keypair
    return {'op': 'create', 'operation_id': 1, 'device_id': identity, 'name': f'master_{identity}',
            'label': 'Phone', 'keys': {**generate_peer_keypair(), 'allowed_ips': []},
            'entitlement': grant()}


def test_create_retry_after_lost_response(master_node):
    import httpx
    from vs_master.bridge import BridgeClient, BridgeError
    lost = [False]

    def dispatch(request):
        response = master_node[0].request(request.method, str(request.url),
                                          headers=request.headers, content=request.content)
        if not lost[0] and response.status_code == 200:
            lost[0] = True
            raise httpx.ReadTimeout('lost response', request=request)
        return response

    bridge = BridgeClient('http://testserver', TOKEN, transport=httpx.MockTransport(dispatch))
    body = new_payload()
    with pytest.raises(BridgeError):
        bridge.device_op('s99', body)
    result = bridge.device_op('s99', body)
    assert result['status'] == 'applied'
    assert result['device']['public_key'] == body['keys']['public_key']
    assert result['device']['allowed_ips']
    assert len(master_node[3]) == 1
    assert len(bridge.state('s99')['devices']) == 1


def test_entitlement_required_stale_replay_and_expire_renew_without_portal(master_node, tmp_path):
    from vs_master.bridge import BridgeError
    from test_portal_internal import last
    bridge = master_bridge(master_node)
    unavailable = create_engine(f"sqlite:///{tmp_path / 'absent' / 'portal.db'}")
    master_node[0].app.state.portal_engine = unavailable
    try:
        body = new_payload()
        missing = {k: v for k, v in body.items() if k != 'entitlement'}
        with pytest.raises(BridgeError):
            bridge.device_op('s99', missing)
        assert not master_node[3]
        bridge.device_op('s99', body)
        assert bridge.node_state()['active_devices'] == 1
        assert bridge.state('s99')['devices'][0]['applied'] is True
        assert 'private_key' not in str(bridge.state('s99'))
        assert bridge.expire('s99', {'entitlement': grant(2, False)})['status'] == 'applied'
        assert not last(master_node).tunnels[0].peers
        with pytest.raises(BridgeError):
            bridge.device_op('s99', body)
        assert bridge.renew('s99', {'entitlement': grant(3)})['status'] == 'applied'
        assert len(last(master_node).tunnels[0].peers) == 1
        assert bridge.rotate(NEXT) == {'rotated': True}
    finally:
        master_node[0].app.state.portal_engine = master_node[2]
        unavailable.dispose()


def test_expire_between_intent_commit_and_apply_cannot_restore_peer(master_node, monkeypatch):
    """A newer grant must fence a create even if confirmed config ID did not change."""
    from vs_master.bridge import BridgeError
    from vs_router import internal_app
    from test_portal_internal import last

    bridge = master_bridge(master_node)
    body = new_payload()
    real_apply = internal_app._apply

    def interleave(db, original, updated, *args, **kwargs):
        monkeypatch.setattr(internal_app, '_apply', real_apply)
        expired = bridge.expire('alice', {'entitlement': grant(2, False)})
        assert expired['status'] == 'applied'
        return real_apply(db, original, updated, *args, **kwargs)

    monkeypatch.setattr(internal_app, '_apply', interleave)
    with pytest.raises(BridgeError, match='master.entitlement_stale|apply.busy'):
        bridge.device_op('alice', body)
    assert bridge.state('alice')['subscription']['status'] == 'expired'
    assert not last(master_node).tunnels[0].peers


def test_newer_device_op_between_intent_commit_and_apply_fences_create(master_node, monkeypatch):
    """A device operation can supersede a create without changing the grant or config."""
    from vs_master.bridge import BridgeError
    from vs_router import internal_app
    from test_portal_internal import last

    bridge = master_bridge(master_node)
    body = new_payload()
    real_apply = internal_app._apply

    def interleave(db, original, updated, *args, **kwargs):
        monkeypatch.setattr(internal_app, '_apply', real_apply)
        result = bridge.device_op('alice', body | {'op': 'deactivate', 'operation_id': 2})
        assert result['status'] == 'applied'
        return real_apply(db, original, updated, *args, **kwargs)

    monkeypatch.setattr(internal_app, '_apply', interleave)
    with pytest.raises(BridgeError, match='master.operation_stale'):
        bridge.device_op('alice', body)
    assert bridge.state('alice')['devices'][0]['status'] == 'inactive'
    assert not last(master_node).tunnels[0].peers


def test_replayed_renew_snapshot_cannot_undo_newer_deactivate(master_node):
    """Entitlement version alone does not order device state within that grant."""
    from test_portal_internal import last

    bridge = master_bridge(master_node)
    body = new_payload()
    bridge.device_op('s99', body)
    snapshot = {'entitlement': body['entitlement'],
                'devices': [body | {'op': 'activate', 'operation_id': 1}]}
    assert bridge.renew('s99', snapshot)['status'] == 'applied'
    bridge.device_op('s99', body | {'op': 'deactivate', 'operation_id': 2})
    assert not last(master_node).tunnels[0].peers
    bridge.renew('s99', snapshot)  # Delayed duplicate after an ACK was lost.
    state = bridge.state('s99')['devices'][0]
    assert state['status'] == 'inactive' and not state['applied']
    assert not last(master_node).tunnels[0].peers


def test_device_operation_order_and_lifecycle_preserve_policy(master_node):
    from vs_master.bridge import BridgeError
    from vs_router.db import ConfigurationRow
    from test_portal_internal import last
    bridge = master_bridge(master_node)
    body = new_payload()
    body['operation_id'] = 1
    bridge.device_op('s99', body)
    with Session(master_node[1]) as db:
        row = db.get(ConfigurationRow, 2)
        data = row.configuration.model_dump(mode='json')
        data['tunnels'][0]['peers'][0]['dns_mode'] = 'own'
        data['routing_rules'] = [{'name': 'block_phone', 'subject': {'kind': 'device',
                                 'subscriber': 's99', 'peer': body['name']},
                                 'ip_cidr': ['10.0.0.0/8'], 'exit': {'kind': 'block'}}]
        row.configuration = data
        db.commit()
    original = last(master_node).tunnels[0].peers[0]
    deactivate = body | {'op': 'deactivate', 'operation_id': 2}
    bridge.device_op('s99', deactivate)
    assert not last(master_node).tunnels[0].peers
    bridge.device_op('s99', body | {'op': 'activate', 'operation_id': 3})
    assert last(master_node).tunnels[0].peers[0] == original
    assert last(master_node).routing_rules[0].name == 'block_phone'
    with pytest.raises(BridgeError):
        bridge.device_op('s99', deactivate)  # delayed old request must not disable the newer grant
    assert last(master_node).tunnels[0].peers[0] == original
    bridge.device_op('s99', body | {'op': 'delete', 'operation_id': 4})
    assert not last(master_node).tunnels[0].peers
    with pytest.raises(BridgeError):
        bridge.device_op('s99', body | {'op': 'activate', 'operation_id': 5})


def test_master_creation_respects_unadopted_master_allocations(master_node):
    from test_portal_internal import last
    from vs_router.generators.wireguard import peer_address
    from vs_router.schema import Peer
    body = new_payload()
    configuration = last(master_node)
    peer = Peer(name=body['name'], public_key=body['keys']['public_key'], subscriber='s99')
    tunnel = configuration.tunnels[0].model_copy(update={'peers': (peer,)})
    # Reserve the actual deterministic first choice, not an arbitrary /32 that
    # this device might never select even if reservations were ignored.
    reserved = list(peer_address(tunnel, peer, configuration))
    body['reservations'] = {'vpn': reserved}
    from vs_master.bridge import BridgeError
    with pytest.raises(BridgeError, match='wireguard.address_collision'):
        master_bridge(master_node).device_op('s99', body)
    assert not master_node[3]


def test_master_apply_failure_and_pending_keep_encrypted_intent(master_node):
    from vs_master.bridge import BridgeError
    from vs_router.db import ConfigurationRow, MasterBridgeDevice
    from sqlalchemy import select
    from test_portal_internal import last
    body = new_payload()
    bridge = master_bridge(master_node)
    with Session(master_node[1]) as db:
        db.add(ConfigurationRow(id=2, status='draft', profile='panel', configuration=last(master_node)))
        db.commit()
    with pytest.raises(BridgeError, match='apply.busy'):
        bridge.device_op('s99', body)
    with Session(master_node[1]) as db:
        assert db.get(ConfigurationRow, 2).status == 'draft'
        db.delete(db.get(ConfigurationRow, 2))
        db.commit()
    master_node[4]['safe'] = 'failed'
    with pytest.raises(BridgeError, match='apply.failed'):
        bridge.device_op('s99', body)
    with Session(master_node[1]) as db:
        assert list(db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))) == []
        saved = db.get(MasterBridgeDevice, body['device_id'])
        assert saved.private_key.ciphertext != body['keys']['private_key']
        addresses = saved.allowed_ips
    master_node[4]['safe'] = 'pending'
    assert bridge.device_op('s99', body)['status'] == 'pending'
    with pytest.raises(BridgeError, match='apply.busy'):
        bridge.device_op('s99', body)
    with Session(master_node[1]) as db:
        draft = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))
        assert draft is not None
        db.delete(draft)  # Simulate the agent finishing rollback, not a bridge action.
        db.commit()
    master_node[4]['safe'] = None
    assert bridge.device_op('s99', body)['device']['allowed_ips'] == addresses


def test_apply_rejects_stale_base_snapshot(master_node):
    from vs_router.api.errors import APIError
    from vs_router.db import ConfigurationRow
    from vs_router.internal_app import _apply
    from test_portal_internal import last
    with Session(master_node[1]) as db:
        original = db.get(ConfigurationRow, 1)
        db.add(ConfigurationRow(id=2, status='confirmed', profile='panel', configuration=last(master_node)))
        db.commit()
        with pytest.raises(APIError, match='apply.busy'):
            _apply(db, original, original.configuration)
    assert not master_node[3]


def test_legacy_token_import_runs_on_startup_and_never_on_requests(node_rig, tmp_path):
    seed_token(node_rig[2], TOKEN)
    with TestClient(create_internal_app(node_rig[1], portal_engine=node_rig[2])) as client:
        assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    unavailable = create_engine(f"sqlite:///{tmp_path / 'missing' / 'portal.db'}")
    try:
        with TestClient(create_internal_app(node_rig[1], portal_engine=unavailable)) as client:
            assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    finally:
        unavailable.dispose()


def test_master_startup_does_not_create_missing_legacy_database(node_rig, tmp_path):
    path = tmp_path / 'portal.db'
    missing = create_engine(f'sqlite:///{path}')
    try:
        with TestClient(create_internal_app(node_rig[1], portal_engine=missing)) as client:
            assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 403
        assert not path.exists()
    finally:
        missing.dispose()


def test_import_cannot_restore_revoked_legacy_token(master_node):
    from vs_router.internal_app import import_legacy_master_tokens
    bridge = master_bridge(master_node)
    bridge.rotate(NEXT)
    import_legacy_master_tokens(master_node[1], master_node[2])
    with Session(master_node[1]) as db:
        assert _read_master_tokens(db) == (NEXT, TOKEN)


def test_expire_adopts_master_snapshot_of_migrated_peer_without_portal(master_node, tmp_path):
    from test_portal_internal import create, post, last
    identity = create(master_node)
    existing = post(master_node, {'op': 'create', 'device_id': identity}).json()['device']
    body = {'op': 'activate', 'device_id': 99, 'name': existing['name'], 'tunnel': existing['tunnel'],
            'keys': {k: existing[k] for k in ('public_key', 'private_key', 'preshared_key', 'allowed_ips')},
            'entitlement': grant(2, False)}
    unavailable = create_engine(f"sqlite:///{tmp_path / 'absent' / 'portal.db'}")
    master_node[0].app.state.portal_engine = unavailable
    try:
        bridge = master_bridge(master_node)
        result = bridge.expire('alice', {'entitlement': body['entitlement'], 'devices': [body]})
        assert result['status'] == 'applied'
        assert not last(master_node).tunnels[0].peers
        assert bridge.renew('alice', {'entitlement': grant(3)})['status'] == 'applied'
        restored = last(master_node).tunnels[0].peers[0]
        assert restored.name == existing['name'] and restored.public_key == existing['public_key']
        assert list(restored.allowed_ips) == existing['allowed_ips']
    finally:
        master_node[0].app.state.portal_engine = master_node[2]
        unavailable.dispose()


def test_router_bridge_migration_preserves_configuration(tmp_path, monkeypatch):
    from sqlalchemy import inspect, text
    url = f"sqlite:///{tmp_path / 'router.db'}"
    monkeypatch.setenv('VS_ROUTER_DATABASE_URL', url)
    config = Config(str(ROOT / 'alembic.ini'))
    command.upgrade(config, '0004')
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO configuration_versions (id, status, configuration, profile, created_at) "
                                "VALUES (1, 'confirmed', '{}', 'panel', CURRENT_TIMESTAMP)"))
    command.upgrade(config, 'head')
    assert {'master_bridge_settings', 'master_bridge_devices', 'master_bridge_entitlements'} <= set(
        inspect(engine).get_table_names())
    with engine.connect() as connection:
        assert connection.execute(text('SELECT profile FROM configuration_versions WHERE id=1')).scalar() == 'panel'
    command.downgrade(config, '0004')
    assert 'master_bridge_devices' not in inspect(engine).get_table_names()
    engine.dispose()


def test_expiry_catches_create_with_lost_ack_and_keeps_retry_keys(master_node):
    from vs_master.models import Account, Base, Device, DeviceOp, Node, Subscription, Tariff, make_engine
    from vs_master.worker import process_op, process_pending
    from vs_master.bridge import BridgeError
    from sqlalchemy import select
    from test_portal_internal import last
    key = os.environ['VS_ROUTER_SECRET_KEY'].encode()
    now = datetime.now(timezone.utc)
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        account = Account(id=1, display_name='User', telegram_chat_id='1', password_hash='x')
        node = Node(id=1, name='node', bridge_url='http://testserver', bridge_token=encrypt_secret(TOKEN, key))
        tariff = Tariff(id=1, name='base', device_limit=5, term_days=30)
        db.add_all([account, node, tariff])
        db.flush()
        db.add(Subscription(account_id=1, tariff_id=1, expires_at=now + timedelta(days=1)))
        db.add(Device(id=1, account_id=1, node_id=1, node_subscriber='s99', label='Phone', status='inactive'))
        db.flush()
        db.add(DeviceOp(id=1, account_id=1, node_id=1, device_id=1, op='create', status='pending'))
        db.commit()
    real = master_bridge(master_node)

    class LostCreate:
        def device_op(self, subscriber, body):
            real.device_op(subscriber, body)
            raise BridgeError(503, 'node.unreachable')

    assert process_op(engine, lambda _: LostCreate(), 1, now).status == 'pending'
    assert last(master_node).tunnels[0].peers
    with Session(engine) as db:
        sub = db.scalar(select(Subscription))
        sub.expires_at = now - timedelta(seconds=1)
        db.commit()
    process_pending(engine, lambda _: real, now + timedelta(seconds=1))
    assert not last(master_node).tunnels[0].peers
    with Session(engine) as db:
        assert db.get(DeviceOp, 1).status == 'pending'
        assert db.get(Device, 1).private_key is not None
    engine.dispose()


def test_real_worker_lost_create_expire_and_renew_responses(master_node, tmp_path):
    import httpx
    from sqlalchemy import select
    from vs_master.bridge import BridgeClient
    from vs_master.models import Account, Base, Device, DeviceOp, Node, Subscription, Tariff, make_engine
    from vs_master.worker import process_op, process_pending
    from vs_router.secrets import decrypt_secret
    from test_portal_internal import last

    now = datetime.now(timezone.utc)
    key = os.environ['VS_ROUTER_SECRET_KEY'].encode()
    engine = make_engine(f"sqlite:///{tmp_path / 'master.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        account = Account(display_name='New user', telegram_chat_id='9900', password_hash='test')
        node = Node(name='node', bridge_url='http://testserver', enabled=True, capacity=10,
                    bridge_token=encrypt_secret(TOKEN, key))
        tariff = Tariff(name='base', device_limit=5, term_days=30)
        db.add_all([account, node, tariff])
        db.flush()
        sub = Subscription(account_id=account.id, tariff_id=tariff.id,
                           expires_at=now + timedelta(days=1), updated_at=now)
        device = Device(account_id=account.id, node_id=node.id, node_subscriber='s99',
                        label='Phone', status='inactive', allowed_ips=[])
        db.add_all([sub, device])
        db.flush()
        operation = DeviceOp(account_id=account.id, node_id=node.id, device_id=device.id,
                             op='create', label='Phone', status='pending')
        db.add(operation)
        db.commit()
        operation_id, device_id = operation.id, device.id
    lost = ['device-op']
    attempts = []

    def dispatch(request):
        response = master_node[0].request(request.method, str(request.url),
                                          headers=request.headers, content=request.content)
        if request.method == 'POST':
            attempts.append(request.url.path.rsplit('/', 1)[-1])
        if response.status_code == 200 and lost and request.url.path.endswith('/' + lost[0]):
            lost.clear()
            raise httpx.ReadTimeout('lost acknowledged response', request=request)
        return response

    factory = lambda node: BridgeClient(node.bridge_url, TOKEN, transport=httpx.MockTransport(dispatch))
    unavailable = create_engine(f"sqlite:///{tmp_path / 'absent' / 'portal.db'}")
    master_node[0].app.state.portal_engine = unavailable
    try:
        assert process_op(engine, factory, operation_id, now).status == 'pending'
        with Session(engine) as db:
            saved = db.get(Device, device_id)
            initial_private = decrypt_secret(saved.private_key, key)
            assert saved.name == f'master_{device_id}'
        applied_peer = last(master_node).tunnels[0].peers[0]
        # New worker pass/DB session, not an in-memory retry object.
        process_pending(engine, factory, now)
        with Session(engine) as db:
            saved = db.get(Device, device_id)
            assert db.get(DeviceOp, operation_id).status == 'applied'
            assert decrypt_secret(saved.private_key, key) == initial_private
            assert saved.public_key == applied_peer.public_key
            assert saved.allowed_ips == list(applied_peer.allowed_ips)
            sub = db.scalar(select(Subscription))
            sub.expires_at = now - timedelta(seconds=1)
            db.commit()
        assert len(master_node[3]) == 1
        lost[:] = ['expire']
        process_pending(engine, factory, now + timedelta(seconds=1))
        assert not last(master_node).tunnels[0].peers
        with Session(engine) as db:
            expiration = db.scalar(select(DeviceOp).where(DeviceOp.op == 'expire'))
            expire_id = expiration.id
            assert expiration.status == 'pending'
        process_pending(engine, factory, now + timedelta(seconds=2))
        with Session(engine) as db:
            assert db.get(DeviceOp, expire_id).status == 'applied'
            sub = db.scalar(select(Subscription))
            sub.status = 'active'
            sub.updated_at = now + timedelta(seconds=3)
            sub.expires_at = now + timedelta(days=2)
            db.commit()
        lost[:] = ['renew']
        process_pending(engine, factory, now + timedelta(seconds=4))
        assert last(master_node).tunnels[0].peers[0] == applied_peer
        with Session(engine) as db:
            assert db.get(DeviceOp, expire_id).status == 'pending'
            assert db.get(DeviceOp, expire_id).detail != 'renewed'
        process_pending(engine, factory, now + timedelta(seconds=5))
        with Session(engine) as db:
            assert db.get(DeviceOp, expire_id).detail == 'renewed'
        assert attempts == ['device-op', 'device-op', 'expire', 'expire', 'renew', 'renew']
        assert len(master_node[3]) == 3
    finally:
        engine.dispose()
        master_node[0].app.state.portal_engine = master_node[2]
        unavailable.dispose()
