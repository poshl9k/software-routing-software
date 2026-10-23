"""Internal portal boundary: two migrated/isolated stores, fake typed agent only."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_portal.models import Device, Subscription, Tariff
from vs_router.api import versions
from vs_router.db import Base, ConfigurationRow
from vs_router.internal_app import create_internal_app
from vs_router.secrets import encrypt_secret


ROOT = Path(__file__).resolve().parents[1]
PATH = '/internal/portal/subscribers/alice'
HEADERS = {'X-VS-Portal-Secret': 'test-internal-secret'}


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setenv('VS_PORTAL_INTERNAL_SECRET', HEADERS['X-VS-Portal-Secret'])
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    panel = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(panel)
    portal = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    config = Config()
    config.set_main_option('script_location', str(ROOT / 'alembic-portal'))
    with portal.begin() as connection:
        config.attributes['connection'] = connection
        command.upgrade(config, 'head')
    from vs_router.api.keygen import generate_peer_keypair
    server = generate_peer_keypair()
    document = {
        'interfaces': [{'name': 'wan0', 'zone': 'wan', 'addresses': ['203.0.113.1/24']},
                       {'name': 'wg0', 'zone': 'lan', 'addresses': ['10.66.66.1/24']}],
        'subscribers': [{'name': 'alice'}, {'name': 'bob'}],
        'tunnels': [{'name': 'vpn', 'interface': 'wg0', 'role': 'server', 'protocol': 'wg',
                     'private_key': encrypt_secret(server['private_key'], key).model_dump(mode='json'),
                     'listen_port': 20500, 'endpoint': 'vpn.example.org',
                     'allowed_ips': ['10.66.66.0/24']}],
    }
    with Session(panel) as db:
        db.add(ConfigurationRow(id=1, profile='panel', status='confirmed', configuration=document))
        db.commit()
    with Session(portal) as db:
        tariff = Tariff(name='Base', device_limit=5, term_days=30)
        db.add(tariff)
        db.flush()
        db.add(Subscription(subscriber_name='alice', tariff_id=tariff.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
        db.add(Subscription(subscriber_name='bob', tariff_id=tariff.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
        db.commit()
    calls = []
    state = {'status': 'confirmed', 'safe': None}

    def agent(method, body):
        if method == 'status':
            return {'status': state['status']}
        if method == 'tunnel_activity':
            return {'wg0': []}
        if method == 'apply_version':
            calls.append((method, body.version_id, body.safe_mode))
            with Session(panel) as db:
                row = db.get(ConfigurationRow, body.version_id)
                assert row is not None and row.status == 'draft'
                if state['safe'] is None:
                    row.status = 'confirmed'
                    db.commit()
                    return {'version_id': body.version_id, 'status': 'confirmed'}
                return {'version_id': body.version_id, 'status': state['safe']}
        raise AssertionError(method)

    monkeypatch.setattr(versions, 'agent_call', agent)
    client = TestClient(create_internal_app(panel, portal_engine=portal), raise_server_exceptions=False)
    yield client, panel, portal, calls, state
    client.close()
    panel.dispose()
    portal.dispose()


def post(rig, payload):
    return rig[0].post(PATH + '/device-op', headers=HEADERS, json=payload)


def create(rig, label='phone', owner='alice'):
    with Session(rig[2]) as db:
        d = Device(subscriber_name=owner, label=label, status='active')
        db.add(d)
        db.commit()
        return d.id


def last(rig):
    with Session(rig[1]) as db:
        return db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                         .order_by(ConfigurationRow.id.desc())).configuration


def test_criterion_7_secret_and_no_admin_surface(rig, monkeypatch, tmp_path):
    client = rig[0]
    for route in ('/api/apply', '/api/versions', '/docs', '/openapi.json', '/health'):
        assert client.get(route, headers=HEADERS).status_code == 404
    for headers in ({}, {'X-VS-Portal-Secret': 'wrong'}):
        response = client.get(PATH + '/state', headers=headers)
        assert response.status_code == 403
        assert response.json()['error']['code'] == 'auth.forbidden'
    secret_file = tmp_path / 'secret'
    secret_file.write_text('from-file\n')
    monkeypatch.setenv('VS_PORTAL_INTERNAL_SECRET', str(secret_file))
    assert client.get(PATH + '/state', headers={'X-VS-Portal-Secret': 'from-file'}).status_code == 200
    assert client.get(PATH + '/state', headers=HEADERS).status_code == 403


def test_criterion_7_create_retry_and_encrypted_material(rig):
    id = create(rig)
    first = post(rig, {'op': 'create', 'device_id': id})
    assert first.status_code == 200, first.text
    assert first.json()['status'] == 'applied'
    device = first.json()['device']
    assert device['name'] == f'portal_{id}'
    assert device['private_key'] and device['preshared_key'] and device['allowed_ips']
    assert rig[3] == [('apply_version', 2, False)]
    peer = last(rig).tunnels[0].peers[0]
    assert peer.name == device['name'] and peer.public_key == device['public_key']
    assert peer.private_key.ciphertext != device['private_key']
    with Session(rig[2]) as db:
        stored = db.get(Device, id)
        assert stored.private_key.ciphertext != device['private_key']
        assert stored.preshared_key.ciphertext != device['preshared_key']
    again = post(rig, {'op': 'create', 'device_id': id})
    assert again.status_code == 200, again.text
    assert again.json()['device'] == device
    assert len(rig[3]) == 1
    bad_keys = post(rig, {'op': 'create', 'device_id': id,
                          'keys': {'public_key': 'unexpected', 'allowed_ips': device['allowed_ips']}})
    assert bad_keys.status_code == 409
    assert bad_keys.json()['error']['code'] == 'device.keys_mismatch'
    assert len(rig[3]) == 1
    state = rig[0].get(PATH + '/state', headers=HEADERS).json()
    assert state['devices'][0]['applied'] is True
    assert 'private_key' not in str(state)
    assert state['tunnel']['public_key'] and state['tunnel']['endpoint']


def test_criterion_7_delete_deactivate_activate_ownership(rig):
    id = create(rig)
    assert post(rig, {'op': 'create', 'device_id': id}).status_code == 200
    original = last(rig).tunnels[0].peers[0]
    assert post(rig, {'op': 'deactivate', 'device_id': id}).status_code == 200
    assert not last(rig).tunnels[0].peers
    with Session(rig[2]) as db:
        db.get(Device, id).status = 'inactive'
        db.commit()
    assert post(rig, {'op': 'activate', 'device_id': id}).status_code == 200
    assert last(rig).tunnels[0].peers[0] == original
    assert post(rig, {'op': 'delete', 'device_id': id}).status_code == 200
    assert not last(rig).tunnels[0].peers
    assert post(rig, {'op': 'delete', 'device_id': id}).status_code == 200
    other = create(rig, owner='bob')
    assert post(rig, {'op': 'activate', 'device_id': other}).json()['error']['code'] == 'device.not_found'


def test_criterion_7_expire_renew_preserves_desired_active_only(rig):
    active = create(rig)
    inactive = create(rig, 'tablet')
    for id in (active, inactive):
        assert post(rig, {'op': 'create', 'device_id': id}).status_code == 200
    with Session(rig[2]) as db:
        db.get(Device, inactive).status = 'inactive'
        db.commit()
    assert rig[0].post(PATH + '/expire', headers=HEADERS).status_code == 200
    assert not last(rig).tunnels[0].peers
    with Session(rig[2]) as db:
        saved = db.get(Device, active)
        keys, addresses = saved.public_key, saved.allowed_ips
    assert rig[0].post(PATH + '/renew', headers=HEADERS).status_code == 200
    peers = last(rig).tunnels[0].peers
    assert len(peers) == 1 and peers[0].public_key == keys
    assert list(peers[0].allowed_ips) == addresses
    count = len(rig[3])
    assert rig[0].post(PATH + '/renew', headers=HEADERS).status_code == 200
    assert len(rig[3]) == count


def test_criterion_7_admin_draft_pending_and_disabled_do_not_mutate(rig):
    id = create(rig)
    with Session(rig[1]) as db:
        db.add(ConfigurationRow(id=2, profile='panel', status='draft', configuration=last(rig)))
        db.commit()
    assert post(rig, {'op': 'create', 'device_id': id}).json()['error']['code'] == 'apply.busy'
    with Session(rig[1]) as db:
        assert db.get(ConfigurationRow, 2).status == 'draft'
        db.delete(db.get(ConfigurationRow, 2))
        db.commit()
    rig[4]['status'] = 'pending'
    assert post(rig, {'op': 'create', 'device_id': id}).json()['error']['code'] == 'apply.busy'
    rig[4]['status'] = 'confirmed'
    with Session(rig[2]) as db:
        db.get(Subscription, 'alice').status = 'expired'
        db.commit()
    assert post(rig, {'op': 'create', 'device_id': id}).json()['error']['code'] == 'portal.subscription_expired'
    assert not rig[3]


def test_criterion_7_same_apply_entry_and_pending_semantics(rig, monkeypatch):
    original = versions.apply
    entered = []

    def same_entry(params, db):
        entered.append((params.version_id, params.safe_mode))
        return original(params, db)

    monkeypatch.setattr(versions, 'apply', same_entry)
    id = create(rig)
    rig[4]['safe'] = 'pending'  # Host, not portal, decides whether safe mode applies.
    response = post(rig, {'op': 'create', 'device_id': id})
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'pending'
    assert entered == [(2, False)]
    with Session(rig[1]) as db:
        assert db.get(ConfigurationRow, 2).status == 'draft'
    assert post(rig, {'op': 'create', 'device_id': id}).json()['error']['code'] == 'apply.busy'


def test_criterion_7_failed_apply_keeps_retry_material_and_cleans_only_own_draft(rig):
    id = create(rig)
    rig[4]['safe'] = 'failed'  # e.g. agent.no_confirmed_version on first safe apply
    response = post(rig, {'op': 'create', 'device_id': id})
    assert response.status_code == 409
    assert response.json()['error']['code'] == 'apply.failed'
    with Session(rig[1]) as db:
        assert list(db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))) == []
    with Session(rig[2]) as db:
        saved = db.get(Device, id)
        assert saved.private_key and saved.preshared_key and saved.allowed_ips
        first_key = saved.public_key
    rig[4]['safe'] = None
    retried = post(rig, {'op': 'create', 'device_id': id})
    assert retried.status_code == 200, retried.text
    assert retried.json()['device']['public_key'] == first_key


def test_criterion_7_state_ignores_admin_draft(rig):
    with Session(rig[1]) as db:
        modified = last(rig).model_dump(mode='json')
        modified['subscribers'] = [{'name': 'bob'}]
        db.add(ConfigurationRow(id=2, profile='panel', status='draft', configuration=modified))
        db.commit()
    state = rig[0].get(PATH + '/state', headers=HEADERS)
    assert state.status_code == 200
    assert state.json()['subscription']['status'] == 'active'
    assert rig[0].get('/internal/portal/subscribers/bob/state', headers=HEADERS).status_code == 200
    assert rig[0].get('/internal/portal/subscribers/nobody/state', headers=HEADERS).status_code == 404


def test_criterion_9_public_worker_audits_completed_internal_operation(rig):
    from vs_portal.devices import process_op
    from vs_portal.models import Audit, DeviceOp
    id = create(rig)
    with Session(rig[2]) as db:
        operation = DeviceOp(subscriber_name='alice', device_id=id, op='create',
                             label='phone', status='pending')
        db.add(operation)
        db.commit()
        op_id = operation.id

    class Internal:
        def device_op(self, name, payload):
            assert name == 'alice'
            response = post(rig, payload)
            assert response.status_code == 200, response.text
            return response.json()

    process_op(rig[2], Internal(), op_id, datetime.now(timezone.utc))
    with Session(rig[2]) as db:
        assert db.get(DeviceOp, op_id).status == 'applied'
        assert db.get(Device, id).status == 'active'
        assert db.scalar(select(Audit).where(Audit.action == 'device.create.applied')) is not None
