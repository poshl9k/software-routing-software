"""Host-free contract tests for the ADR-0035 master worker."""
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.bridge import BridgeError
from vs_master.models import (Account, Audit, Base, Device, DeviceOp, Node, Subscription,
                              Tariff, make_engine)
from vs_master.worker import process_op, process_pending
from vs_router.secrets import decrypt_secret, encrypt_secret


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


class FakeBridge:
    def __init__(self, *, device_result=None, expire_result=None, state_result=None,
                 device_error=None, expire_error=None, state_error=None):
        self.device_result = device_result or {'status': 'applied'}
        self.expire_result = expire_result or {'status': 'applied'}
        self.state_result = state_result or {'active_devices': 0}
        self.device_error = device_error
        self.expire_error = expire_error
        self.state_error = state_error
        self.calls = []

    def device_op(self, subscriber, payload):
        self.calls.append(('device_op', subscriber, payload))
        if self.device_error:
            raise self.device_error
        return self.device_result

    def expire(self, subscriber):
        self.calls.append(('expire', subscriber))
        if self.expire_error:
            raise self.expire_error
        return self.expire_result

    def renew(self, subscriber):
        self.calls.append(('renew', subscriber))
        return {'status': 'applied'}

    def node_state(self):
        self.calls.append(('node_state',))
        if self.state_error:
            raise self.state_error
        return self.state_result


def rig(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        account = Account(display_name='User', telegram_chat_id='100', password_hash='x')
        node = Node(name='n1', bridge_url='https://n1', bridge_token=encrypt_secret('token', key),
                    enabled=True, state='stale', active_peers=1, last_seen=NOW - timedelta(hours=1))
        tariff = Tariff(name='base', device_limit=5, term_days=30)
        db.add_all([account, node, tariff])
        db.flush()
        subscription = Subscription(account_id=account.id, tariff_id=tariff.id,
                                    expires_at=NOW + timedelta(days=1), status='active')
        db.add(subscription)
        db.commit()
        return engine, key, account.id, node.id, tariff.id


def add_device(engine, account_id, node_id, key, *, status='inactive', complete=False,
               subscriber='subscriber-100'):
    with Session(engine) as db:
        device = Device(account_id=account_id, node_id=node_id, node_subscriber=subscriber,
                        label='Phone', status=status, allowed_ips=['10.0.0.2/32'] if complete else [])
        if complete:
            device.name = f'peer_{subscriber}'
            device.public_key = 'public-old'
            device.private_key = encrypt_secret('private-old', key)
            device.preshared_key = encrypt_secret('psk-old', key)
            device.tunnel_name = 'awg0'
        db.add(device)
        db.commit()
        return device.id


def add_op(engine, account_id, node_id, kind, device_id=None):
    with Session(engine) as db:
        op = DeviceOp(account_id=account_id, node_id=node_id, op=kind,
                      device_id=device_id, label='Phone' if kind == 'create' else None,
                      status='pending', created_at=NOW)
        db.add(op)
        db.commit()
        return op.id


def test_criterion_1_successful_create_persists_encrypted_material_and_audit(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key)
    op_id = add_op(engine, account_id, node_id, 'create', device_id)
    bridge = FakeBridge(device_result={'status': 'applied', 'device': {
        'name': 'peer_9', 'public_key': 'public-new', 'private_key': 'private-new',
        'preshared_key': 'psk-new', 'allowed_ips': ['10.0.0.9/32'], 'tunnel': 'awg0'}})

    result = process_op(engine, lambda node: bridge, op_id, NOW)

    assert result.status == 'applied' and result.applied_at == NOW
    with Session(engine) as db:
        device = db.get(Device, device_id)
        assert device.status == 'active'
        assert (device.name, device.public_key, device.allowed_ips, device.tunnel_name) == (
            'peer_9', 'public-new', ['10.0.0.9/32'], 'awg0')
        assert decrypt_secret(device.private_key, key) == 'private-new'
        assert decrypt_secret(device.preshared_key, key) == 'psk-new'
        assert device.private_key.ciphertext != 'private-new'
        audit = db.scalar(select(Audit))
        assert (audit.actor, audit.action) == ('100', 'device.create.applied')
    payload = bridge.calls[0][2]
    assert payload['device_id'] is None and payload['label'] == 'Phone'


def test_criterion_2_retryable_bridge_error_leaves_pending(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key, complete=True)
    op_id = add_op(engine, account_id, node_id, 'activate', device_id)
    bridge = FakeBridge(device_error=BridgeError(409, 'apply.busy'))

    assert process_op(engine, lambda node: bridge, op_id, NOW).status == 'pending'
    with Session(engine) as db:
        assert db.get(DeviceOp, op_id).status == 'pending'
        assert db.scalar(select(Audit)) is None


def test_criterion_3_hard_error_fails_and_rolls_back_create(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key, complete=True)
    op_id = add_op(engine, account_id, node_id, 'create', device_id)
    bridge = FakeBridge(device_error=BridgeError(409, 'device.conflict'))

    result = process_op(engine, lambda node: bridge, op_id, NOW)

    assert result is not None
    assert (result.status, result.detail) == ('failed', 'device.conflict')
    with Session(engine) as db:
        device = db.get(Device, device_id)
        assert device is not None
        assert device.status == 'removed'
        assert (device.name, device.public_key, device.private_key, device.preshared_key,
                device.allowed_ips, device.tunnel_name) == (
                    'peer_subscriber-100', None, None, None, [], 'awg0')
        assert db.scalar(select(Audit)).action == 'device.create.failed'


def test_criterion_4_expiration_queues_once_per_node_and_dedupes(monkeypatch):
    engine, key, account_id, node_id, tariff_id = rig(monkeypatch)
    add_device(engine, account_id, node_id, key, status='active', complete=True)
    with Session(engine) as db:
        node2 = Node(name='n2', bridge_url='https://n2', bridge_token=encrypt_secret('t2', key),
                     enabled=False, state='down', active_peers=0)
        db.add(node2)
        db.flush()
        add_id = node2.id
        db.add(Device(account_id=account_id, node_id=add_id, node_subscriber='subscriber-100',
                      label='Tablet', status='active', allowed_ips=[]))
        removed = Device(account_id=account_id, node_id=add_id, node_subscriber='other',
                         label='Old', status='removed', allowed_ips=[])
        db.add(removed)
        subscription = db.scalar(select(Subscription).where(Subscription.tariff_id == tariff_id))
        subscription.expires_at = NOW
        db.commit()
    bridges = {node_id: FakeBridge(expire_result={'status': 'pending'}),
               add_id: FakeBridge(expire_result={'status': 'pending'})}

    process_pending(engine, lambda node: bridges[node.id], NOW)
    process_pending(engine, lambda node: bridges[node.id], NOW)

    with Session(engine) as db:
        ops = list(db.scalars(select(DeviceOp).where(DeviceOp.op == 'expire').order_by(DeviceOp.node_id)))
        assert [(op.node_id, op.status) for op in ops] == [(node_id, 'pending'), (add_id, 'pending')]


def test_criterion_5_telemetry_ok_and_down_preserves_last_seen(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    with Session(engine) as db:
        node2 = Node(name='n2', bridge_url='https://n2', bridge_token=encrypt_secret('t2', key),
                     enabled=True, state='ok', active_peers=4,
                     last_seen=NOW - timedelta(minutes=10))
        db.add(node2)
        db.commit()
        node2_id = node2.id
    bridges = {node_id: FakeBridge(state_result={'active_devices': 7}),
               node2_id: FakeBridge(state_error=BridgeError(503, 'node.unreachable'))}

    process_pending(engine, lambda node: bridges[node.id], NOW)

    with Session(engine) as db:
        first, second = db.get(Node, node_id), db.get(Node, node2_id)
        assert (first.state, first.active_peers, first.last_seen) == ('ok', 7, NOW)
        assert second.state == 'down'
        assert second.last_seen == NOW - timedelta(minutes=10)


def test_criterion_6_renewal_cancels_pending_expire_and_calls_renew(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    add_device(engine, account_id, node_id, key, status='active', complete=True)
    op_id = add_op(engine, account_id, node_id, 'expire')
    bridge = FakeBridge()

    process_pending(engine, lambda node: bridge, NOW)

    with Session(engine) as db:
        op = db.get(DeviceOp, op_id)
        assert (op.status, op.detail, op.applied_at) == ('applied', 'renewed', NOW)
    assert ('renew', 'subscriber-100') in bridge.calls
    assert not any(call[0] == 'expire' for call in bridge.calls)


def test_contract_payload_uses_master_material_and_never_master_device_id(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key, complete=True)
    op_id = add_op(engine, account_id, node_id, 'deactivate', device_id)
    bridge = FakeBridge()

    process_op(engine, lambda node: bridge, op_id, NOW)

    call = bridge.calls[0]
    assert call[1] == 'subscriber-100'
    assert call[2] == {'op': 'deactivate', 'device_id': None, 'label': None,
                       'tunnel': 'awg0', 'keys': {
        'private_key': 'private-old', 'public_key': 'public-old',
        'preshared_key': 'psk-old', 'allowed_ips': ['10.0.0.2/32']}}


def test_contract_node_pending_and_incomplete_create_stay_retryable(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key)
    op_id = add_op(engine, account_id, node_id, 'create', device_id)
    bridge = FakeBridge(device_result={'status': 'pending'})
    assert process_op(engine, lambda node: bridge, op_id, NOW).status == 'pending'
    bridge.device_result = {'status': 'applied', 'device': {'name': 'peer', 'public_key': 'pub'}}
    assert process_op(engine, lambda node: bridge, op_id, NOW).status == 'pending'


def test_contract_expire_calls_each_active_subscriber_mapping(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    add_device(engine, account_id, node_id, key, status='active', complete=True,
               subscriber='subscriber-a')
    add_device(engine, account_id, node_id, key, status='active', complete=True,
               subscriber='subscriber-b')
    add_device(engine, account_id, node_id, key, status='inactive', complete=True,
               subscriber='inactive')
    op_id = add_op(engine, account_id, node_id, 'expire')
    bridge = FakeBridge()

    assert process_op(engine, lambda node: bridge, op_id, NOW).status == 'applied'
    assert [call for call in bridge.calls if call[0] == 'expire'] == [
        ('expire', 'subscriber-a'), ('expire', 'subscriber-b')]


def test_contract_delete_clears_keys_but_keeps_remote_identity(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key, complete=True)
    op_id = add_op(engine, account_id, node_id, 'delete', device_id)

    result = process_op(engine, lambda node: FakeBridge(), op_id, NOW)

    assert result is not None
    assert result.status == 'applied'
    with Session(engine) as db:
        device = db.get(Device, device_id)
        assert device is not None
        assert device.status == 'removed'
        assert (device.name, device.tunnel_name) == ('peer_subscriber-100', 'awg0')
        assert (device.public_key, device.private_key, device.preshared_key,
                device.allowed_ips) == (None, None, None, [])


def test_contract_default_factory_decrypts_node_token(monkeypatch):
    engine, key, account_id, node_id, _ = rig(monkeypatch)
    device_id = add_device(engine, account_id, node_id, key, complete=True)
    op_id = add_op(engine, account_id, node_id, 'deactivate', device_id)
    bridge = FakeBridge()
    captured = {}

    def fake_client(base_url, token):
        captured.update(base_url=base_url, token=token)
        return bridge

    monkeypatch.setattr('vs_master.worker.BridgeClient', fake_client)
    result = process_op(engine, None, op_id, NOW)

    assert result.status == 'applied'
    assert captured == {'base_url': 'https://n1', 'token': 'token'}
