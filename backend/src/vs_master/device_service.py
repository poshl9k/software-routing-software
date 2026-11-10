"""Shared master-owned device domain; no HTTP sessions or local portal access."""
from sqlalchemy import func, select, text

from vs_router.api.errors import APIError

from .bridge import BridgeError
from .models import Audit, Device, DeviceOp, Node, Setting, Subscription, Tariff
from .worker import process_op


def live_subscription(db, account_id, now):
    subscription = db.scalar(select(Subscription).where(
        Subscription.account_id == account_id).order_by(Subscription.id.desc()))
    if (subscription is None or subscription.status != 'active'
            or subscription.expires_at <= now):
        raise APIError(403, 'portal.subscription_expired')
    tariff = db.get(Tariff, subscription.tariff_id)
    if tariff is None:
        raise APIError(403, 'portal.subscription_expired')
    return tariff


def device_owned(db, identity, account_id):
    conditions = [Device.id == identity] if type(identity) is int else [Device.name == str(identity)]
    try:
        conditions.append(Device.id == int(identity))
    except (TypeError, ValueError):
        pass
    device = db.scalar(select(Device).where(
        Device.account_id == account_id, Device.status != 'removed',
        conditions[0] if len(conditions) == 1 else (conditions[0] | conditions[1])))
    if device is None:
        raise APIError(404, 'portal.device_not_found')
    return device


def public_device(device):
    return {'id': device.id, 'name': device.name, 'label': device.label,
            'public_key': device.public_key, 'allowed_ips': list(device.allowed_ips or ()),
            'status': device.status}


def _contains_secret_fields(value):
    if isinstance(value, dict):
        if any(str(key).lower() in {'private_key', 'preshared_key', 'ciphertext'} for key in value):
            return True
        return any(_contains_secret_fields(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_secret_fields(item) for item in value)
    return False


def subscriber_state(node_client_factory, node, subscriber):
    try:
        state = node_client_factory(node).state(subscriber)
    except (BridgeError, APIError):
        raise APIError(503, 'portal.internal_unavailable') from None
    except Exception:
        raise APIError(503, 'portal.internal_unavailable') from None
    if (not isinstance(state, dict)
            or not {'devices', 'subscription', 'tunnel'} <= state.keys()
            or not isinstance(state.get('devices'), list)
            or state.get('subscription') is not None
            and not isinstance(state.get('subscription'), dict)
            or state.get('tunnel') is not None and not isinstance(state.get('tunnel'), dict)
            or any(not isinstance(item, dict) for item in state['devices'])
            or _contains_secret_fields(state.get('subscription'))
            or _contains_secret_fields(state.get('tunnel'))):
        raise APIError(503, 'portal.internal_unavailable')
    return state


def pending_operation(db, device_id):
    return db.scalar(select(DeviceOp).where(
        DeviceOp.device_id == device_id, DeviceOp.status == 'pending').order_by(DeviceOp.id.desc()))


def _operation_response(op):
    if op is None:
        raise APIError(503, 'portal.internal_unavailable')
    if op.status == 'failed':
        raise APIError(409, op.detail or 'portal.operation_failed')
    return {'status': op.status, 'operation_id': op.id, 'device_id': op.device_id}


def _replayed(db, receipt_key, account_id):
    receipt = db.get(Setting, receipt_key) if receipt_key else None
    if receipt is None:
        return None
    op = db.get(DeviceOp, int(receipt.value))
    if op is None or op.account_id != account_id:
        raise APIError(409, 'portal.operation_failed')
    return _operation_response(op)


def _dispatch(db, engine, node_client_factory, device_lock, account, kind, device, now,
              label=None, receipt_key=None):
    op = DeviceOp(account_id=account.id, node_id=device.node_id, op=kind,
                  device_id=device.id, label=label, status='pending', created_at=now)
    db.add(op)
    db.add(Audit(actor=account.telegram_chat_id, action=f'device.{kind}',
                 detail=str(device.id), at=now))
    db.flush()
    op_id = op.id
    if receipt_key:
        # Same writer transaction as the operation: lost Telegram ACK/restart
        # cannot enqueue a second create for the same Telegram update.
        db.add(Setting(key=receipt_key, value=str(op_id)))
    db.commit()
    with device_lock:
        process_op(engine, node_client_factory, op_id, now)
    db.expire_all()
    return _operation_response(db.get(DeviceOp, op_id))


def list_devices(db, account, node_client_factory):
    local = list(db.scalars(select(Device).where(
        Device.account_id == account.id, Device.status != 'removed').order_by(Device.id)))
    mappings = {(device.node_id, device.node_subscriber) for device in local}
    states = {}
    for node_id, subscriber in sorted(mappings):
        node = db.get(Node, node_id)
        if node is None:
            raise APIError(503, 'portal.internal_unavailable')
        states[(node_id, subscriber)] = subscriber_state(node_client_factory, node, subscriber)
    items = []
    for device in local:
        state = states[(device.node_id, device.node_subscriber)]
        remote = {item.get('name'): item for item in state['devices']
                  if isinstance(item.get('name'), str)}
        external = remote.get(device.name, {}) if device.name else {}
        item = public_device(device)
        item.update({'last_handshake': external.get('last_handshake'),
                     'applied': bool(external.get('applied', False))})
        pending = pending_operation(db, device.id)
        if pending is not None:
            item['status'] = 'pending'
            item['pending_op'] = pending.op
        items.append(item)
    echoes = [{'subscription': state.get('subscription'), 'tunnel': state.get('tunnel')}
              for _, state in sorted(states.items())]
    result = {'devices': items, 'node_states': echoes}
    if len(echoes) == 1:
        result.update(echoes[0])
    elif not echoes:
        result.update({'subscription': None, 'tunnel': None})
    return result


def create_device(db, account, label, *, engine, node_client_factory, device_lock, now,
                  receipt_key=None):
    if db.get_bind().dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    tariff = live_subscription(db, account.id, now)
    replayed = _replayed(db, receipt_key, account.id)
    if replayed is not None:
        return replayed
    if not isinstance(label, str) or not 1 <= len(label.strip()) <= 128:
        raise APIError(422, 'portal.device_label')
    count = db.scalar(select(func.count(Device.id)).where(
        Device.account_id == account.id, Device.status != 'removed')) or 0
    if count >= tariff.device_limit:
        raise APIError(403, 'portal.device_limit', [
            {'message': f'На этом тарифе разрешено {tariff.device_limit} устройств'}])
    active_counts = {node_id: active for node_id, active in db.execute(
        select(Device.node_id, func.count(Device.id)).where(
            Device.status == 'active').group_by(Device.node_id)).all()}
    candidates = []
    for node in db.scalars(select(Node).where(
            Node.enabled.is_(True), Node.state == 'ok',
            Node.role.in_(('entry', 'both'))).order_by(Node.id)):
        free = node.capacity - int(active_counts.get(node.id, 0))
        if free > 0:
            candidates.append((free, node))
    if not candidates:
        raise APIError(409, 'master.no_node_available')
    node = min(candidates, key=lambda item: (-item[0], item[1].id))[1]
    device = Device(account_id=account.id, node_id=node.id,
                    node_subscriber=f's{account.id}', name=None, label=label,
                    allowed_ips=[], status='inactive', created_at=now)
    db.add(device)
    db.flush()
    return _dispatch(db, engine, node_client_factory, device_lock, account, 'create', device,
                     now, label, receipt_key)


def change_device(db, account, identity, kind, *, engine, node_client_factory, device_lock,
                  now, receipt_key=None):
    if kind not in ('activate', 'deactivate', 'delete'):
        raise APIError(422, 'portal.operation_invalid')
    if db.get_bind().dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    live_subscription(db, account.id, now)
    replayed = _replayed(db, receipt_key, account.id)
    if replayed is not None:
        return replayed
    device = device_owned(db, identity, account.id)
    if pending_operation(db, device.id) is not None:
        raise APIError(409, 'portal.operation_pending')
    if kind == 'activate' and device.status == 'active':
        raise APIError(409, 'portal.device_active')
    if kind == 'deactivate' and device.status == 'inactive':
        raise APIError(409, 'portal.device_inactive')
    return _dispatch(db, engine, node_client_factory, device_lock, account, kind, device,
                     now, receipt_key=receipt_key)
