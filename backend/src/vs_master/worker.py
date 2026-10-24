"""Synchronous master DeviceOp replay and node telemetry worker (ADR-0035)."""
from cryptography.fernet import InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.secrets import decrypt_secret, encrypt_secret

from .bridge import BridgeClient, BridgeError
from .models import Account, Audit, Device, DeviceOp, Node, Subscription, utcnow


_RETRYABLE_STATUS = {502, 503, 504}


def _default_node_client(node):
    token = decrypt_secret(node.bridge_token, get_secret_key())
    return BridgeClient(node.bridge_url, token)


def _client(factory, node):
    return (factory or _default_node_client)(node)


def _actor(account):
    return account.telegram_chat_id if account and account.telegram_chat_id else 'master'


def _clear_material(device):
    device.public_key = None
    device.private_key = None
    device.preshared_key = None
    device.allowed_ips = []


def _stored_secret(value, key):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('invalid secret material')
    return encrypt_secret(value, key)


def _apply_material(device, fields, key):
    if not isinstance(fields, dict):
        return
    for field in ('name', 'public_key', 'allowed_ips'):
        if field in fields and fields[field] is not None:
            setattr(device, field, fields[field])
    if 'tunnel' in fields and fields['tunnel'] is not None:
        device.tunnel_name = fields['tunnel']
    for field in ('private_key', 'preshared_key'):
        if field in fields and fields[field] is not None:
            setattr(device, field, _stored_secret(fields[field], key))


def _payload(op, device, key):
    keys = {'private_key': None, 'public_key': None, 'preshared_key': None,
            'allowed_ips': []}
    if device:
        try:
            keys = {
                'private_key': decrypt_secret(device.private_key, key)
                if device.private_key else None,
                'public_key': device.public_key,
                'preshared_key': decrypt_secret(device.preshared_key, key)
                if device.preshared_key else None,
                'allowed_ips': device.allowed_ips,
            }
        except (InvalidToken, ValueError):
            raise BridgeError(503, 'secret.decryption_failed') from None
    payload = {'op': op.op, 'device_id': None,
               'label': op.label if op.op == 'create' else None,
               'tunnel': device.tunnel_name if device else None, 'keys': keys}
    return payload


def _valid_create(device):
    return bool(device and device.name and device.public_key and device.private_key
                and device.allowed_ips and device.tunnel_name)


def _hard_failure(db, op, device, account, code, now):
    op.status = 'failed'
    op.detail = str(code or 'node.operation_failed')[:128]
    if device and op.op == 'create':
        device.status = 'removed'
        _clear_material(device)
    db.add(Audit(actor=_actor(account), action=f'device.{op.op}.failed',
                 detail=op.detail, at=now))
    db.commit()


def _process_op(engine, node_client_factory, op_id, now):
    with Session(engine, expire_on_commit=False) as db:
        op = db.get(DeviceOp, op_id)
        if not op or op.status != 'pending':
            return op
        device = db.get(Device, op.device_id) if op.device_id else None
        node = db.get(Node, op.node_id)
        account = db.get(Account, op.account_id)
        if node is None or account is None or (op.op != 'expire' and device is None):
            _hard_failure(db, op, device, account, 'master.operation_invalid', now)
            return op
        try:
            client = _client(node_client_factory, node)
            if op.op == 'expire':
                mappings = list(db.scalars(select(Device.node_subscriber).where(
                    Device.account_id == op.account_id, Device.node_id == op.node_id,
                    Device.status == 'active').distinct()))
                results = [client.expire(subscriber) for subscriber in mappings]
            else:
                assert device is not None
                if op.op in ('activate', 'deactivate', 'delete') and (
                        not device.tunnel_name or not device.private_key
                        or not device.public_key or not device.allowed_ips):
                    raise BridgeError(409, 'master.device_material_missing')
                key = get_secret_key()
                results = [client.device_op(device.node_subscriber, _payload(op, device, key))]
            if any(not isinstance(result, dict)
                   or result.get('status') not in ('applied', 'pending') for result in results):
                return op
            if any(result['status'] == 'pending' for result in results):
                return op
            if device and op.op != 'expire':
                key = get_secret_key()
                for result in results:
                    _apply_material(device, result.get('device'), key)
                if op.op == 'create' and not _valid_create(device):
                    db.commit()
                    return op
                if op.op == 'delete':
                    device.status = 'removed'
                    _clear_material(device)
                elif op.op in ('create', 'activate'):
                    device.status = 'active'
                elif op.op == 'deactivate':
                    device.status = 'inactive'
            op.status = 'applied'
            op.detail = None
            op.applied_at = now
            db.add(Audit(actor=_actor(account), action=f'device.{op.op}.applied',
                         detail=str(op.id), at=now))
            db.commit()
            return op
        except BridgeError as exc:
            db.rollback()
            op = db.get(DeviceOp, op_id)
            device = db.get(Device, op.device_id) if op and op.device_id else None
            account = db.get(Account, op.account_id) if op else None
            if op is None:
                return None
            if exc.code == 'apply.busy' or exc.status in _RETRYABLE_STATUS:
                return op
            _hard_failure(db, op, device, account, exc.code, now)
            return op
        except Exception:
            db.rollback()
            return db.get(DeviceOp, op_id)


def process_op(engine, node_client_factory, op_id, now):
    """Replay one persisted operation; no failure escapes this function."""
    try:
        return _process_op(engine, node_client_factory, op_id, now)
    except Exception:
        try:
            with Session(engine, expire_on_commit=False) as db:
                return db.get(DeviceOp, op_id)
        except Exception:
            return None


def _mappings(db, account_id, node_id=None, active_only=False):
    query = select(Device.node_id, Device.node_subscriber).where(
        Device.account_id == account_id, Device.status != 'removed')
    if node_id is not None:
        query = query.where(Device.node_id == node_id)
    if active_only:
        query = query.where(Device.status == 'active')
    return list(db.execute(query.distinct()))


def process_pending(engine, node_client_factory=None, now=None):
    """Run one expiry, renewal, telemetry, and pending-op replay pass."""
    now = now or utcnow()
    with Session(engine) as db:
        for subscription in db.scalars(select(Subscription).order_by(Subscription.id)).all():
            if subscription.status == 'active' and subscription.expires_at <= now:
                subscription.status = 'expired'
                subscription.updated_at = now
            if subscription.status == 'expired':
                for node_id, _subscriber in _mappings(db, subscription.account_id):
                    pending = db.scalar(select(DeviceOp.id).where(
                        DeviceOp.account_id == subscription.account_id,
                        DeviceOp.node_id == node_id, DeviceOp.op == 'expire',
                        DeviceOp.status == 'pending'))
                    last = db.scalar(select(DeviceOp).where(
                        DeviceOp.account_id == subscription.account_id,
                        DeviceOp.node_id == node_id, DeviceOp.op == 'expire').order_by(
                            DeviceOp.id.desc()))
                    if pending is None and (last is None or last.detail == 'renewed'):
                        db.add(DeviceOp(account_id=subscription.account_id, node_id=node_id,
                                        op='expire', status='pending', created_at=now))
            elif subscription.status == 'active' and subscription.expires_at > now:
                expiring = list(db.scalars(select(DeviceOp).where(
                    DeviceOp.account_id == subscription.account_id, DeviceOp.op == 'expire',
                    ((DeviceOp.status == 'pending') | ((DeviceOp.status == 'applied') &
                                                      DeviceOp.detail.is_(None))))))
                if expiring:
                    for queued in expiring:
                        queued.status = 'applied'
                        queued.detail = 'renewed'
                        queued.applied_at = now
                    for node_id, subscriber in _mappings(db, subscription.account_id):
                        node = db.get(Node, node_id)
                        if node is None:
                            continue
                        try:
                            _client(node_client_factory, node).renew(subscriber)
                        except Exception:
                            pass
        db.flush()
        for node in db.scalars(select(Node).where(Node.enabled.is_(True)).order_by(Node.id)).all():
            try:
                result = _client(node_client_factory, node).node_state()
                if not isinstance(result, dict) or not isinstance(result.get('active_devices'), int):
                    continue
                node.state = 'ok'
                node.active_peers = int(result['active_devices'])
                node.last_seen = now
            except BridgeError as exc:
                if exc.status == 503:
                    node.state = 'down'
            except Exception:
                pass
        db.commit()
        pending = list(db.scalars(select(DeviceOp.id).where(
            DeviceOp.status == 'pending').order_by(DeviceOp.id)))
    for op_id in pending:
        process_op(engine, node_client_factory, op_id, now)
