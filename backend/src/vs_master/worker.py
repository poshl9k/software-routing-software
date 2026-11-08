"""Synchronous master DeviceOp replay and node telemetry worker (ADR-0035)."""
import base64
import json
import secrets
from types import SimpleNamespace

from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.secrets import decrypt_secret, encrypt_secret

from .bridge import BridgeClient, BridgeError
from .models import Account, Audit, Device, DeviceOp, Node, Setting, Subscription, utcnow
from .notifications import enqueue_subscription


_RETRYABLE_STATUS = {401, 403, 502, 503, 504}


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
    payload = {'op': op.op, 'operation_id': getattr(op, 'id', None),
               'device_id': device.id if device else None,
               'name': device.name if device else None,
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


def _entitlement(db, account_id, now):
    # Serialize the durable revision with other worker instances. A timestamp
    # is not a revision: NTP adjustment must not strand expiry/renewal retries.
    db.execute(text('BEGIN IMMEDIATE'))
    subscription = db.scalar(select(Subscription).where(
        Subscription.account_id == account_id).order_by(Subscription.id.desc()))
    account = db.get(Account, account_id)
    if subscription is None or account is None:
        raise BridgeError(403, 'portal.subscription_expired')
    active = (account.status == 'active' and subscription.status == 'active'
              and subscription.expires_at > now)
    value = {'status': 'active' if active else 'expired',
             'expires_at': subscription.expires_at.isoformat()}
    setting = db.get(Setting, f'bridge_entitlement:{account_id}')
    previous = json.loads(setting.value) if setting is not None else {}
    if all(previous.get(k) == v for k, v in value.items()):
        db.commit()
        return previous
    value['version'] = int(previous.get('version', 0)) + 1
    if setting is None:
        db.add(Setting(key=f'bridge_entitlement:{account_id}', value=json.dumps(value)))
    else:
        setting.value = json.dumps(value)
    db.commit()  # Persist the version BEFORE a possibly successful remote call.
    return value


def _ensure_create_material(db, device, key):
    db.execute(text('BEGIN IMMEDIATE'))
    db.refresh(device)
    if not device.name:
        device.name = f'master_{device.id}'
    if not device.private_key:
        private = X25519PrivateKey.generate()
        device.private_key = encrypt_secret(base64.b64encode(private.private_bytes_raw()).decode(), key)
        device.public_key = base64.b64encode(private.public_key().public_bytes_raw()).decode()
        device.preshared_key = encrypt_secret(base64.b64encode(secrets.token_bytes(32)).decode(), key)
    # Commit BEFORE the request: a timeout must not change identity or keys.
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
            grant = _entitlement(db, account.id, now)
            renewing = False
            if op.op == 'create' and grant['status'] != 'active':
                # A lost response may already have installed this peer. Keep
                # its identity/material until expiry reconciles the node; a
                # later renewal can replay the original create safely.
                return op
            if op.op == 'expire':
                mappings = list(db.scalars(select(Device.node_subscriber).where(
                    Device.account_id == op.account_id, Device.node_id == op.node_id,
                    Device.status != 'removed').distinct()))
                renewing = grant['status'] == 'active'
                method = client.renew if renewing else client.expire
                results = []
                for subscriber in mappings:
                    material = []
                    for remote in db.scalars(select(Device).where(
                            Device.account_id == account.id, Device.node_id == node.id,
                            Device.node_subscriber == subscriber, Device.status != 'removed')):
                        if not remote.public_key or not remote.private_key:
                            if remote.status == 'active':
                                raise BridgeError(503, 'master.device_material_missing')
                            continue  # Never-provisioned queued create has nothing to adopt.
                        # Device.status only advances after ACK. A lost ACK can
                        # leave the node ahead; the snapshot must carry the
                        # last ACKed operation, never a still-pending one.
                        applied_id = db.scalar(select(DeviceOp.id).where(
                            DeviceOp.device_id == remote.id, DeviceOp.status == 'applied',
                            DeviceOp.op != 'expire').order_by(DeviceOp.id.desc())) or 0
                        desired = SimpleNamespace(op='activate' if remote.status == 'active' else 'deactivate',
                                                  id=applied_id, label=None)
                        material.append(_payload(desired, remote, get_secret_key()) | {'entitlement': grant})
                    results.append(method(subscriber, {'entitlement': grant, 'devices': material}))
            else:
                assert device is not None
                if op.op in ('activate', 'deactivate', 'delete') and (
                        not device.tunnel_name or not device.private_key
                        or not device.public_key or not device.allowed_ips):
                    raise BridgeError(409, 'master.device_material_missing')
                key = get_secret_key()
                if op.op == 'create':
                    _ensure_create_material(db, device, key)
                payload = _payload(op, device, key) | {'entitlement': grant}
                if op.op == 'create':
                    reservations = {}
                    for other in db.scalars(select(Device).where(
                            Device.node_id == node.id, Device.id != device.id, Device.status != 'removed')):
                        if other.tunnel_name and other.allowed_ips:
                            reservations.setdefault(other.tunnel_name, []).extend(other.allowed_ips)
                    payload['reservations'] = reservations
                results = [client.device_op(device.node_subscriber, payload)]
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
            op.detail = 'renewed' if renewing else None
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
            if (op.op == 'expire' or exc.code in ('apply.busy', 'apply.failed',
                                                'master.entitlement_stale', 'master.operation_stale')
                    or exc.status in _RETRYABLE_STATUS):
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
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        for subscription in db.scalars(select(Subscription).order_by(Subscription.id)).all():
            if subscription.status == 'active' and subscription.expires_at <= now:
                subscription.status = 'expired'
                subscription.updated_at = now
                enqueue_subscription(db, subscription, 'expired', now)
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
                    # The expire row is the durable entitlement reconciliation
                    # ticket. Reuse it on renewal; only node ACK marks 'renewed'.
                    for queued in expiring:
                        queued.status = 'pending'
        # Commit entitlement + outbox BEFORE any remote telemetry or replay.
        db.commit()
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
