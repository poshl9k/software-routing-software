"""Subscriber device operations, persisted before dispatch and retried after apply contention."""
import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from threading import RLock

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError
from vs_router.schema import EncryptedSecret
from vs_router.secrets import decrypt_secret, encrypt_secret
from .auth import Payload, current_account, get_db
from .models import Account, Audit, Device, DeviceOp, Subscription, Tariff
from .security import get_secret_key

router = APIRouter(dependencies=[Depends(current_account)])


class NewDevice(Payload):
    label: str = Field(min_length=1, max_length=128)


def live_subscription(db, name, now):
    subscription = db.get(Subscription, name)
    if not subscription or subscription.status != 'active' or subscription.expires_at <= now:
        raise APIError(403, 'portal.subscription_expired')
    tariff = db.get(Tariff, subscription.tariff_id)
    if tariff is None:
        raise APIError(403, 'portal.subscription_expired')
    return tariff


def device_owned(db, name, owner):
    device = db.scalar(select(Device).where(Device.name == name, Device.subscriber_name == owner,
                                            Device.status != 'removed'))
    if device is None:
        raise APIError(404, 'portal.device_not_found')
    return device


def public_device(device):
    return {'id': device.id, 'name': device.name, 'label': device.label,
            'public_key': device.public_key, 'allowed_ips': device.allowed_ips,
            'status': device.status}


def _op_response(op):
    return {'status': op.status, 'operation_id': op.id, 'device_id': op.device_id}


def _secret(value):
    if value is None:
        return None
    if isinstance(value, (dict, EncryptedSecret)):
        # The internal process can persist encrypted keys before apply; never double-encrypt.
        return EncryptedSecret.model_validate(value)
    if not isinstance(value, str):
        raise APIError(503, 'portal.internal_unavailable')
    return encrypt_secret(value, get_secret_key())


def _material(device, fields):
    if not isinstance(fields, dict):
        return
    if name := fields.get('name'):
        if name != f'portal_{device.id}':
            raise APIError(503, 'portal.internal_unavailable')
        device.name = name
    for field in ('public_key', 'allowed_ips'):
        if field in fields and fields[field] is not None:
            setattr(device, field, fields[field])
    for field in ('private_key', 'preshared_key'):
        if field in fields and fields[field] is not None:
            setattr(device, field, _secret(fields[field]))
    if fields.get('tunnel'):
        device.tunnel_name = fields['tunnel']


def _payload(op, device):
    payload = {'op': op.op, 'device_id': device.id if device else None,
               'label': op.label if op.op == 'create' else None,
               'tunnel': device.tunnel_name if device else None}
    if device and device.private_key is not None:
        key = get_secret_key()
        try:
            payload['keys'] = {'private_key': decrypt_secret(device.private_key, key),
                               'public_key': device.public_key,
                               'preshared_key': decrypt_secret(device.preshared_key, key)
                               if device.preshared_key else None,
                               'allowed_ips': device.allowed_ips}
        except (InvalidToken, ValueError):
            raise APIError(503, 'secret.decryption_failed') from None
    return payload


def process_op(engine, internal, op_id, now):
    """Replay by stable device PK. Busy leaves the same operation pending."""
    with Session(engine) as db:
        op = db.get(DeviceOp, op_id)
        if not op or op.status != 'pending':
            return op
        device = db.get(Device, op.device_id) if op.device_id else None
        try:
            result = internal.expire(op.subscriber_name) if op.op == 'expire' else internal.device_op(
                op.subscriber_name, _payload(op, device))
            if not isinstance(result, dict) or result.get('status') not in ('applied', 'pending'):
                raise APIError(503, 'portal.internal_unavailable')
            # Refresh: the internal process may have persisted keys before applying.
            db.expire_all()
            device = db.get(Device, op.device_id) if op.device_id else None
            if device and result.get('device'):
                _material(device, result['device'])
            if result['status'] == 'pending':
                return op
            op.status = 'applied'
            op.applied_at = now
            if device:
                if op.op == 'delete':
                    device.status = 'removed'
                    device.private_key = None
                    device.preshared_key = None
                    device.public_key = None
                    device.allowed_ips = []
                elif op.op in ('create', 'activate'):
                    # A successful create without key material is not a completed operation.
                    if op.op == 'create' and (not device.private_key or not device.public_key or not device.allowed_ips):
                        raise APIError(503, 'portal.internal_unavailable')
                    device.status = 'active'
                elif op.op == 'deactivate':
                    device.status = 'inactive'
            db.add(Audit(actor=op.subscriber_name, action=f'device.{op.op}.applied',
                         detail=str(op.id), at=now))
            db.commit()
            return op
        except APIError as exc:
            if exc.code == 'apply.busy' or exc.status in (503, 502, 504):
                # The same request can be safely retried; internal apply is keyed by device_id.
                return op
            op.status = 'failed'
            op.detail = exc.code[:128]
            if device and op.op == 'create':
                device.status = 'removed'
                device.private_key = None
                device.preshared_key = None
                device.public_key = None
                device.allowed_ips = []
            db.add(Audit(actor=op.subscriber_name, action=f'device.{op.op}.failed',
                         detail=exc.code[:128], at=now))
            db.commit()
            return op


def _queue(request, db, owner, kind, device=None, label=None):
    now = request.app.state.auth.now()
    op = DeviceOp(subscriber_name=owner, op=kind, device_id=device.id if device else None,
                  label=label, status='pending', created_at=now)
    db.add(op)
    db.add(Audit(actor=owner, action=f'device.{kind}', at=now))
    db.commit()
    with request.app.state.device_lock:
        process_op(request.app.state.engine, request.app.state.internal, op.id, now)
    db.expire(op)
    if op.status == 'failed':
        raise APIError(409, op.detail or 'portal.operation_failed')
    return ResponseJSON(_op_response(op), 202 if op.status == 'pending' else 200)


def ResponseJSON(value, status):
    from fastapi.responses import JSONResponse
    return JSONResponse(value, status_code=status)


@router.get('/devices')
def devices(request: Request, account: Account = Depends(current_account), db: Session = Depends(get_db)):
    name = account.subscriber_name
    state = request.app.state.internal.state(name)
    local = list(db.scalars(select(Device).where(Device.subscriber_name == name, Device.status != 'removed')))
    remote = state.get('devices', [])
    if not isinstance(remote, list):
        raise APIError(503, 'portal.internal_unavailable')
    by_name = {item.get('name'): item for item in remote if isinstance(item, dict)}
    subscription = db.get(Subscription, name)
    expired = (not subscription or subscription.status != 'active'
               or subscription.expires_at <= request.app.state.auth.now())
    items = []
    for device in local:
        item = public_device(device)
        external = by_name.get(device.name, {})
        item.update({'last_handshake': external.get('last_handshake'),
                     'applied': bool(external.get('applied', False))})
        if expired and not item['applied']:
            item['status'] = 'inactive'
        pending = db.scalar(select(DeviceOp).where(DeviceOp.device_id == device.id,
                        DeviceOp.status == 'pending').order_by(DeviceOp.id.desc()))
        if pending:
            item['status'] = 'pending'
            item['pending_op'] = pending.op
        items.append(item)
    return {'devices': items, 'subscription': state.get('subscription'), 'tunnel': state.get('tunnel')}


@router.post('/devices')
def create_device(body: NewDevice, request: Request, account: Account = Depends(current_account),
                  db: Session = Depends(get_db)):
    # Serialize quota check + placeholder insertion across SQLite writers.
    db.execute(text('BEGIN IMMEDIATE'))
    name = account.subscriber_name
    tariff = live_subscription(db, name, request.app.state.auth.now())
    count = db.scalar(select(func.count(Device.id)).where(Device.subscriber_name == name,
                                                         Device.status != 'removed'))
    if count >= tariff.device_limit:
        raise APIError(403, 'portal.device_limit', [{'message': f'На этом тарифе разрешено {tariff.device_limit} устройств'}])
    device = Device(subscriber_name=name, label=body.label, status='inactive', allowed_ips=[],
                    created_at=request.app.state.auth.now())
    db.add(device)
    db.flush()
    device.name = f'portal_{device.id}'
    return _queue(request, db, name, 'create', device, body.label)


def _change(name, kind, request, account, db):
    owner = account.subscriber_name
    if kind == 'activate':
        live_subscription(db, owner, request.app.state.auth.now())
    device = device_owned(db, name, owner)
    if db.scalar(select(DeviceOp.id).where(DeviceOp.device_id == device.id, DeviceOp.status == 'pending')):
        raise APIError(409, 'portal.operation_pending')
    if kind == 'activate' and device.status == 'active':
        raise APIError(409, 'portal.device_active')
    if kind == 'deactivate' and device.status == 'inactive':
        raise APIError(409, 'portal.device_inactive')
    return _queue(request, db, owner, kind, device)


@router.delete('/devices/{name}')
def delete_device(name: str, request: Request, account: Account = Depends(current_account),
                  db: Session = Depends(get_db)):
    return _change(name, 'delete', request, account, db)


@router.post('/devices/{name}/activate')
def activate_device(name: str, request: Request, account: Account = Depends(current_account),
                    db: Session = Depends(get_db)):
    return _change(name, 'activate', request, account, db)


@router.post('/devices/{name}/deactivate')
def deactivate_device(name: str, request: Request, account: Account = Depends(current_account),
                      db: Session = Depends(get_db)):
    return _change(name, 'deactivate', request, account, db)


def _line(value):
    if not isinstance(value, str) or not value or '\n' in value or '\r' in value:
        raise APIError(503, 'portal.export_unavailable')
    return value


def _conf_text(device, tunnel, key):
    """The wg-quick client config for one device, from stored key material."""
    if not isinstance(tunnel, dict) or not device.private_key or not device.allowed_ips:
        raise APIError(503, 'portal.export_unavailable')
    if not tunnel.get('endpoint'):
        # A DHCP WAN without a lease and no explicit tunnel endpoint: the server
        # does not know its own public address, so the client config would be
        # broken. Name the missing piece instead of a bare export_unavailable.
        raise APIError(503, 'portal.export_unavailable',
                       [{'message': 'Сервер не знает свой публичный адрес: задайте '
                                    'endpoint туннеля в панели администратора.'}])
    try:
        private = decrypt_secret(device.private_key, key)
    except (InvalidToken, ValueError):
        raise APIError(503, 'portal.export_unavailable') from None
    endpoint = tunnel.get('endpoint')
    if endpoint and ':' not in endpoint and tunnel.get('listen_port'):
        endpoint = f'{endpoint}:{tunnel["listen_port"]}'
    dns = tunnel.get('dns_servers')
    allowed = tunnel.get('allowed_ips')
    if not endpoint or not tunnel.get('public_key') or not dns or not allowed:
        raise APIError(503, 'portal.export_unavailable')
    lines = ['[Interface]', f'PrivateKey = {_line(private)}',
             'Address = ' + ', '.join(_line(v) for v in device.allowed_ips),
             'DNS = ' + ', '.join(_line(v) for v in dns)]
    if tunnel.get('protocol') == 'awg':
        from vs_router.generators.wireguard import AWG_ORDER
        obfuscation = tunnel.get('obfuscation') or {}
        if not obfuscation or (any(key in obfuscation for key in ('S3', 'S4', 'I1'))
                               and not tunnel.get('header_protection_key')):
            raise APIError(503, 'portal.export_unavailable')
        lines += [f'{k} = {_line(str(obfuscation[k]))}' for k in AWG_ORDER if k in obfuscation]
        if tunnel.get('header_protection_key'):
            lines.append(f'HeaderProtectionKey = {_line(tunnel["header_protection_key"])}')
        if tunnel.get('random_trailers'):
            lines.append('RandomTrailers = on')
        if tunnel.get('disable_cookies'):
            lines.append('DisableCookies = on')
    elif tunnel.get('protocol') != 'wg':
        raise APIError(503, 'portal.export_unavailable')
    lines += ['', '[Peer]', f'PublicKey = {_line(tunnel["public_key"])}',
              f'Endpoint = {_line(endpoint)}',
              'AllowedIPs = ' + ', '.join(_line(v) for v in allowed),
              'PersistentKeepalive = 25']
    if device.preshared_key:
        try:
            lines.append(f'PresharedKey = {_line(decrypt_secret(device.preshared_key, key))}')
        except (InvalidToken, ValueError):
            raise APIError(503, 'portal.export_unavailable') from None
    return '\n'.join(lines) + '\n'


def _amnezia_uri(device, tunnel, key, account_name):
    """The Amnezia ``vpn://`` container, reusing the panel's own generator.

    The generator's schema objects are replaced by a shim carrying the same
    fields from the internal state and the stored (decrypted) key material;
    ``dns1``/``dns2``/``subnet`` remove the last configuration dependencies.
    """
    from types import SimpleNamespace
    from vs_router.generators.amnezia import amnezia_uri
    from vs_router.secrets import encrypt_secret
    if tunnel.get('protocol') != 'awg':
        raise APIError(400, 'amnezia.role_unsupported')
    for field in ('listen_port', 'public_key', 'endpoint', 'subnet'):
        if not tunnel.get(field):
            raise APIError(503, 'portal.export_unavailable')
    try:
        private = encrypt_secret(decrypt_secret(device.private_key, key), key) \
            if device.private_key else None
        psk = encrypt_secret(decrypt_secret(device.preshared_key, key), key) \
            if device.preshared_key else None
    except (InvalidToken, ValueError):
        raise APIError(503, 'portal.export_unavailable') from None
    hpk = tunnel.get('header_protection_key')
    dns_pair = tunnel.get('dns_servers') or ()
    shim = SimpleNamespace(
        protocol='awg', role='server', name=tunnel.get('name') or device.name,
        listen_port=tunnel['listen_port'], obfuscation=tunnel.get('obfuscation') or {},
        header_protection_key=encrypt_secret(hpk, key) if hpk else None,
        random_trailers=bool(tunnel.get('random_trailers')),
        disable_cookies=bool(tunnel.get('disable_cookies')),
        allowed_ips=tuple(tunnel.get('allowed_ips') or ()),
        keepalive=tunnel.get('keepalive') or 25,
        # Non-empty: tunnel_dns eagerly derives a primary otherwise.
        dns_servers=tuple(dns_pair), endpoint=None)
    peer = SimpleNamespace(name=device.name, allowed_ips=tuple(device.allowed_ips or ()),
                           public_key=device.public_key, private_key=private,
                           preshared_key=psk)
    dns_pair = tunnel.get('dns_servers') or ()
    try:
        return amnezia_uri(shim, peer, None, dns1=dns_pair[0] if dns_pair else None,
                           dns2=dns_pair[1] if len(dns_pair) > 1 else None,
                           endpoint=tunnel.get('endpoint'), description=device.label,
                           subnet=tunnel['subnet'], server_public=tunnel.get('public_key'))
    except ValueError as exc:
        raise APIError(503, 'portal.export_unavailable') from exc


@router.get('/devices/{name}/export')
def export_device(name: str, request: Request, format: str = Query('conf'),
                  account: Account = Depends(current_account), db: Session = Depends(get_db)):
    device = device_owned(db, name, account.subscriber_name)
    if format not in ('conf', 'qr', 'amnezia'):
        raise APIError(422, 'portal.export_format')
    # The device's recorded creation tunnel resolves ambiguity; a legacy record
    # without one falls back to the server-side heuristics.
    state = request.app.state.internal.state(account.subscriber_name, tunnel=device.tunnel_name)
    tunnel = state.get('tunnel')
    key = get_secret_key()
    if format == 'qr':
        import io
        import qrcode
        image = qrcode.make(_conf_text(device, tunnel, key))
        out = io.BytesIO()
        image.save(out, format='PNG')
        return Response(out.getvalue(), media_type='image/png',
                        headers={'Cache-Control': 'no-store'})
    if format == 'amnezia':
        uri = _amnezia_uri(device, tunnel, key, account.subscriber_name)
        return Response(uri, media_type='text/plain; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="{name}-amnezia.txt"',
                                 'Cache-Control': 'no-store'})
    return Response(_conf_text(device, tunnel, key), media_type='text/plain; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{name}.conf"',
                             'Cache-Control': 'no-store'})


def process_pending(engine, internal, now):
    """One worker pass: expiry/renewal and replay of pending operations."""
    with Session(engine) as db:
        for subscription in db.scalars(select(Subscription)).all():
            if subscription.status == 'active' and subscription.expires_at <= now:
                subscription.status = 'expired'
                subscription.updated_at = now
            if subscription.status == 'expired' and not db.scalar(select(DeviceOp.id).where(
                    DeviceOp.subscriber_name == subscription.subscriber_name,
                    DeviceOp.op == 'expire', DeviceOp.status == 'pending')):
                last = db.scalar(select(DeviceOp).where(DeviceOp.subscriber_name == subscription.subscriber_name,
                    DeviceOp.op == 'expire').order_by(DeviceOp.id.desc()))
                if last is None or last.detail == 'renewed':
                    db.add(DeviceOp(subscriber_name=subscription.subscriber_name, op='expire',
                                    status='pending', created_at=now))
            if subscription.status == 'active' and subscription.expires_at > now:
                # Renewal before an expired apply has run cancels that queued removal.
                for queued in db.scalars(select(DeviceOp).where(
                        DeviceOp.subscriber_name == subscription.subscriber_name,
                        DeviceOp.op == 'expire', DeviceOp.status == 'pending')):
                    queued.status = 'applied'
                    queued.detail = 'renewed'
                    queued.applied_at = now
                last = db.scalar(select(DeviceOp).where(DeviceOp.subscriber_name == subscription.subscriber_name,
                    DeviceOp.op == 'expire', DeviceOp.status == 'applied',
                    DeviceOp.detail.is_(None)).order_by(DeviceOp.id.desc()))
                if last:
                    try:
                        outcome = internal.renew(subscription.subscriber_name)
                        if outcome.get('status') == 'applied':
                            last.detail = 'renewed'
                            db.add(Audit(actor='admin', action='subscription.renewed', at=now))
                    except APIError:
                        pass
        db.commit()
        pending = list(db.scalars(select(DeviceOp.id).where(DeviceOp.status == 'pending').order_by(DeviceOp.id)))
    for op_id in pending:
        process_op(engine, internal, op_id, now)


@asynccontextmanager
async def lifespan(app):
    async def worker():
        while True:
            try:
                async with app.state.worker_lock:
                    await asyncio.to_thread(process_pending, app.state.engine, app.state.internal,
                                            app.state.auth.now())
            except Exception:
                # Keep the worker alive; pending operations remain persisted for retry.
                pass
            await asyncio.sleep(15)
    app.state.worker_lock = asyncio.Lock()
    task = asyncio.create_task(worker())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
