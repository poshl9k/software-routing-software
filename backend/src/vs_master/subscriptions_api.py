"""Stable, revocable per-device subscription links delivering the mihomo profile.

The token is stored encrypted as well as hashed, so the cabinet can show the
same link (and its QR) on every visit. A link changes only when the user asks
for a new one (``POST …/subscription/rotate``), when the device is removed, or
when the account's subscription is no longer active.
"""
import base64
import io
import secrets
from hashlib import sha256

import qrcode
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.secrets import decrypt_secret, encrypt_secret

from .accounts import current_account, get_db
from .device_service import device_owned
from .exports import device_export
from .models import Account, Device, DeviceSubscription, utcnow
from .portal_api import _client_factory

router = APIRouter(prefix='/api/portal')


def _link(request, token):
    base = str(request.base_url).rstrip('/')
    return f'{base}/api/portal/sub/{token}'


def _qr_data_url(text):
    """Inline PNG so mobile clients can scan the link instead of typing it."""
    out = io.BytesIO()
    qrcode.make(text).save(out, 'PNG')
    return 'data:image/png;base64,' + base64.b64encode(out.getvalue()).decode('ascii')


def _token_of(row):
    """Decrypt the stored token; a missing or unreadable secret hides the link."""
    if row is None or not row.token_secret:
        return None
    try:
        return decrypt_secret(row.token_secret, get_secret_key())
    except (InvalidToken, ValueError):
        return None


def _view(request, row):
    token = _token_of(row)
    if token is None:
        return {'url': None, 'qr': None, 'clash_url': None}
    url = _link(request, token)
    return {'url': url, 'qr': _qr_data_url(url),
            'clash_url': 'clash://install-config?url=' + url}


def _stamp(row):
    """ISO timestamp; JSONResponse does not serialise datetimes on its own."""
    return row.created_at.isoformat() if row.created_at else None


def _owned(db, account, identity):
    return device_owned(db, identity, account.id)


def _store(db, row, device, now):
    token = secrets.token_urlsafe(32)
    digest = sha256(token.encode()).hexdigest()
    secret = encrypt_secret(token, get_secret_key())
    if row is None:
        row = DeviceSubscription(device_id=device.id, token_hash=digest,
                                 token_secret=secret, created_at=now)
        db.add(row)
    else:
        row.token_hash = digest
        row.token_secret = secret
        row.created_at = now
        row.last_used_at = None
    db.commit()
    return row


@router.post('/devices/{identity}/subscription')
def issue_subscription(identity: str, request: Request,
                       account: Account = Depends(current_account), db: Session = Depends(get_db)):
    """Return the device's link, creating it once; repeat calls keep the same token."""
    device = _owned(db, account, identity)
    row = db.get(DeviceSubscription, device.id)
    if row is None or _token_of(row) is None:
        row = _store(db, row, device, utcnow())
        return JSONResponse({'created': True, **_view(request, row),
                             'created_at': _stamp(row)}, status_code=201)
    return JSONResponse({'created': False, **_view(request, row),
                         'created_at': _stamp(row)}, status_code=200)


@router.post('/devices/{identity}/subscription/rotate')
def rotate_subscription(identity: str, request: Request,
                        account: Account = Depends(current_account),
                        db: Session = Depends(get_db)):
    """Replace the token at the user's request; the previous link stops working."""
    device = _owned(db, account, identity)
    now = utcnow()
    row = _store(db, db.get(DeviceSubscription, device.id), device, now)
    return {'created': True, **_view(request, row), 'created_at': _stamp(row)}


@router.get('/devices/{identity}/subscription')
def subscription_state(identity: str, request: Request,
                       account: Account = Depends(current_account),
                       db: Session = Depends(get_db)):
    device = _owned(db, account, identity)
    row = db.get(DeviceSubscription, device.id)
    if row is None:
        return {'active': False, 'created_at': None, 'last_used_at': None,
                'url': None, 'qr': None, 'clash_url': None}
    return {'active': True, 'created_at': row.created_at, 'last_used_at': row.last_used_at,
            **_view(request, row)}


@router.delete('/devices/{identity}/subscription', status_code=204)
def revoke_subscription(identity: str, account: Account = Depends(current_account),
                        db: Session = Depends(get_db)):
    device = _owned(db, account, identity)
    row = db.get(DeviceSubscription, device.id)
    if row is not None:
        db.delete(row)
        db.commit()


@router.get('/sub/{token}')
def fetch_subscription(token: str, request: Request, db: Session = Depends(get_db)):
    """Public profile delivery: the token is the credential, so never log it."""
    if not token or len(token) > 128:
        raise APIError(404, 'portal.subscription_link_invalid')
    row = db.scalar(select(DeviceSubscription).where(
        DeviceSubscription.token_hash == sha256(token.encode()).hexdigest()))
    if row is None:
        raise APIError(404, 'portal.subscription_link_invalid')
    device = db.get(Device, row.device_id)
    if device is None or device.status == 'removed':
        raise APIError(404, 'portal.subscription_link_invalid')
    account = db.get(Account, device.account_id)
    if account is None:
        raise APIError(404, 'portal.subscription_link_invalid')
    now = request.app.state.portal_auth.now()
    content, media_type, filename = device_export(
        db, account, device.id, 'mihomo', now, _client_factory(request))
    row.last_used_at = now
    db.commit()
    return Response(content, media_type=media_type,
                    headers={'Cache-Control': 'no-store',
                             'Content-Disposition': f'attachment; filename="{filename}"'})
