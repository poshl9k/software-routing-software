"""Revocable per-device subscription links delivering the mihomo profile."""
import base64
import io
import secrets
from hashlib import sha256

import qrcode
from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

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
    """Inline PNG so mobile clients can scan the link instead of typing it.

    The value is generated in the issue response only: the master stores just
    the hash, so an existing link can never be redrawn from the database.
    """
    out = io.BytesIO()
    qrcode.make(text).save(out, 'PNG')
    return 'data:image/png;base64,' + base64.b64encode(out.getvalue()).decode('ascii')


def _owned(db, account, identity):
    return device_owned(db, identity, account.id)


@router.post('/devices/{identity}/subscription', status_code=201)
def issue_subscription(identity: str, request: Request,
                       account: Account = Depends(current_account), db: Session = Depends(get_db)):
    """Issue (or replace) the device's link; the URL is returned exactly once."""
    device = _owned(db, account, identity)
    token = secrets.token_urlsafe(32)
    digest = sha256(token.encode()).hexdigest()
    now = utcnow()
    row = db.get(DeviceSubscription, device.id)
    if row is None:
        db.add(DeviceSubscription(device_id=device.id, token_hash=digest, created_at=now))
    else:
        row.token_hash = digest
        row.created_at = now
        row.last_used_at = None
    db.commit()
    url = _link(request, token)
    return {'url': url, 'created_at': now, 'qr': _qr_data_url(url),
            'clash_url': 'clash://install-config?url=' + url}


@router.get('/devices/{identity}/subscription')
def subscription_state(identity: str, account: Account = Depends(current_account),
                       db: Session = Depends(get_db)):
    device = _owned(db, account, identity)
    row = db.get(DeviceSubscription, device.id)
    if row is None:
        return {'active': False, 'created_at': None, 'last_used_at': None}
    return {'active': True, 'created_at': row.created_at, 'last_used_at': row.last_used_at}


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
