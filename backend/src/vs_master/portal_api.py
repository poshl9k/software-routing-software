"""Subscriber HTTP adapter for the shared master device domain."""
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import Field
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.secrets import decrypt_secret

from .accounts import Payload, current_account, get_db
from .bridge import BridgeClient, BridgeError
from . import device_service
from .models import Account

# Compatibility imports for existing callers; authorization semantics live in
# the domain, not in an HTTP request or a synthetic portal session.
from .device_service import device_owned, live_subscription, public_device

router = APIRouter(prefix='/api/portal', dependencies=[Depends(current_account)])


class NewDevice(Payload):
    label: str = Field(min_length=1, max_length=128)


def _client_factory(request):
    override = getattr(request.app.state, 'node_client_factory', None)
    if override is not None:
        return override

    def factory(node):
        try:
            token = decrypt_secret(node.bridge_token, get_secret_key())
        except (InvalidToken, ValueError):
            raise BridgeError(503, 'secret.decryption_failed') from None
        return BridgeClient(node.bridge_url, token)
    return factory


def subscriber_state(request, node, subscriber):
    return device_service.subscriber_state(_client_factory(request), node, subscriber)


def _context(request):
    return {'engine': request.app.state.engine,
            'node_client_factory': _client_factory(request),
            'device_lock': request.app.state.device_lock,
            'now': request.app.state.portal_auth.now()}


def _response(result):
    return JSONResponse(result, status_code=202 if result['status'] == 'pending' else 200)


@router.get('/devices')
def devices(request: Request, account: Account = Depends(current_account),
            db: Session = Depends(get_db)):
    return device_service.list_devices(db, account, _client_factory(request))


@router.post('/devices')
def create_device(body: NewDevice, request: Request,
                  account: Account = Depends(current_account), db: Session = Depends(get_db)):
    return _response(device_service.create_device(db, account, body.label, **_context(request)))


def _change(identity, kind, request, account, db):
    return _response(device_service.change_device(db, account, identity, kind, **_context(request)))


@router.delete('/devices/{identity}')
def delete_device(identity: str, request: Request,
                  account: Account = Depends(current_account), db: Session = Depends(get_db)):
    return _change(identity, 'delete', request, account, db)


@router.post('/devices/{identity}/activate')
def activate_device(identity: str, request: Request,
                    account: Account = Depends(current_account), db: Session = Depends(get_db)):
    return _change(identity, 'activate', request, account, db)


@router.post('/devices/{identity}/deactivate')
def deactivate_device(identity: str, request: Request,
                      account: Account = Depends(current_account), db: Session = Depends(get_db)):
    return _change(identity, 'deactivate', request, account, db)
