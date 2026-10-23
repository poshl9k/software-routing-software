"""Portal-specific invite activation and process-local sessions."""
import secrets
import time
from datetime import datetime, timezone
from threading import RLock

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError
from .models import Account, Audit, Device, Invite, Subscription, Tariff, as_utc

COOKIE = 'vs_portal_session'
TTL = 8 * 60 * 60
LOGIN_WINDOW = 15 * 60
router = APIRouter()


class Payload(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Credentials(Payload):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=1024)


class Activation(Payload):
    token: str = Field(min_length=1, max_length=128)
    password: SecretStr | None = Field(default=None, min_length=8, max_length=1024)
    email: str | None = Field(default=None, max_length=320)


class AuthState:
    def __init__(self, clock=None):
        self.clock = clock or time.monotonic
        self.lock = RLock()
        self.sessions = {}
        self.failures = {}
        self.hasher = PasswordHasher(type=Type.ID)
        self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))

    def tick(self):
        value = self.clock()
        return value.timestamp() if isinstance(value, datetime) else value

    def now(self):
        value = self.clock()
        return as_utc(value) if isinstance(value, datetime) else datetime.now(timezone.utc)

    def prune(self):
        now = self.tick()
        self.sessions = {token: entry for token, entry in self.sessions.items() if entry[1] > now}
        self.failures = {key: entry for key, entry in self.failures.items() if entry[1] > now}

    def revoke(self, name):
        with self.lock:
            self.sessions = {token: entry for token, entry in self.sessions.items() if entry[0] != name}


def get_db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def current_account(request: Request, db: Session = Depends(get_db)):
    state = request.app.state.auth
    with state.lock:
        state.prune()
        entry = state.sessions.get(request.cookies.get(COOKIE))
    account = db.get(Account, entry[0]) if entry else None
    if account is None or account.status != 'active':
        raise APIError(401, 'auth.required')
    return account


def public_account(account):
    return {'subscriber_name': account.subscriber_name, 'username': account.subscriber_name,
            'email': account.email, 'status': account.status}


@router.post('/invite/activate')
def activate(body: Activation, request: Request, db: Session = Depends(get_db)):
    state = request.app.state.auth
    # SQLite writer lock makes the one-use check/update atomic across processes.
    db.execute(text('BEGIN IMMEDIATE'))
    invite = db.get(Invite, body.token)
    if invite is None or invite.used_at is not None or invite.expires_at <= state.now():
        raise APIError(400, 'portal.invite_invalid')
    if invite.password_hash is None and body.password is None:
        raise APIError(422, 'portal.password_required')
    # Invitation alone is not proof that a subscriber still exists in the panel.
    live = request.app.state.internal.state(invite.subscriber_name)
    if not isinstance(live.get('subscription'), dict):
        raise APIError(404, 'portal.subscriber_not_found')
    account = db.get(Account, invite.subscriber_name)
    password_hash = (state.hasher.hash(body.password.get_secret_value()) if body.password is not None
                     else invite.password_hash)
    if account is None:
        account = Account(subscriber_name=invite.subscriber_name, password_hash=password_hash,
                          email=body.email, status='active', created_at=state.now())
        db.add(account)
    else:
        account.password_hash = password_hash
        account.status = 'active'
        if body.email is not None:
            account.email = body.email
    invite.used_at = state.now()
    db.add(Audit(actor=invite.subscriber_name, action='activate', at=state.now()))
    db.commit()
    state.revoke(invite.subscriber_name)
    return public_account(account)


@router.post('/login')
def login(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    state = request.app.state.auth
    address = request.client.host if request.client else 'unknown'
    key = (body.username, address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            db.add(Audit(actor=body.username, action='login.failure', detail='rate_limited', at=state.now()))
            db.commit()
            raise APIError(429, 'auth.rate_limited')
        account = db.get(Account, body.username)
        try:
            state.hasher.verify(account.password_hash if account else state.dummy_hash,
                                body.password.get_secret_value())
            valid = account is not None and account.status == 'active'
        except (VerificationError, InvalidHashError):
            valid = False
        db.add(Audit(actor=body.username, action='login.success' if valid else 'login.failure', at=state.now()))
        if not valid:
            state.failures[key] = (count + 1, deadline)
            db.commit()
            raise APIError(401, 'auth.invalid_credentials')
        state.failures.pop(key, None)
        if state.hasher.check_needs_rehash(account.password_hash):
            account.password_hash = state.hasher.hash(body.password.get_secret_value())
        db.commit()
        state.sessions.pop(request.cookies.get(COOKIE), None)
        token = secrets.token_urlsafe(32)
        state.sessions[token] = (account.subscriber_name, state.tick() + TTL)
    response.set_cookie(COOKIE, token, max_age=TTL, httponly=True, secure=True,
                        samesite='lax', path='/')
    return public_account(account)


@router.post('/logout', status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    state = request.app.state.auth
    with state.lock:
        entry = state.sessions.pop(token, None)
    if entry:
        db.add(Audit(actor=entry[0], action='logout', at=state.now()))
        db.commit()
    response.delete_cookie(COOKIE, httponly=True, secure=True, samesite='lax', path='/')


@router.get('/me')
def me(request: Request, account: Account = Depends(current_account), db: Session = Depends(get_db)):
    subscription = db.get(Subscription, account.subscriber_name)
    if subscription is None:
        return {'account': public_account(account), 'subscription': None, 'notices': []}
    tariff = db.get(Tariff, subscription.tariff_id)
    remaining = (subscription.expires_at - request.app.state.auth.now()).total_seconds()
    expired = subscription.status != 'active' or remaining <= 0
    notices = ([{'code': 'portal.subscription_expired', 'message': 'Подписка истекла'}] if expired else [])
    if not expired and remaining <= 7 * 86400:
        notices.append({'code': 'portal.subscription_expiring',
                        'message': f'Подписка истекает через {max(0, int((remaining + 86399) // 86400))} дн.'})
    if tariff is not None:
        count = db.scalar(select(func.count(Device.id)).where(
            Device.subscriber_name == account.subscriber_name, Device.status != 'removed')) or 0
        if count >= tariff.device_limit:
            notices.append({'code': 'portal.device_limit',
                            'message': f'На этом тарифе разрешено {tariff.device_limit} устройств'})
    return {'account': public_account(account),
            'subscription': {'status': 'expired' if expired else 'active',
                             'expires_at': subscription.expires_at.isoformat(),
                             'tariff': {'name': tariff.name, 'device_limit': tariff.device_limit,
                                        'term_days': tariff.term_days} if tariff else None},
            'notices': notices}
