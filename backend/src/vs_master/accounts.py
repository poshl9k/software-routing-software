"""Subscriber authentication for the master-owned public portal."""
import secrets
import time
from datetime import datetime, timezone
from threading import RLock

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from .models import Account, Audit, Subscription, Tariff

COOKIE = 'vs_master_portal_session'
TTL = 8 * 60 * 60
LOGIN_WINDOW = 15 * 60
router = APIRouter()


class Payload(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Credentials(Payload):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=1024)


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
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None \
                else value.astimezone(timezone.utc)
        return datetime.now(timezone.utc)

    def prune(self):
        now = self.tick()
        self.sessions = {token: entry for token, entry in self.sessions.items()
                         if entry[1] > now}
        self.failures = {key: entry for key, entry in self.failures.items()
                         if entry[1] > now}

    def revoke(self, account_id):
        with self.lock:
            self.sessions = {token: entry for token, entry in self.sessions.items()
                             if entry[0] != account_id}


def get_db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def current_account(request: Request, db: Session = Depends(get_db)):
    state = request.app.state.portal_auth
    with state.lock:
        state.prune()
        entry = state.sessions.get(request.cookies.get(COOKIE))
    account = db.get(Account, entry[0]) if entry else None
    if account is None or account.status != 'active':
        raise APIError(401, 'auth.required')
    return account


def public_account(account):
    return {'id': account.id, 'display_name': account.display_name}


def _audit(db, actor, action, detail, state):
    db.add(Audit(actor=str(actor)[:64], action=action, detail=detail, at=state.now()))


@router.post('/login')
def login(body: Credentials, request: Request, response: Response,
          db: Session = Depends(get_db)):
    state = request.app.state.portal_auth
    address = request.client.host if request.client else 'unknown'
    key = (body.username, address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            _audit(db, body.username, 'portal.login.failure', 'rate_limited', state)
            db.commit()
            raise APIError(429, 'auth.rate_limited')

        accounts = list(db.scalars(select(Account).where(
            Account.display_name == body.username, Account.status == 'active').order_by(
                Account.id).limit(2)))
        if len(accounts) > 1:
            _audit(db, body.username, 'portal.login.failure', 'name_ambiguous', state)
            state.failures[key] = (count + 1, deadline)
            db.commit()
            raise APIError(409, 'portal.name_ambiguous')
        account = accounts[0] if accounts else None
        password_hash = account.password_hash if account and account.password_hash else state.dummy_hash
        try:
            state.hasher.verify(password_hash, body.password.get_secret_value())
            valid = account is not None and bool(account.password_hash)
        except (VerificationError, InvalidHashError):
            valid = False
        _audit(db, account.id if valid else body.username,
               'portal.login.success' if valid else 'portal.login.failure', None, state)
        if not valid:
            state.failures[key] = (count + 1, deadline)
            db.commit()
            raise APIError(401, 'auth.invalid_credentials')
        assert account is not None
        state.failures.pop(key, None)
        if state.hasher.check_needs_rehash(account.password_hash):
            account.password_hash = state.hasher.hash(body.password.get_secret_value())
        db.commit()
        state.sessions.pop(request.cookies.get(COOKIE), None)
        token = secrets.token_urlsafe(32)
        state.sessions[token] = (account.id, state.tick() + TTL)
    response.set_cookie(COOKIE, token, max_age=TTL, httponly=True, secure=True,
                        samesite='lax', path='/')
    return public_account(account)


@router.post('/logout', status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    state = request.app.state.portal_auth
    with state.lock:
        entry = state.sessions.pop(request.cookies.get(COOKIE), None)
    if entry:
        _audit(db, entry[0], 'portal.logout', None, state)
        db.commit()
    response.delete_cookie(COOKIE, httponly=True, secure=True, samesite='lax', path='/')


@router.get('/me')
def me(request: Request, account: Account = Depends(current_account),
       db: Session = Depends(get_db)):
    subscription = db.scalar(select(Subscription).where(
        Subscription.account_id == account.id).order_by(Subscription.id.desc()))
    if subscription is None:
        return {'account': public_account(account), 'subscription': None}
    tariff = db.get(Tariff, subscription.tariff_id)
    expired = (subscription.status != 'active' or subscription.expires_at <=
               request.app.state.portal_auth.now() or tariff is None)
    return {'account': public_account(account),
            'subscription': {'status': 'expired' if expired else 'active',
                             'expires_at': subscription.expires_at,
                             'tariff': {'name': tariff.name} if tariff is not None else None}}
