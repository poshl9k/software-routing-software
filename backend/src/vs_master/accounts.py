"""Subscriber authentication for the master-owned public portal."""
import secrets
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from threading import RLock

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from .models import Account, Audit, MagicLogin, PortalLink, Subscription, Tariff

COOKIE = 'vs_master_portal_session'
# A verified Telegram account keeps its session for a month; the cookie still
# has to pass the origin and SameSite checks on every request.
TTL = 30 * 24 * 60 * 60
LOGIN_WINDOW = 15 * 60
MAGIC_TTL = 10 * 60
router = APIRouter()


class Payload(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Credentials(Payload):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=1024)


class MagicProof(Payload):
    token: SecretStr = Field(min_length=1, max_length=128)


class LinkProof(Payload):
    token: SecretStr = Field(min_length=1, max_length=128)


def register_telegram(engine, message):
    """Accept only a private Bot API message whose sender owns its chat ID."""
    if not isinstance(message, dict) or message.get('text') != '/start':
        return None
    chat, sender = message.get('chat'), message.get('from')
    if not isinstance(chat, dict) or not isinstance(sender, dict):
        return None
    identity = chat.get('id')
    if (chat.get('type') != 'private' or type(identity) is not int or identity <= 0
            or type(sender.get('id')) is not int or sender['id'] != identity):
        return None
    parts = [sender.get('first_name'), sender.get('last_name')]
    display = ' '.join(part.strip() for part in parts if isinstance(part, str) and part.strip())
    if not display:
        username = sender.get('username')
        display = username.strip() if isinstance(username, str) and username.strip() else f'tg{identity}'
    with Session(engine) as db:
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        account = db.scalar(select(Account).where(Account.telegram_chat_id == str(identity)))
        if account is not None:
            if account.status != 'active':
                return None
            if account.telegram_linked_at is None or account.telegram_linked_chat_id != str(identity):
                account.telegram_linked_at = datetime.now(timezone.utc)
                account.telegram_linked_chat_id = str(identity)
                db.commit()
            return account.id, False
        account = Account(display_name=display[:64], telegram_chat_id=str(identity),
                          telegram_linked_at=datetime.now(timezone.utc),
                          telegram_linked_chat_id=str(identity),
                          password_hash=PasswordHasher(type=Type.ID).hash(secrets.token_urlsafe(32)))
        db.add(account)
        db.flush()
        db.add(Audit(actor=str(identity), action='portal.telegram.register', detail=str(account.id)))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.scalar(select(Account).where(Account.telegram_chat_id == str(identity)))
            return (existing.id, False) if existing is not None and existing.status == 'active' else None
        return account.id, True


def issue_magic_token(engine, account_id: int, now: datetime) -> str:
    """Create one proof for a verified Telegram identity; never store raw tokens."""
    with Session(engine) as db:
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        account = db.get(Account, account_id)
        if account is None or account.status != 'active':
            db.rollback()
            raise APIError(403, 'auth.forbidden')
        token = secrets.token_urlsafe(32)
        db.execute(delete(MagicLogin).where(MagicLogin.account_id == account.id))
        db.add(MagicLogin(token_hash=sha256(token.encode()).hexdigest(),
                          account_id=account.id, expires_at=now + timedelta(seconds=MAGIC_TTL)))
        db.commit()
        return token


def portal_link_token(engine, account_id: int, now: datetime, rotate: bool = False) -> str:
    """Return the account's stable cabinet token, creating or replacing it on demand."""
    from vs_portal.security import get_secret_key
    from vs_router.secrets import decrypt_secret, encrypt_secret
    from cryptography.fernet import InvalidToken

    with Session(engine) as db:
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        account = db.get(Account, account_id)
        if account is None or account.status != 'active':
            db.rollback()
            raise APIError(403, 'auth.forbidden')
        row = db.get(PortalLink, account.id)
        if row is not None and not rotate:
            try:
                token = decrypt_secret(row.token_secret, get_secret_key())
            except (InvalidToken, ValueError):
                token = None
            if token:
                db.rollback()
                return token
        token = secrets.token_urlsafe(32)
        secret = encrypt_secret(token, get_secret_key())
        digest = sha256(token.encode()).hexdigest()
        if row is None:
            db.add(PortalLink(account_id=account.id, token_hash=digest,
                              token_secret=secret, created_at=now))
        else:
            row.token_hash = digest
            row.token_secret = secret
            row.created_at = now
            row.last_used_at = None
        db.add(Audit(actor=str(account.id), action='portal.link.rotate', detail='1' if rotate else '0'))
        db.commit()
        return token


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


@router.post('/login/magic')
def login_magic(body: MagicProof, request: Request, response: Response,
                db: Session = Depends(get_db)):
    state = request.app.state.portal_auth
    address = request.client.host if request.client else 'unknown'
    rate_key = ('magic', address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(rate_key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, 'auth.rate_limited')
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        now = state.now()
        digest = sha256(body.token.get_secret_value().encode()).hexdigest()
        proof = db.get(MagicLogin, digest)
        account = db.get(Account, proof.account_id) if proof else None
        if (proof is None or proof.consumed_at is not None or proof.expires_at <= now
                or account is None or account.status != 'active'):
            db.rollback()
            state.failures[rate_key] = (count + 1, deadline)
            raise APIError(401, 'auth.invalid_credentials')
        proof.consumed_at = now
        _audit(db, account.id, 'portal.login.magic', None, state)
        db.commit()
        state.failures.pop(rate_key, None)
        state.sessions.pop(request.cookies.get(COOKIE), None)
        session = secrets.token_urlsafe(32)
        state.sessions[session] = (account.id, state.tick() + TTL)
    response.set_cookie(COOKIE, session, max_age=TTL, httponly=True, secure=True,
                        samesite='lax', path='/')
    return public_account(account)


@router.post('/login/link')
def login_link(body: LinkProof, request: Request, response: Response,
               db: Session = Depends(get_db)):
    """Sign in with the account's stable link; repeat visits reuse the same token."""
    state = request.app.state.portal_auth
    address = request.client.host if request.client else 'unknown'
    rate_key = ('link', address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(rate_key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, 'auth.rate_limited')
        now = state.now()
        digest = sha256(body.token.get_secret_value().encode()).hexdigest()
        row = db.scalar(select(PortalLink).where(PortalLink.token_hash == digest))
        account = db.get(Account, row.account_id) if row is not None else None
        if account is None or account.status != 'active':
            state.failures[rate_key] = (count + 1, deadline)
            raise APIError(401, 'auth.invalid_credentials')
        row.last_used_at = now
        _audit(db, account.id, 'portal.login.link', None, state)
        db.commit()
        state.failures.pop(rate_key, None)
        state.sessions.pop(request.cookies.get(COOKIE), None)
        session = secrets.token_urlsafe(32)
        state.sessions[session] = (account.id, state.tick() + TTL)
    response.set_cookie(COOKIE, session, max_age=TTL, httponly=True, secure=True,
                        samesite='lax', path='/')
    return public_account(account)


@router.post('/link/rotate', status_code=204)
def rotate_link(request: Request, account: Account = Depends(current_account)):
    """Replace the stable link; the previous URL stops working immediately."""
    portal_link_token(request.app.state.engine, account.id,
                      request.app.state.portal_auth.now(), rotate=True)


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
                             'tariff': {'name': tariff.name, 'device_limit': tariff.device_limit,
                                        'term_days': tariff.term_days} if tariff is not None else None}}
