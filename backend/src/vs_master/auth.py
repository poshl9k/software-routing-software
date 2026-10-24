"""Master administrator authentication and process-local sessions."""
import secrets
import time
from datetime import datetime, timezone
from threading import RLock

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from .models import Audit, Setting

COOKIE = 'vs_master_session'
TTL = 8 * 60 * 60
LOGIN_WINDOW = 15 * 60
ADMIN_PASSWORD_KEY = 'admin_password_hash'
router = APIRouter()


class Payload(BaseModel):
    model_config = ConfigDict(extra='forbid')


class SetupBody(Payload):
    password: SecretStr = Field(min_length=8, max_length=1024)


class Credentials(Payload):
    username: str = Field(default='admin', min_length=1, max_length=64)
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
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return datetime.now(timezone.utc)

    def prune(self):
        now = self.tick()
        self.sessions = {token: deadline for token, deadline in self.sessions.items()
                         if deadline > now}
        self.failures = {key: entry for key, entry in self.failures.items()
                         if entry[1] > now}


def get_db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def current_admin(request: Request):
    state = request.app.state.auth
    with state.lock:
        state.prune()
        active = request.cookies.get(COOKIE) in state.sessions
    if not active:
        raise APIError(401, 'auth.required')
    return 'admin'


def _audit(db, action, detail, state):
    db.add(Audit(actor='admin', action=action, detail=detail, at=state.now()))


@router.post('/setup', status_code=201)
def setup(body: SetupBody, request: Request, db: Session = Depends(get_db)):
    state = request.app.state.auth
    if db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))
    if db.get(Setting, ADMIN_PASSWORD_KEY) is not None:
        db.rollback()
        raise APIError(409, 'admin.already_initialized')
    db.add(Setting(key=ADMIN_PASSWORD_KEY,
                   value=state.hasher.hash(body.password.get_secret_value())))
    _audit(db, 'admin.setup', None, state)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, 'admin.already_initialized') from None
    return {'username': 'admin'}


@router.post('/login')
def login(body: Credentials, request: Request, response: Response,
          db: Session = Depends(get_db)):
    state = request.app.state.auth
    address = request.client.host if request.client else 'unknown'
    key = (body.username, address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            _audit(db, 'login.failure', 'rate_limited', state)
            db.commit()
            raise APIError(429, 'auth.rate_limited')
        setting = db.get(Setting, ADMIN_PASSWORD_KEY)
        password_hash = setting.value if setting is not None and body.username == 'admin' \
            else state.dummy_hash
        try:
            state.hasher.verify(password_hash, body.password.get_secret_value())
            valid = setting is not None and body.username == 'admin'
        except (VerificationError, InvalidHashError):
            valid = False
        _audit(db, 'login.success' if valid else 'login.failure', None, state)
        if not valid:
            state.failures[key] = (count + 1, deadline)
            db.commit()
            raise APIError(401, 'auth.invalid_credentials')
        state.failures.pop(key, None)
        if state.hasher.check_needs_rehash(setting.value):
            setting.value = state.hasher.hash(body.password.get_secret_value())
        db.commit()
        state.sessions.pop(request.cookies.get(COOKIE), None)
        token = secrets.token_urlsafe(32)
        state.sessions[token] = state.tick() + TTL
    response.set_cookie(COOKIE, token, max_age=TTL, httponly=True, secure=True,
                        samesite='lax', path='/')
    return {'username': 'admin'}


@router.post('/logout', status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    state = request.app.state.auth
    with state.lock:
        active = state.sessions.pop(request.cookies.get(COOKIE), None)
    if active is not None:
        _audit(db, 'logout', None, state)
        db.commit()
    response.delete_cookie(COOKIE, httponly=True, secure=True, samesite='lax', path='/')


@router.get('/me')
def me(admin=Depends(current_admin)):
    return {'username': admin}
