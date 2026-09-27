"""Single-process sessions and login throttling; restart invalidates sessions."""
import logging
import os
import secrets
import time
from threading import RLock

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, SecretStr
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..db import UserRow
from ..schema import Model
from .errors import APIError

router = APIRouter()
COOKIE = "vs_router_session"
TTL = 8 * 60 * 60
LOGIN_WINDOW = 15 * 60
logger = logging.getLogger(__name__)


class Credentials(Model):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: SecretStr = Field(min_length=1, max_length=1024)


class SetupCredentials(Credentials):
    password: SecretStr = Field(min_length=8, max_length=1024)


class AuthState:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = RLock()
        self.sessions = {}
        self.failures = {}
        self.hasher = PasswordHasher(type=Type.ID)
        self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))

    def prune(self):
        now = self.clock()
        self.sessions = {k: v for k, v in self.sessions.items() if v[1] > now}
        self.failures = {k: v for k, v in self.failures.items() if v[1] > now}


def get_db(request: Request):
    with Session(request.app.state.engine) as session:
        yield session


def current_user(request: Request, db: Session = Depends(get_db)):
    state = request.app.state.auth
    with state.lock:
        state.prune()
        entry = state.sessions.get(request.cookies.get(COOKIE))
    user = db.get(UserRow, entry[0]) if entry else None
    if user is None:
        raise APIError(401, "auth.required")
    return user


def admin(user: UserRow = Depends(current_user)):
    if user.role != "admin":
        raise APIError(403, "auth.forbidden")
    return user


def public_user(user):
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/setup", status_code=201)
def setup(body: SetupCredentials, request: Request, db: Session = Depends(get_db)):
    # SQLite is the supported storage backend. Serialize the empty-table check
    # across processes too, rather than relying on the in-memory auth lock.
    db.execute(text("BEGIN IMMEDIATE"))
    if db.scalar(select(UserRow.id).limit(1)) is not None:
        raise APIError(409, "setup.completed")
    user = UserRow(username=body.username,
                   password_hash=request.app.state.auth.hasher.hash(body.password.get_secret_value()),
                   role="admin")
    db.add(user)
    db.commit()
    return public_user(user)


@router.post("/auth/login")
def login(body: Credentials, request: Request, response: Response,
          db: Session = Depends(get_db)):
    state = request.app.state.auth
    # Do not trust X-Forwarded-For supplied by clients.
    address = request.client.host if request.client else "unknown"
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(address, (0, state.clock() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, "auth.rate_limited")
        user = db.scalar(select(UserRow).where(UserRow.username == body.username))
        try:
            state.hasher.verify(user.password_hash if user else state.dummy_hash,
                                body.password.get_secret_value())
            valid = user is not None
        except (VerificationError, InvalidHashError):
            valid = False
        logger.info("login outcome=%s", "success" if valid else "failure")
        if not valid:
            state.failures[address] = (count + 1, deadline)
            raise APIError(401, "auth.invalid_credentials")
        state.failures.pop(address, None)
        if state.hasher.check_needs_rehash(user.password_hash):
            user.password_hash = state.hasher.hash(body.password.get_secret_value())
            db.commit()
        state.sessions.pop(request.cookies.get(COOKIE), None)
        token = secrets.token_urlsafe(32)
        state.sessions[token] = (user.id, state.clock() + TTL)
    # Secure cookies require HTTPS; lab deployments behind a plain-HTTP TCP
    # bridge would silently drop the session on every navigation otherwise.
    secure = os.environ.get("VS_ROUTER_COOKIE_SECURE", "1") != "0"
    response.set_cookie(COOKIE, token, max_age=TTL, httponly=True, secure=secure,
                        samesite="strict", path="/")
    return public_user(user)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response):
    state = request.app.state.auth
    with state.lock:
        state.sessions.pop(request.cookies.get(COOKIE), None)
    response.delete_cookie(COOKIE, httponly=True, secure=True, samesite="strict", path="/")


@router.get("/auth/me")
def me(user: UserRow = Depends(current_user)):
    return public_user(user)
