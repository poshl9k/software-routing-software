"""Verified email and recovery for subscribers, never administrator credentials.

Reset revokes web sessions via the persisted password revision. Permanent cabinet
links and client/device credentials are separate credentials and remain unchanged.
"""
from datetime import timedelta
from hashlib import sha256
import secrets

from fastapi import APIRouter, Depends, Request
from pydantic import Field, SecretStr, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.secrets import encrypt_secret
from .accounts import COOKIE, Payload, current_account
from .mail import (EMAIL_RESET_PATH, EMAIL_TTL, EMAIL_VERIFY_PATH, begin_write,
                   load_config, normalize_email)
from .models import Account, Audit, EmailOutbox, EmailProof, EmailRateLimit, MagicLogin

router = APIRouter()
ACCEPTED = {'status': 'accepted'}


class EmailBody(Payload):
    email: str = Field(min_length=3, max_length=256)

    @field_validator('email')
    @classmethod
    def validate_email(cls, value):
        return normalize_email(value)


class ProofBody(Payload):
    token: SecretStr = Field(min_length=1, max_length=128)


class ResetBody(ProofBody):
    password: SecretStr = Field(min_length=12, max_length=1024)


def configuration():
    try:
        return load_config()
    except Exception:
        raise APIError(503, 'portal.email_unavailable') from None


def rate(db, namespace, value, maximum, now):
    digest = sha256(f'{namespace}:{value}'.encode()).hexdigest()
    row = db.get(EmailRateLimit, digest)
    if row is None:
        row = EmailRateLimit(key=digest, count=0, expires_at=now + timedelta(hours=1))
        db.add(row)
    elif row.expires_at <= now:
        row.count, row.expires_at = 0, now + timedelta(hours=1)
    row.count += 1
    return row.count <= maximum


def enqueue(db, account, email, kind, now, config):
    db.execute(delete(EmailProof).where(EmailProof.account_id == account.id, EmailProof.kind == kind))
    token = secrets.token_urlsafe(32)
    digest = sha256(token.encode()).hexdigest()
    proof = EmailProof(token_hash=digest, account_id=account.id, kind=kind, email=email,
                       password_revision=account.password_revision, expires_at=now + EMAIL_TTL)
    db.add(proof)
    db.flush()
    path = EMAIL_VERIFY_PATH if kind == 'verify' else EMAIL_RESET_PATH
    purpose = 'Verify your subscriber email' if kind == 'verify' else 'Reset your subscriber password'
    body = (f'{purpose}:\n{config.origin}{path}#token={token}\n\n'
            'This one-use link expires in 30 minutes. If you did not request it, ignore this email.\n')
    db.add(EmailOutbox(token_hash=digest, body_secret=encrypt_secret(body, get_secret_key()),
                       next_attempt_at=now))
    db.add(Audit(actor=str(account.id), action=f'portal.email.{kind}.requested', at=now))


@router.post('/email/request', status_code=202)
def request_email(body: EmailBody, request: Request, account: Account = Depends(current_account)):
    config = configuration()
    state = request.app.state.portal_auth
    now = state.now()
    account_id = account.id
    # Re-read after acquiring the write reservation: a simultaneous reset must
    # not let a now-revoked browser session bind another address.
    with Session(request.app.state.engine) as db:
        begin_write(db)
        account = db.get(Account, account_id)
        with state.lock:
            entry = state.sessions.get(request.cookies.get(COOKIE))
        if (account is None or account.status != 'active' or not entry
                or len(entry) != 3 or entry[2] != account.password_revision):
            raise APIError(401, 'auth.required')
        account_ok = rate(db, 'verify:account', account.id, 3, now)
        email_ok = rate(db, 'verify:email', body.email, 3, now)
        if not account_ok or not email_ok:
            db.commit()
            raise APIError(429, 'auth.rate_limited')
        enqueue(db, account, body.email, 'verify', now, config)
        db.commit()
    return {'status': 'queued'}


@router.post('/password/forgot', status_code=202)
def forgot_password(body: EmailBody, request: Request):
    # Precheck for *every* address so a broken configuration cannot enumerate users.
    config = configuration()
    now = request.app.state.portal_auth.now()
    with Session(request.app.state.engine) as db:
        begin_write(db)
        email_ok = rate(db, 'forgot:email', body.email, 3, now)
        account = db.scalar(select(Account).where(Account.email == body.email, Account.status == 'active'))
        account_ok = rate(db, 'forgot:account', account.id, 3, now) if account else False
        if account is not None and email_ok and account_ok:
            enqueue(db, account, body.email, 'reset', now, config)
        db.commit()
    # Accepted is NOT a claim that mail was sent, nor that this account exists.
    return ACCEPTED


def valid_proof(db, body, kind, now):
    digest = sha256(body.token.get_secret_value().encode()).hexdigest()
    proof = db.get(EmailProof, digest)
    account = db.get(Account, proof.account_id) if proof else None
    if (proof is None or proof.kind != kind or proof.consumed_at is not None
            or proof.expires_at <= now or account is None or account.status != 'active'
            or proof.password_revision != account.password_revision
            or (kind == 'reset' and account.email != proof.email)):
        # Persist invalid-attempt throttling too.
        db.commit()
        raise APIError(400, 'portal.email_token_invalid')
    return proof, account


@router.post('/email/confirm', status_code=204)
def confirm_email(body: ProofBody, request: Request):
    now = request.app.state.portal_auth.now()
    with Session(request.app.state.engine) as db:
        begin_write(db)
        proof, account = valid_proof(db, body, 'verify', now)
        owner = db.scalar(select(Account.id).where(Account.email == proof.email, Account.id != account.id))
        if owner is not None:
            proof.consumed_at = now
            db.commit()
            raise APIError(400, 'portal.email_token_invalid')
        account.email = proof.email
        proof.consumed_at = now
        # A reset sent to a former address must not survive an address change.
        db.execute(delete(EmailProof).where(EmailProof.account_id == account.id, EmailProof.kind == 'reset'))
        db.add(Audit(actor=str(account.id), action='portal.email.verified', at=now))
        db.commit()


@router.post('/password/reset', status_code=204)
def reset_password(body: ResetBody, request: Request):
    state = request.app.state.portal_auth
    now = state.now()
    with Session(request.app.state.engine) as db:
        begin_write(db)
        proof, account = valid_proof(db, body, 'reset', now)
        account.password_hash = state.hasher.hash(body.password.get_secret_value())
        account.password_revision += 1
        account_id = account.id
        # Invalidate all outstanding recovery/binding proofs and short-lived logins.
        # Stable cabinet links and client tokens deliberately remain untouched.
        db.execute(delete(EmailProof).where(EmailProof.account_id == account.id))
        db.execute(delete(MagicLogin).where(MagicLogin.account_id == account.id))
        db.add(Audit(actor=str(account.id), action='portal.password.reset', at=now))
        db.commit()
    state.revoke(account_id)
