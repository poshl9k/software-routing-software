"""Subscriber mail: encrypted transactional outbox, sent by worker_main.

SMTP is at-least-once: a lost acknowledgement may resend the same one-use link.
Only a configured HTTPS public origin is used; request Host is never consulted.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import ipaddress
import logging
import os
import re
import secrets
import smtplib
import ssl
from urllib.parse import urlsplit

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.secrets import decrypt_secret
from .models import Account, EmailOutbox, EmailProof, EmailRateLimit

logger = logging.getLogger(__name__)
EMAIL_TTL = timedelta(minutes=30)
EMAIL_VERIFY_PATH = '/portal/email/confirm'
EMAIL_RESET_PATH = '/portal/password/reset'


def normalize_email(value: str) -> str:
    """Conservative ASCII mailbox contract, case-insensitive account identity."""
    value = value.strip().lower()
    if (len(value) > 254 or not re.fullmatch(
            r"[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[a-z0-9.-]+", value)):
        raise ValueError('invalid email address')
    local, domain = value.rsplit('@', 1)
    if (local.startswith('.') or local.endswith('.') or '..' in local
            or '.' not in domain or not valid_hostname(domain)):
        raise ValueError('invalid email address')
    return value


def valid_hostname(host: str) -> bool:
    return len(host) <= 253 and all(re.fullmatch(
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
        for label in host.split('.'))


@dataclass(frozen=True)
class MailConfig:
    origin: str
    host: str
    port: int
    sender: str
    security: str
    username: str | None = field(repr=False)
    password: str | None = field(repr=False)


def load_config() -> MailConfig:
    """Fail closed before account lookup, including an unavailable encryption key."""
    origin = os.environ.get('VS_MASTER_PUBLIC_URL', '')
    if any(char.isspace() or ord(char) < 32 for char in origin) or '\\' in origin:
        raise ValueError('invalid public origin')
    parsed = urlsplit(origin)
    host = parsed.hostname
    if (parsed.scheme != 'https' or not host or parsed.username is not None
            or parsed.password is not None or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment or '?' in origin or '#' in origin
            or not valid_hostname(host) or host == 'localhost' or host.endswith('.localhost')):
        raise ValueError('invalid public origin')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('invalid public port')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if '.' not in host:
            raise ValueError('public origin requires a qualified hostname') from None
    else:
        if not address.is_global:
            raise ValueError('public origin requires a public address')
    smtp_host = os.environ.get('VS_MASTER_SMTP_HOST', '')
    if not valid_hostname(smtp_host):
        raise ValueError('SMTP host required')
    security = os.environ.get('VS_MASTER_SMTP_SECURITY', 'starttls')
    if security not in ('starttls', 'tls'):
        raise ValueError('SMTP requires TLS')
    port = int(os.environ.get('VS_MASTER_SMTP_PORT', '465' if security == 'tls' else '587'))
    if not 1 <= port <= 65535:
        raise ValueError('invalid SMTP port')
    sender = normalize_email(os.environ.get('VS_MASTER_SMTP_FROM', ''))
    username = os.environ.get('VS_MASTER_SMTP_USERNAME')
    password = os.environ.get('VS_MASTER_SMTP_PASSWORD')
    if bool(username) != bool(password):
        raise ValueError('SMTP credentials must be supplied together')
    get_secret_key()
    return MailConfig(origin.rstrip('/'), smtp_host, port, sender, security, username, password)


def begin_write(db: Session):
    if db.get_bind().dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))


def send_mail(config: MailConfig, recipient: str, body: str):
    message = EmailMessage()
    message['From'] = config.sender
    message['To'] = recipient
    message['Subject'] = 'VS Portal account security'
    message.set_content(body)
    context = ssl.create_default_context()
    if config.security == 'tls':
        connection = smtplib.SMTP_SSL(config.host, config.port, timeout=20, context=context)
    else:
        connection = smtplib.SMTP(config.host, config.port, timeout=20)
    with connection as smtp:
        if config.security == 'starttls':
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        if config.username:
            smtp.login(config.username, config.password)
        # SMTP debug output is deliberately never enabled (credentials and URLs).
        if smtp.send_message(message):
            raise RuntimeError('SMTP recipient refused')


def process_email_outbox(engine, *, now=None, limit=20):
    """Claim briefly, send outside SQLite lock, then compare the lease to ack.

    A crash leaves a two-minute lease. Retry delay is capped at five minutes;
    expired/rotated/consumed/disabled proofs are suppressed instead of delivered.
    """
    try:
        config = load_config()
    except Exception:
        # Disabled/unconfigured mail must not interfere with other worker jobs.
        return
    current = lambda: now if now is not None else datetime.now(timezone.utc)
    with Session(engine) as db:
        begin_write(db)
        db.execute(delete(EmailProof).where(EmailProof.expires_at <= current()))
        db.execute(delete(EmailRateLimit).where(EmailRateLimit.expires_at <= current()))
        db.commit()
    for _ in range(limit):
        timestamp = current()
        with Session(engine) as db:
            begin_write(db)
            row = db.scalar(select(EmailOutbox).where(
                EmailOutbox.status == 'pending', EmailOutbox.next_attempt_at <= timestamp
            ).order_by(EmailOutbox.next_attempt_at, EmailOutbox.token_hash).limit(1).with_for_update())
            if row is None:
                return
            proof = db.get(EmailProof, row.token_hash)
            account = db.get(Account, proof.account_id) if proof else None
            if (proof is None or account is None or account.status != 'active'
                    or proof.consumed_at is not None or proof.expires_at <= timestamp
                    or proof.password_revision != account.password_revision
                    or (proof.kind == 'reset' and account.email != proof.email)):
                row.status, row.body_secret = 'suppressed', None
                db.commit()
                continue
            claim = secrets.token_hex(16)
            row.claim_token = claim
            row.attempts += 1
            row.next_attempt_at = timestamp + timedelta(minutes=2)
            digest, recipient, secret, attempt = row.token_hash, proof.email, row.body_secret, row.attempts
            db.commit()
        try:
            body = decrypt_secret(secret, get_secret_key())
            send_mail(config, recipient, body)
            delivered = True
        except Exception as exc:
            # Never log exception messages: SMTP responses can contain recipients/tokens.
            logger.warning('Subscriber mail delivery failed (%s)', type(exc).__name__)
            delivered = False
        with Session(engine) as db:
            begin_write(db)
            row = db.get(EmailOutbox, digest)
            if row is None or row.claim_token != claim:
                continue
            row.claim_token = None
            if delivered:
                row.status, row.body_secret, row.delivered_at = 'delivered', None, current()
            else:
                row.next_attempt_at = current() + timedelta(seconds=min(300, 30 * 2 ** min(attempt, 4)))
            db.commit()
