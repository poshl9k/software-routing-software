"""Subscription discovery for native VPN clients, without Telegram.

A subscriber authenticates with the long-lived cabinet link token (the same
credential the bot hands out once). The token is never sent in a URL and is
never stored by the app in clear text: Vell Client keeps it in the OS keychain
and repeats this call to discover newly added devices. Device subscription
tokens are minted idempotently, so rotation and deletion stay the only ways
to revoke access.
"""
import base64
import secrets
import uuid
from datetime import timedelta
from hashlib import sha256

from fastapi import APIRouter, Depends, Request
from pydantic import ConfigDict, Field, SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError
from vs_router.schema import Model

from .accounts import LOGIN_WINDOW, get_db, portal_link_token
from .models import (Account, Audit, ClientChallenge, ClientInvite, Device, DeviceSubscription,
                     PortalLink, Setting, Subscription, Tariff, TrafficUsage)
from .subscriptions_api import _store, _token_of, _view

router = APIRouter(prefix='/api/client')


class LinkProof(Model):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=1, max_length=128)


CHALLENGE_TTL = 300
DIFFICULTY = 20
MAX_REGISTRATIONS_PER_DAY = 3


class RegisterBody(Model):
    model_config = ConfigDict(extra='forbid')
    code: SecretStr | None = Field(default=None, min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=64)
    challenge: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=1, max_length=64)


def _leading_zero_bits(digest: bytes) -> int:
    zeros = 0
    for byte in digest:
        if byte:
            return zeros + 8 - byte.bit_length()
        zeros += 8
    return zeros


def _proof_ok(raw: bytes, nonce: str, difficulty: int) -> bool:
    if len(raw) < 16 or len(raw) > 96 or any(ord(c) < 32 for c in nonce):
        return False
    return _leading_zero_bits(sha256(raw + nonce.encode()).digest()) >= difficulty


@router.get('/register/challenge')
def register_challenge(request: Request, db: Session = Depends(get_db)):
    """Одноразовый вызов proof-of-work для открытой регистрации."""
    raw = secrets.token_bytes(24)
    now = request.app.state.portal_auth.now()
    db.add(ClientChallenge(token_hash=sha256(raw).hexdigest(), difficulty=DIFFICULTY,
                           created_at=now, expires_at=now + timedelta(seconds=CHALLENGE_TTL)))
    db.commit()
    return {'challenge': base64.urlsafe_b64encode(raw).decode().rstrip('='),
            'difficulty': DIFFICULTY,
            'expires_at': now + timedelta(seconds=CHALLENGE_TTL)}


@router.post('/register')
def register_client(body: RegisterBody, request: Request,
                    db: Session = Depends(get_db)):
    """Создать аккаунт абонента без Telegram и без администратора.

    Защита от массовых аккаунтов: одноразовый proof-of-work вызов, не более
    трёх регистраций с одного адреса в сутки и общий rate limit. Демо-тариф
    выдаётся автоматически; платный тариф подключается отдельно.
    """
    state = request.app.state.portal_auth
    address = request.client.host if request.client else 'unknown'
    rate_key = ('client_register', address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(rate_key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, 'auth.rate_limited')
        now = state.now()
        name = body.display_name.strip()
        if not name:
            raise APIError(422, 'client.display_name_required')
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))

        try:
            raw = base64.urlsafe_b64decode(body.challenge + '=' * (-len(body.challenge) % 4))
        except (ValueError, TypeError):
            db.rollback()
            state.failures[rate_key] = (count + 1, deadline)
            raise APIError(400, 'client.pow_invalid') from None
        challenge = db.get(ClientChallenge, sha256(raw).hexdigest())
        if (challenge is None or challenge.used_at is not None or challenge.expires_at <= now
                or not _proof_ok(raw, body.nonce, challenge.difficulty)):
            # Вызов сжигается и при неудачном proof: перебор не переиспользует его.
            if challenge is not None and challenge.used_at is None:
                challenge.used_at = now
            db.commit()
            state.failures[rate_key] = (count + 1, deadline)
            raise APIError(400, 'client.pow_invalid')

        daily = db.scalar(select(func.count(Account.id)).where(
            Account.registration_ip == address,
            Account.created_at >= now - timedelta(days=1),
            Account.telegram_chat_id.like('client:%')))
        if (daily or 0) >= MAX_REGISTRATIONS_PER_DAY:
            db.rollback()
            raise APIError(429, 'client.registration_limit')

        invite = None
        if body.code is not None:
            digest = sha256(body.code.get_secret_value().encode()).hexdigest()
            invite = db.get(ClientInvite, digest)
            if (invite is None or invite.used_at is not None or invite.expires_at <= now):
                db.rollback()
                state.failures[rate_key] = (count + 1, deadline)
                raise APIError(400, 'client.invite_invalid')

        # Идентификатор из Telegram-бота здесь недоступен: уникальный синтетический.
        account = Account(display_name=name[:64], telegram_chat_id=f'client:{uuid.uuid4().hex}',
                          telegram_linked_at=None, telegram_linked_chat_id=None,
                          password_hash=state.hasher.hash(secrets.token_urlsafe(32)),
                          status='active', created_at=now, registration_ip=address[:64])
        db.add(account)
        db.flush()
        challenge.used_at = now
        if invite is not None:
            invite.used_at = now
            invite.account_id = account.id
        subscription_view = {'status': 'inactive'}
        demo = db.scalar(select(Tariff).where(Tariff.name == 'Demo'))
        if demo is not None:
            expires = now + timedelta(days=demo.term_days)
            db.add(Subscription(account_id=account.id, tariff_id=demo.id, expires_at=expires,
                                status='active', updated_at=now))
            subscription_view = {'status': 'active', 'expires_at': expires,
                                 'tariff': {'name': demo.name,
                                            'daily_traffic_limit_mb': demo.daily_traffic_limit_mb}}
        db.add(Audit(actor='client', action='client.register', detail=str(account.id), at=now))
        db.commit()
        state.failures.pop(rate_key, None)

    token = portal_link_token(request.app.state.engine, account.id, now)
    return {'account': {'id': account.id, 'display_name': account.display_name},
            'token': token, 'subscription': subscription_view}


@router.post('/checkout')
def client_checkout(body: LinkProof, request: Request, db: Session = Depends(get_db)):
    """Return the configured external checkout URL for a verified subscriber."""
    digest = sha256(body.token.get_secret_value().encode()).hexdigest()
    row = db.scalar(select(DeviceSubscription).where(DeviceSubscription.token_hash == digest))
    if row is None:
        raise APIError(404, 'portal.subscription_link_invalid')
    device = db.get(Device, row.device_id)
    if device is None or device.status == 'removed':
        raise APIError(404, 'portal.subscription_link_invalid')
    checkout = db.get(Setting, 'payment_checkout_url')
    if checkout is None or not checkout.value:
        raise APIError(404, 'payment.not_configured')
    provider = db.get(Setting, 'payment_provider_name')
    return {'checkout_url': checkout.value,
            'provider': provider.value if provider is not None else None}


def _entitlement(db, account_id, now):
    sub = db.scalar(select(Subscription).where(
        Subscription.account_id == account_id).order_by(Subscription.id.desc()))
    if sub is None:
        # Клиент всегда ожидает объект subscription; без тарифа это inactive.
        return {'status': 'inactive', 'expires_at': None, 'tariff': None}, False
    tariff = db.get(Tariff, sub.tariff_id)
    active = (sub.status == 'active' and sub.expires_at > now and tariff is not None)
    used = db.scalar(select(func.coalesce(func.sum(TrafficUsage.bytes), 0)).where(
        TrafficUsage.account_id == account_id, TrafficUsage.day == now.date())) or 0
    limit_mb = tariff.daily_traffic_limit_mb if tariff is not None else None
    status = 'active' if active else 'expired'
    if active and limit_mb is not None and used >= limit_mb * 1024 * 1024:
        status = 'limit'
    return {'status': status,
            'expires_at': sub.expires_at,
            'daily': {'used_bytes': int(used), 'limit_mb': limit_mb},
            'tariff': {'name': tariff.name, 'device_limit': tariff.device_limit}
            if tariff is not None else None}, active and status == 'active'


@router.post('/subscriptions')
def client_subscriptions(body: LinkProof, request: Request,
                         db: Session = Depends(get_db)):
    """Exchange a cabinet link token for per-device native subscription URLs."""
    state = request.app.state.portal_auth
    address = request.client.host if request.client else 'unknown'
    rate_key = ('client_link', address)
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(rate_key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, 'auth.rate_limited')
        digest = sha256(body.token.get_secret_value().encode()).hexdigest()
        row = db.scalar(select(PortalLink).where(PortalLink.token_hash == digest))
        account = db.get(Account, row.account_id) if row is not None else None
        if row is None or account is None or account.status != 'active':
            state.failures[rate_key] = (count + 1, deadline)
            raise APIError(401, 'auth.invalid_credentials')
        now = state.now()
        row.last_used_at = now
        entitlement, active = _entitlement(db, account.id, now)
        db.commit()
        state.failures.pop(rate_key, None)

    profiles = []
    if active:
        devices = db.scalars(select(Device).where(
            Device.account_id == account.id, Device.status != 'removed').order_by(Device.id))
        for device in devices:
            token_row = db.get(DeviceSubscription, device.id)
            if token_row is None or _token_of(token_row) is None:
                token_row = _store(db, token_row, device, now)
            view = _view(request, db, token_row)
            profiles.append({
                'device_id': device.id,
                'label': device.label,
                'device_name': device.name,
                'status': device.status,
                # The native client always wants a wg-quick .conf; the other
                # URLs are returned so one discovery call covers every client.
                'url': view['conf_url'],
                'qr': view['qr'],
                'amnezia_url': view['amnezia_url'],
                'mihomo_url': view['url'],
                'singbox_url': view['singbox_url'],
            })
    return {'account': {'id': account.id, 'display_name': account.display_name},
            'subscription': entitlement,
            'profiles': profiles}
