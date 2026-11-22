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
from datetime import date, timedelta
from hashlib import sha256

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import ConfigDict, Field, SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.schema import Model
from vs_router.secrets import decrypt_secret, encrypt_secret

from .accounts import LOGIN_WINDOW, get_db, portal_link_token
from .device_service import create_device as create_device_record
from .models import (Account, Audit, ClientChallenge, ClientInvite, ClientShare, Device,
                     DeviceSubscription, PortalLink, RegistrationDevice, ScopedLink, Setting,
                     Subscription, Tariff, TrafficUsage)
from .portal_api import _context
from .subscriptions_api import _store, _token_of, _view

router = APIRouter(prefix='/api/client')


class LinkProof(Model):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=1, max_length=128)


class JoinBody(Model):
    model_config = ConfigDict(extra='forbid')
    code: SecretStr = Field(min_length=8, max_length=128)
    label: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=16, max_length=128,
                           pattern=r'^[0-9a-fA-F]{16,128}$')


SHARE_TTL = timedelta(hours=24)
SHARE_MAX_USES = 5
DEMO_TARIFF = 'Demo'


def _resolve_link(db, token: str):
    """Return (account, scoped_link_or_None) for any native client credential."""
    digest = sha256(token.encode()).hexdigest()
    link = db.scalar(select(PortalLink).where(PortalLink.token_hash == digest))
    scoped = None
    if link is None:
        scoped = db.get(ScopedLink, digest)
        if scoped is None:
            raise APIError(401, 'auth.invalid_credentials')
        account = db.get(Account, scoped.account_id)
    else:
        account = db.get(Account, link.account_id)
    if account is None or account.status != 'active':
        raise APIError(401, 'auth.invalid_credentials')
    return account, scoped


@router.post('/share')
def client_share(body: LinkProof, request: Request, db: Session = Depends(get_db)):
    """Issue a short-lived code for adding devices to a paid account."""
    account, scoped = _resolve_link(db, body.token.get_secret_value())
    if scoped is not None:
        raise APIError(403, 'client.share_not_allowed')
    entitlement, active = _entitlement(db, account.id, request.app.state.portal_auth.now())
    if not active or (entitlement['tariff'] or {}).get('name') == DEMO_TARIFF:
        raise APIError(403, 'client.share_not_allowed')
    raw = secrets.token_urlsafe(18)
    now = request.app.state.portal_auth.now()
    db.add(ClientShare(account_id=account.id, token_hash=sha256(raw.encode()).hexdigest(),
                       token_secret=encrypt_secret(raw, get_secret_key()),
                       max_uses=SHARE_MAX_USES, used_count=0,
                       expires_at=now + SHARE_TTL, created_at=now))
    db.add(Audit(actor='client', action='client.share', detail=str(account.id), at=now))
    db.commit()
    return {'code': raw, 'expires_at': (now + SHARE_TTL).isoformat(),
            'max_devices': SHARE_MAX_USES, 'used': 0}


@router.post('/join')
def client_join(body: JoinBody, request: Request, db: Session = Depends(get_db)):
    """Redeem a share code: one fresh peer and one device-scoped token."""
    now = request.app.state.portal_auth.now()
    digest = sha256(body.code.get_secret_value().encode()).hexdigest()
    share = db.scalar(select(ClientShare).where(ClientShare.token_hash == digest))
    if share is None or share.expires_at <= now or share.used_count >= share.max_uses:
        raise APIError(400, 'client.share_invalid')
    account = db.get(Account, share.account_id)
    if account is None or account.status != 'active':
        raise APIError(400, 'client.share_invalid')
    entitlement, active = _entitlement(db, account.id, now)
    if not active:
        raise APIError(403, 'client.subscription_inactive')
    result = create_device_record(db, account, body.label, **_context(request))
    device_id = result.get('device_id')
    if device_id is None:
        raise APIError(409, 'portal.device_limit')
    device = db.get(Device, device_id)
    if device is None:
        raise APIError(409, 'portal.device_limit')
    device.client_fingerprint = body.device_id
    raw = secrets.token_urlsafe(32)
    db.add(ScopedLink(token_hash=sha256(raw.encode()).hexdigest(), account_id=account.id,
                      device_id=device.id, device_fingerprint=body.device_id,
                      token_secret=encrypt_secret(raw, get_secret_key()), created_at=now))
    share.used_count += 1
    db.add(Audit(actor='client', action='client.join', detail=str(device.id), at=now))
    db.commit()
    return {'token': raw, 'device_id': device.id, 'status': result.get('status', 'pending')}


CHALLENGE_TTL = 300
DIFFICULTY = 20
MAX_REGISTRATIONS_PER_DAY = 3


class RegisterBody(Model):
    model_config = ConfigDict(extra='forbid')
    code: SecretStr | None = Field(default=None, min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=64)
    challenge: str = Field(min_length=16, max_length=128)
    nonce: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=16, max_length=128,
                           pattern=r'^[0-9a-fA-F]{16,128}$')


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
    трёх регистраций с одного устройства в сутки (локальный ID хешируется
    серверным секретом; IP не используется) и общий rate limit. Демо-тариф
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

        device_hash = sha256(body.device_id.lower().encode() + get_secret_key()).hexdigest()
        device_row = db.scalar(select(RegistrationDevice).where(
            RegistrationDevice.device_hash == device_hash,
            RegistrationDevice.day == now.date()))
        if (device_row.count if device_row is not None else 0) >= MAX_REGISTRATIONS_PER_DAY:
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
        if device_row is None:
            db.add(RegistrationDevice(device_hash=device_hash, day=now.date(),
                                      count=1, updated_at=now))
        else:
            device_row.count += 1
            device_row.updated_at = now
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
    link = db.scalar(select(PortalLink).where(
        PortalLink.token_hash == sha256(token.encode()).hexdigest()))
    if link is not None:
        link.device_fingerprint = device_hash
        db.commit()
    return {'account': {'id': account.id, 'display_name': account.display_name},
            'token': token, 'subscription': subscription_view}


class DeviceBody(Model):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=128)


@router.post('/devices')
def client_create_device(body: DeviceBody, request: Request,
                         db: Session = Depends(get_db)):
    """Create a device for the account behind a cabinet token, no admin/bot."""
    account, scoped = _resolve_link(db, body.token.get_secret_value())
    if scoped is not None:
        raise APIError(403, 'client.share_not_allowed')
    result = create_device_record(db, account, body.label, **_context(request))
    return JSONResponse(result, status_code=202 if result.get('status') == 'pending' else 200)


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
    current_fingerprint = None
    with state.lock:
        state.prune()
        count, deadline = state.failures.get(rate_key, (0, state.tick() + LOGIN_WINDOW))
        if count >= 5:
            raise APIError(429, 'auth.rate_limited')
        account, scoped = _resolve_link(db, body.token.get_secret_value())
        now = state.now()
        if scoped is not None:
            scoped.last_used_at = now
            current_fingerprint = scoped.device_fingerprint
        else:
            link = db.scalar(select(PortalLink).where(
                PortalLink.token_hash == sha256(body.token.get_secret_value().encode()).hexdigest()))
            if link is not None:
                link.last_used_at = now
                current_fingerprint = link.device_fingerprint
        entitlement, active = _entitlement(db, account.id, now)
        db.commit()
        state.failures.pop(rate_key, None)

    profiles = []
    if active:
        devices = db.scalars(select(Device).where(
            Device.account_id == account.id, Device.status != 'removed').order_by(Device.id))
        if scoped is not None:
            devices = db.scalars(select(Device).where(
                Device.id == scoped.device_id, Device.status != 'removed'))
        for device in devices:
            token_row = db.get(DeviceSubscription, device.id)
            if token_row is None or _token_of(token_row) is None:
                token_row = _store(db, token_row, device, now)
            view = _view(request, db, token_row)
            used_elsewhere = bool(device.client_fingerprint and current_fingerprint
                                  and device.client_fingerprint != current_fingerprint)
            profiles.append({
                'device_id': device.id,
                'label': device.label,
                'device_name': device.name,
                'status': device.status,
                'in_use': used_elsewhere,
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
            'share': {'allowed': bool(active and (entitlement['tariff'] or {}).get('name')
                                     != DEMO_TARIFF)},
            'profiles': profiles}
