"""Subscription discovery for native VPN clients, without Telegram.

A subscriber authenticates with the long-lived cabinet link token (the same
credential the bot hands out once). The token is never sent in a URL and is
never stored by the app in clear text: Vell Client keeps it in the OS keychain
and repeats this call to discover newly added devices. Device subscription
tokens are minted idempotently, so rotation and deletion stay the only ways
to revoke access.
"""
import secrets
import uuid
from hashlib import sha256

from fastapi import APIRouter, Depends, Request
from pydantic import ConfigDict, Field, SecretStr
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError
from vs_router.schema import Model

from .accounts import LOGIN_WINDOW, get_db, portal_link_token
from .models import (Account, Audit, ClientInvite, Device, DeviceSubscription, PortalLink,
                     Subscription, Tariff)
from .subscriptions_api import _store, _token_of, _view

router = APIRouter(prefix='/api/client')


class LinkProof(Model):
    model_config = ConfigDict(extra='forbid')
    token: SecretStr = Field(min_length=1, max_length=128)


class RegisterBody(Model):
    model_config = ConfigDict(extra='forbid')
    code: SecretStr | None = Field(default=None, min_length=8, max_length=128)
    display_name: str = Field(min_length=1, max_length=64)


@router.post('/register')
def register_client(body: RegisterBody, request: Request,
                    db: Session = Depends(get_db)):
    """Создать аккаунт абонента без Telegram и без администратора.

    Код приглашения необязателен: он остаётся для онбординга по команде
    администратора, но обычная регистрация открыта и защищена rate limit.
    Тариф не выдаётся — его назначают отдельно.
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
                          status='active', created_at=now)
        db.add(account)
        db.flush()
        if invite is not None:
            invite.used_at = now
            invite.account_id = account.id
        db.add(Audit(actor='client', action='client.register', detail=str(account.id), at=now))
        db.commit()
        state.failures.pop(rate_key, None)

    token = portal_link_token(request.app.state.engine, account.id, now)
    return {'account': {'id': account.id, 'display_name': account.display_name},
            'token': token,
            # Тариф администратор назначает отдельно: регистрация не даёт доступ.
            'subscription': {'status': 'inactive'}}


def _entitlement(db, account_id, now):
    sub = db.scalar(select(Subscription).where(
        Subscription.account_id == account_id).order_by(Subscription.id.desc()))
    if sub is None:
        # Клиент всегда ожидает объект subscription; без тарифа это inactive.
        return {'status': 'inactive', 'expires_at': None, 'tariff': None}, False
    tariff = db.get(Tariff, sub.tariff_id)
    active = (sub.status == 'active' and sub.expires_at > now and tariff is not None)
    return {'status': 'active' if active else 'expired',
            'expires_at': sub.expires_at,
            'tariff': {'name': tariff.name, 'device_limit': tariff.device_limit}
            if tariff is not None else None}, active


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
