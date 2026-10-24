"""Authenticated administrator API for the master-owned subscriber database."""
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, field_validator, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.schema import Model
from vs_router.secrets import decrypt_secret, encrypt_secret

from .auth import current_admin
from .bridge import BridgeClient, BridgeError
from .models import Account, Audit, Device, Node, Subscription, Tariff

router = APIRouter(prefix='/api/master-admin', dependencies=[Depends(current_admin)])


def get_db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def utc(value=None):
    value = value or datetime.now(timezone.utc)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def now(request):
    return utc(request.app.state.auth.now())


def aware(value):
    return utc(value) if value is not None else None


def begin_write(db):
    if db.bind.dialect.name == 'sqlite':
        db.execute(text('BEGIN IMMEDIATE'))


def audit(db, action, detail, at):
    db.add(Audit(actor='admin', action=action, detail=detail, at=at))


def _valid_bridge_url(value):
    parsed = urlsplit(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc or len(value) > 255:
        raise ValueError('master.node_url_invalid')
    return value


class TariffBody(Model):
    name: str = Field(min_length=1, max_length=128)
    device_limit: int = Field(ge=1)
    term_days: int = Field(ge=1, le=36500)
    price_amount: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class TariffPatch(Model):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    device_limit: int | None = Field(default=None, ge=1)
    term_days: int | None = Field(default=None, ge=1, le=36500)
    price_amount: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class NodeBody(Model):
    name: str = Field(min_length=1, max_length=64)
    bridge_url: str = Field(min_length=1, max_length=255)
    capacity: int = Field(ge=1)

    @field_validator('bridge_url')
    @classmethod
    def bridge_url_valid(cls, value):
        return _valid_bridge_url(value)


class NodePatch(Model):
    bridge_url: str | None = Field(default=None, min_length=1, max_length=255)
    capacity: int | None = Field(default=None, ge=1)
    enabled: bool | None = None

    @field_validator('bridge_url')
    @classmethod
    def bridge_url_valid(cls, value):
        return _valid_bridge_url(value) if value is not None else value


class SubscriptionBody(Model):
    tariff_id: int = Field(ge=1)
    days: int | None = Field(default=None, ge=1, le=36500)
    expires_at: datetime | None = None

    @model_validator(mode='after')
    def one_expiry(self):
        if (self.days is None) == (self.expires_at is None):
            raise ValueError('master.subscription_expiry_required')
        return self


def tariff_view(row):
    return {'id': row.id, 'name': row.name, 'device_limit': row.device_limit,
            'term_days': row.term_days,
            'price_amount': float(row.price_amount) if row.price_amount is not None else None,
            'created_at': aware(row.created_at)}


def node_view(row):
    return {'id': row.id, 'name': row.name, 'bridge_url': row.bridge_url,
            'capacity': row.capacity, 'enabled': row.enabled, 'state': row.state,
            'active_peers': row.active_peers, 'last_seen': aware(row.last_seen)}


def get_tariff(db, tariff_id):
    row = db.get(Tariff, tariff_id)
    if row is None:
        raise APIError(404, 'master.tariff_not_found')
    return row


def get_node(db, node_id):
    row = db.get(Node, node_id)
    if row is None:
        raise APIError(404, 'master.node_not_found')
    return row


def get_account(db, account_id):
    row = db.get(Account, account_id)
    if row is None:
        raise APIError(404, 'master.subscriber_not_found')
    return row


def commit_unique(db, code):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, code) from None


@router.get('/tariffs')
def list_tariffs(db: Session = Depends(get_db)):
    return [tariff_view(row) for row in db.scalars(select(Tariff).order_by(Tariff.id))]


@router.get('/tariffs/{tariff_id}')
def read_tariff(tariff_id: int, db: Session = Depends(get_db)):
    return tariff_view(get_tariff(db, tariff_id))


@router.post('/tariffs', status_code=201)
def create_tariff(body: TariffBody, request: Request, db: Session = Depends(get_db)):
    values = body.model_dump()
    values['price_amount'] = str(values['price_amount']) if values['price_amount'] is not None else None
    row = Tariff(**values, created_at=now(request))
    db.add(row)
    audit(db, 'tariff.create', body.name, now(request))
    commit_unique(db, 'master.tariff_exists')
    return tariff_view(row)


@router.put('/tariffs/{tariff_id}')
def replace_tariff(tariff_id: int, body: TariffBody, request: Request,
                   db: Session = Depends(get_db)):
    begin_write(db)
    row = get_tariff(db, tariff_id)
    values = body.model_dump()
    values['price_amount'] = str(values['price_amount']) if values['price_amount'] is not None else None
    for key, value in values.items():
        setattr(row, key, value)
    audit(db, 'tariff.update', str(tariff_id), now(request))
    commit_unique(db, 'master.tariff_exists')
    return tariff_view(row)


@router.patch('/tariffs/{tariff_id}')
def update_tariff(tariff_id: int, body: TariffPatch, request: Request,
                  db: Session = Depends(get_db)):
    values = body.model_dump(exclude_unset=True)
    if any(value is None and key != 'price_amount' for key, value in values.items()):
        raise APIError(422, 'request.invalid')
    begin_write(db)
    row = get_tariff(db, tariff_id)
    if 'price_amount' in values and values['price_amount'] is not None:
        values['price_amount'] = str(values['price_amount'])
    for key, value in values.items():
        setattr(row, key, value)
    audit(db, 'tariff.update', str(tariff_id), now(request))
    commit_unique(db, 'master.tariff_exists')
    return tariff_view(row)


@router.delete('/tariffs/{tariff_id}', status_code=204)
def delete_tariff(tariff_id: int, request: Request, db: Session = Depends(get_db)):
    begin_write(db)
    row = get_tariff(db, tariff_id)
    if db.scalar(select(Subscription.id).where(Subscription.tariff_id == tariff_id)) is not None:
        raise APIError(409, 'master.tariff_in_use')
    db.delete(row)
    audit(db, 'tariff.delete', str(tariff_id), now(request))
    db.commit()
    return Response(status_code=204)


@router.get('/nodes')
def list_nodes(db: Session = Depends(get_db)):
    return [node_view(row) for row in db.scalars(select(Node).order_by(Node.id))]


@router.post('/nodes', status_code=201)
def create_node(body: NodeBody, request: Request, db: Session = Depends(get_db)):
    token = secrets.token_urlsafe(32)
    row = Node(**body.model_dump(), bridge_token=encrypt_secret(token, get_secret_key()),
               enabled=True, state='down', active_peers=0, created_at=now(request))
    db.add(row)
    audit(db, 'node.create', body.name, now(request))
    commit_unique(db, 'master.node_exists')
    return {**node_view(row), 'token': token}


@router.patch('/nodes/{node_id}')
def update_node(node_id: int, body: NodePatch, request: Request,
                db: Session = Depends(get_db)):
    values = body.model_dump(exclude_unset=True)
    if not values or any(value is None for value in values.values()):
        raise APIError(422, 'request.invalid')
    begin_write(db)
    row = get_node(db, node_id)
    for key, value in values.items():
        setattr(row, key, value)
    audit(db, 'node.update', str(node_id), now(request))
    db.commit()
    return node_view(row)


@router.delete('/nodes/{node_id}', status_code=204)
def delete_node(node_id: int, request: Request, db: Session = Depends(get_db)):
    begin_write(db)
    row = get_node(db, node_id)
    if db.scalar(select(Device.id).where(Device.node_id == node_id)) is not None:
        raise APIError(409, 'master.node_in_use')
    db.delete(row)
    audit(db, 'node.delete', str(node_id), now(request))
    db.commit()
    return Response(status_code=204)


@router.post('/nodes/{node_id}/rotate-token')
def rotate_node_token(node_id: int, request: Request, db: Session = Depends(get_db)):
    begin_write(db)
    row = get_node(db, node_id)
    key = get_secret_key()
    try:
        current = decrypt_secret(row.bridge_token, key)
    except (InvalidToken, ValueError):
        db.rollback()
        raise APIError(503, 'secret.decryption_failed') from None
    proposed = secrets.token_urlsafe(32)
    try:
        result = BridgeClient(row.bridge_url, current).rotate(proposed)
    except BridgeError as exc:
        db.rollback()
        if exc.status in (401, 403):
            raise APIError(409, 'master.node_token_revoked') from None
        if exc.status == 503:
            raise APIError(503, 'node.unreachable') from None
        status = exc.status if 400 <= exc.status <= 599 else 502
        raise APIError(status, exc.code or 'node.operation_failed') from None
    row.bridge_token = encrypt_secret(proposed, key)
    audit(db, 'node.rotate_token', str(node_id), now(request))
    db.commit()
    return {'rotated': bool(result.get('rotated')) if isinstance(result, dict) else False}


def subscription_view(row, tariff):
    return {'tariff_id': row.tariff_id, 'tariff_name': tariff.name if tariff else None,
            'expires_at': aware(row.expires_at), 'status': row.status,
            'updated_at': aware(row.updated_at)}


def _subscription(db, account_id):
    return db.scalar(select(Subscription).where(Subscription.account_id == account_id)
                     .order_by(Subscription.id))


def subscriber_view(db, account, *, devices=False):
    subscription = _subscription(db, account.id)
    tariff = db.get(Tariff, subscription.tariff_id) if subscription is not None else None
    device_count = db.scalar(select(func.count(Device.id)).where(
        Device.account_id == account.id, Device.status != 'removed')) or 0
    result = {'id': account.id, 'display_name': account.display_name,
              'telegram_chat_id': account.telegram_chat_id, 'status': account.status,
              'created_at': aware(account.created_at), 'device_count': device_count,
              'subscription': subscription_view(subscription, tariff)
              if subscription is not None else None}
    if devices:
        rows = db.execute(select(Device, Node.name).outerjoin(Node, Device.node_id == Node.id).where(
            Device.account_id == account.id).order_by(Device.id))
        result['devices'] = [
            {'id': device.id, 'label': device.label, 'name': device.name,
             'node_name': node_name, 'status': device.status,
             'allowed_ips': list(device.allowed_ips)}
            for device, node_name in rows
        ]
    return result


@router.get('/subscribers')
def list_subscribers(db: Session = Depends(get_db)):
    return [subscriber_view(db, row) for row in db.scalars(select(Account).order_by(Account.id))]


@router.get('/subscribers/{account_id}')
def read_subscriber(account_id: int, db: Session = Depends(get_db)):
    return subscriber_view(db, get_account(db, account_id), devices=True)


@router.put('/subscribers/{account_id}/subscription')
def put_subscription(account_id: int, body: SubscriptionBody, request: Request,
                     db: Session = Depends(get_db)):
    begin_write(db)
    get_account(db, account_id)
    tariff = get_tariff(db, body.tariff_id)
    row = _subscription(db, account_id)
    timestamp = now(request)
    if row is None:
        expiry = timestamp + timedelta(days=body.days) if body.days is not None \
            else aware(body.expires_at)
        row = Subscription(account_id=account_id, tariff_id=tariff.id,
                           expires_at=expiry, status='active', updated_at=timestamp)
        db.add(row)
        action = 'subscription.create'
    else:
        try:
            row.expires_at = aware(row.expires_at) + timedelta(days=body.days) \
                if body.days is not None else aware(body.expires_at)
        except OverflowError:
            raise APIError(422, 'master.subscription_term_invalid') from None
        row.tariff_id = tariff.id
        row.status = 'active'
        row.updated_at = timestamp
        action = 'subscription.renew' if body.days is not None else 'subscription.update'
    audit(db, action, str(account_id), timestamp)
    db.commit()
    return subscription_view(row, tariff)
