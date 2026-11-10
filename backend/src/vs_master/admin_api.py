"""Authenticated administrator API for the master-owned subscriber database."""
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from argon2 import PasswordHasher, Type
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, SecretStr, StrictStr, field_validator, model_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.schema import Model
from vs_router.secrets import decrypt_secret, encrypt_secret

from . import ruleset_import, rulesets
from .auth import current_admin
from .bridge import BridgeClient, BridgeError
from .models import (Account, Audit, Device, Node, RuleSet, RuleSetSource, Setting, Subscription,
                     Tariff)
from .notifications import enqueue_subscription

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
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment or len(value) > 255):
        raise ValueError('master.node_url_invalid')
    try:
        parsed.port
    except ValueError:
        raise ValueError('master.node_url_invalid') from None
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
    role: StrictStr = 'both'
    public_entry: str | None = Field(default=None, max_length=255)

    @field_validator('bridge_url')
    @classmethod
    def bridge_url_valid(cls, value):
        return _valid_bridge_url(value)

    @field_validator('role')
    @classmethod
    def role_valid(cls, value):
        return _valid_role(value)

    @field_validator('public_entry')
    @classmethod
    def public_entry_valid(cls, value):
        return _valid_public_entry(value)


class NodePatch(Model):
    bridge_url: str | None = Field(default=None, min_length=1, max_length=255)
    capacity: int | None = Field(default=None, ge=1)
    enabled: bool | None = None
    role: StrictStr | None = None
    public_entry: str | None = Field(default=None, max_length=255)

    @field_validator('bridge_url')
    @classmethod
    def bridge_url_valid(cls, value):
        return _valid_bridge_url(value) if value is not None else value

    @field_validator('role')
    @classmethod
    def role_valid(cls, value):
        return _valid_role(value) if value is not None else value

    @field_validator('public_entry')
    @classmethod
    def public_entry_valid(cls, value):
        return _valid_public_entry(value) if value is not None else value


class SubscriptionBody(Model):
    tariff_id: int = Field(ge=1)
    days: int | None = Field(default=None, ge=1, le=36500)
    expires_at: datetime | None = None

    @model_validator(mode='after')
    def one_expiry(self):
        if (self.days is None) == (self.expires_at is None):
            raise ValueError('master.subscription_expiry_required')
        return self


class SubscriberBody(Model):
    display_name: StrictStr = Field(min_length=1, max_length=64)
    telegram_chat_id: StrictStr = Field(pattern=r'^[1-9][0-9]{0,63}$')

    @field_validator('display_name')
    @classmethod
    def display_name_valid(cls, value):
        value = value.strip()
        if not value:
            raise ValueError('master.subscriber_name_required')
        return value


class TelegramSettingsBody(Model):
    bot_token: SecretStr = Field(min_length=20, max_length=96)
    public_url: str = Field(min_length=9, max_length=255)

    @field_validator('public_url')
    @classmethod
    def valid_public_url(cls, value):
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
            raise ValueError('master.public_url_invalid')
        try:
            _ = parsed.port
        except ValueError:
            raise ValueError('master.public_url_invalid') from None
        return value.rstrip('/')


@router.get('/settings/telegram')
def get_telegram_settings(db: Session = Depends(get_db)):
    token = db.get(Setting, 'master_bot_token')
    public = db.get(Setting, 'master_public_url')
    return {'configured': bool(token and token.value.startswith('enc:') and public and public.value),
            'public_url': public.value if public else None}


@router.put('/settings/telegram')
def put_telegram_settings(body: TelegramSettingsBody, request: Request,
                          db: Session = Depends(get_db)):
    begin_write(db)
    token = 'enc:' + encrypt_secret(body.bot_token.get_secret_value(), get_secret_key()).ciphertext
    if len(token) > 256:
        raise APIError(422, 'master.bot_token_invalid')
    for key, value in (('master_bot_token', token), ('master_public_url', body.public_url)):
        row = db.get(Setting, key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
    audit(db, 'master.bot.configure', None, now(request))
    db.commit()
    return {'configured': True, 'public_url': body.public_url}


def tariff_view(row):
    return {'id': row.id, 'name': row.name, 'device_limit': row.device_limit,
            'term_days': row.term_days,
            'price_amount': float(row.price_amount) if row.price_amount is not None else None,
            'created_at': aware(row.created_at)}


def _valid_role(value):
    if value not in ('entry', 'egress', 'both'):
        raise ValueError('master.node_role_invalid')
    return value


def _valid_public_entry(value):
    """Client-facing address: bare host or host:port, never a scheme or path."""
    if value is None:
        return None
    text = value.strip()
    if not text or len(text) > 255 or text != value:
        raise ValueError('master.node_entry_invalid')
    if '://' in text or '/' in text or ' ' in text:
        raise ValueError('master.node_entry_invalid')
    host, _, port = text.rpartition(':') if text.count(':') == 1 else (text, '', '')
    if text.startswith('['):
        host, _, rest = text.partition(']')
        host, port = host[1:], rest[1:] if rest.startswith(':') else ''
    if not host:
        raise ValueError('master.node_entry_invalid')
    if port and not (port.isdigit() and 1 <= int(port) <= 65535):
        raise ValueError('master.node_entry_invalid')
    return text


def node_view(row):
    return {'id': row.id, 'name': row.name, 'bridge_url': row.bridge_url,
            'capacity': row.capacity, 'enabled': row.enabled, 'state': row.state,
            'role': row.role, 'public_entry': row.public_entry,
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
    if (db.scalar(select(Device.id).where(Device.node_id == node_id)) is not None
            or db.scalar(select(Device.id).where(Device.egress_node_id == node_id)) is not None):
        raise APIError(409, 'master.node_in_use')
    db.delete(row)
    audit(db, 'node.delete', str(node_id), now(request))
    db.commit()
    return Response(status_code=204)


@router.post('/nodes/{node_id}/reissue-token')
def reissue_node_token(node_id: int, request: Request, db: Session = Depends(get_db)):
    """Replace a lost onboarding token only before the node has connected."""
    begin_write(db)
    row = get_node(db, node_id)
    has_devices = db.scalar(select(Device.id).where(Device.node_id == node_id)) is not None
    if row.last_seen is not None or has_devices:
        db.rollback()
        raise APIError(409, 'master.node_reissue_not_allowed')
    token = secrets.token_urlsafe(32)
    row.bridge_token = encrypt_secret(token, get_secret_key())
    audit(db, 'node.reissue_token', str(node_id), now(request))
    db.commit()
    return {'token': token}


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
        Exit = aliased(Node)
        rows = db.execute(select(Device, Node.name, Exit.name)
                          .outerjoin(Node, Device.node_id == Node.id)
                          .outerjoin(Exit, Device.egress_node_id == Exit.id)
                          .where(Device.account_id == account.id).order_by(Device.id))
        result['devices'] = [
            {'id': device.id, 'label': device.label, 'name': device.name,
             'node_name': node_name, 'status': device.status,
             'egress_node_id': device.egress_node_id, 'egress_node_name': egress_name,
             'allowed_ips': list(device.allowed_ips)}
            for device, node_name, egress_name in rows
        ]
    return result


@router.post('/subscribers', status_code=201)
def create_subscriber(body: SubscriberBody, request: Request, db: Session = Depends(get_db)):
    """Create an admin-owned identity that the subscriber can verify with /start."""
    password_hash = PasswordHasher(type=Type.ID).hash(secrets.token_urlsafe(32))
    begin_write(db)
    timestamp = now(request)
    account = Account(display_name=body.display_name,
                      telegram_chat_id=body.telegram_chat_id,
                      telegram_linked_at=None, telegram_linked_chat_id=None,
                      password_hash=password_hash, status='active', created_at=timestamp)
    db.add(account)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise APIError(409, 'master.subscriber_exists') from None
    audit(db, 'subscriber.create', str(account.id), timestamp)
    commit_unique(db, 'master.subscriber_exists')
    return subscriber_view(db, account)


@router.get('/subscribers')
def list_subscribers(db: Session = Depends(get_db)):
    return [subscriber_view(db, row) for row in db.scalars(select(Account).order_by(Account.id))]


class DeviceEgressBody(Model):
    """Preferred foreign exit for one device's chain; null clears the preference."""
    egress_node_id: int | None = Field(default=None, ge=1)


@router.patch('/subscribers/{account_id}/devices/{device_id}')
def set_device_egress(account_id: int, device_id: int, body: DeviceEgressBody, request: Request,
                      db: Session = Depends(get_db)):
    begin_write(db)
    get_account(db, account_id)
    device = db.get(Device, device_id)
    if device is None or device.account_id != account_id or device.status == 'removed':
        raise APIError(404, 'master.device_not_found')
    if body.egress_node_id is not None:
        target = db.get(Node, body.egress_node_id)
        if target is None or target.role not in ('egress', 'both'):
            raise APIError(422, 'master.node_role_invalid')
        if not target.enabled:
            raise APIError(409, 'master.node_disabled')
        if target.id == device.node_id:
            raise APIError(422, 'master.device_egress_invalid')
    device.egress_node_id = body.egress_node_id
    audit(db, 'device.egress', str(device_id), now(request))
    db.commit()
    return {'id': device.id, 'egress_node_id': device.egress_node_id}


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
    previous = (row.tariff_id, row.expires_at, row.status) if row is not None else None
    if (row is not None and body.days is None
            and aware(body.expires_at) == row.expires_at and row.status == 'expired'
            and tariff.id == row.tariff_id):
        audit(db, 'subscription.update', str(account_id), timestamp)
        db.commit()
        return subscription_view(row, tariff)
    if row is None:
        expiry = timestamp + timedelta(days=body.days) if body.days is not None \
            else aware(body.expires_at)
        row = Subscription(account_id=account_id, tariff_id=tariff.id,
                           expires_at=expiry, status='active', updated_at=timestamp)
        db.add(row)
        action = 'subscription.create'
    else:
        try:
            if body.days is not None:
                row.expires_at = utc(row.expires_at) + timedelta(days=body.days)
            else:
                assert body.expires_at is not None  # SubscriptionBody requires exactly one expiry.
                row.expires_at = utc(body.expires_at)
        except OverflowError:
            raise APIError(422, 'master.subscription_term_invalid') from None
        row.tariff_id = tariff.id
        row.status = 'active' if row.expires_at > timestamp else 'expired'
        row.updated_at = timestamp
        action = 'subscription.renew' if body.days is not None else 'subscription.update'
    if previous != (row.tariff_id, row.expires_at, row.status) and (
            row.expires_at > timestamp or previous is None or previous[1] > timestamp):
        row.notification_revision = (row.notification_revision or 0) + 1
        if row.expires_at > timestamp:
            enqueue_subscription(db, row, 'active', timestamp)
    if previous is not None and previous[2] == 'active' and row.status == 'expired':
        enqueue_subscription(db, row, 'expired', timestamp)
    audit(db, action, str(account_id), timestamp)
    db.commit()
    return subscription_view(row, tariff)


class RuleSetBody(Model):
    """One immutable rule-set version; a correction is a new version."""
    kind: StrictStr
    version: StrictStr = Field(min_length=1, max_length=32)
    content: StrictStr = Field(min_length=1, max_length=rulesets.MAX_BYTES)


@router.get('/rulesets')
def list_rulesets(db: Session = Depends(get_db)):
    rows = list(db.scalars(select(RuleSet).order_by(RuleSet.id.desc())))
    current = {}
    for kind in rulesets.KINDS:
        row = rulesets.current(db, kind)
        current[kind] = {k: v for k, v in rulesets.view(row).items()
                         if k in ('kind', 'version', 'entries', 'sha256')} if row else None
    return {'rulesets': [rulesets.view(row) for row in rows], 'current': current}


@router.post('/rulesets', status_code=201)
def publish_ruleset(body: RuleSetBody, request: Request, db: Session = Depends(get_db)):
    if not rulesets.valid_version(body.version):
        raise APIError(422, 'master.ruleset_version')
    text, entries, digest = rulesets.normalize(body.kind, body.content)
    begin_write(db)
    row = RuleSet(kind=body.kind, version=body.version, sha256=digest, entries=entries,
                  content=text, created_at=now(request))
    db.add(row)
    audit(db, 'master.ruleset.publish', f'{body.kind}:{body.version}', now(request))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, 'master.ruleset_exists') from None
    return rulesets.view(row)


class RuleSetImportBody(Model):
    """Publish a declared source (https URL) as a new immutable version."""
    kind: StrictStr
    version: StrictStr = Field(min_length=1, max_length=32)
    url: StrictStr = Field(min_length=1, max_length=2048)


@router.post('/rulesets/import', status_code=201)
def import_ruleset(body: RuleSetImportBody, request: Request, db: Session = Depends(get_db)):
    timestamp = now(request)
    begin_write(db)
    row = ruleset_import.import_source(db, body.kind, body.version, body.url, timestamp)
    audit(db, 'master.ruleset.import', f'{body.kind}:{body.version}', timestamp)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, 'master.ruleset_exists') from None
    return rulesets.view(row)


class RuleSetSourceBody(Model):
    """Auto-refreshing upstream list, e.g. the panel's built-in geoip/domain sources."""
    name: StrictStr = Field(min_length=1, max_length=64, pattern=r'^[a-z0-9][a-z0-9-]{0,63}$')
    kind: StrictStr
    url: StrictStr = Field(min_length=1, max_length=2048)
    interval_seconds: int = Field(default=86400, ge=3600, le=2592000)


@router.get('/rulesets/sources')
def list_ruleset_sources(db: Session = Depends(get_db)):
    rows = db.scalars(select(RuleSetSource).order_by(RuleSetSource.id))
    return [ruleset_import.source_view(row) for row in rows]


@router.post('/rulesets/sources', status_code=201)
def create_ruleset_source(body: RuleSetSourceBody, request: Request,
                          db: Session = Depends(get_db)):
    if body.kind not in rulesets.KINDS:
        raise APIError(422, 'master.ruleset_kind')
    if not rulesets.valid_version(body.name):
        raise APIError(422, 'master.ruleset_source_invalid')
    ruleset_import.validate_source_url(body.url)
    begin_write(db)
    timestamp = now(request)
    row = RuleSetSource(name=body.name, kind=body.kind, url=body.url,
                        interval_seconds=body.interval_seconds, created_at=timestamp)
    db.add(row)
    audit(db, 'master.ruleset_source.create', body.name, timestamp)
    commit_unique(db, 'master.ruleset_source_exists')
    return ruleset_import.source_view(row)


@router.delete('/rulesets/sources/{source_id}', status_code=204)
def delete_ruleset_source(source_id: int, request: Request, db: Session = Depends(get_db)):
    begin_write(db)
    row = db.get(RuleSetSource, source_id)
    if row is None:
        raise APIError(404, 'master.ruleset_source_not_found')
    db.delete(row)
    audit(db, 'master.ruleset_source.delete', str(source_id), now(request))
    db.commit()
    return Response(status_code=204)


@router.post('/rulesets/sources/{source_id}/refresh')
def refresh_ruleset_source(source_id: int, request: Request, db: Session = Depends(get_db)):
    begin_write(db)
    row = db.get(RuleSetSource, source_id)
    if row is None:
        raise APIError(404, 'master.ruleset_source_not_found')
    timestamp = now(request)
    published = ruleset_import.refresh_source(db, row, timestamp)
    row.last_checked_at = timestamp
    row.last_error = None
    audit(db, 'master.ruleset_source.refresh', row.name, timestamp)
    db.commit()
    return {'version': row.version, 'published': published is not None}
