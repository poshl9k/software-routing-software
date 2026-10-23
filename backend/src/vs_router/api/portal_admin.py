"""Administrator access to portal accounts, independent of configuration storage."""
from datetime import datetime, timedelta, timezone
from threading import RLock
import secrets

from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_portal.models import Account, Audit, Device, DeviceOp, Invite, Setting, Subscription, Tariff, make_engine
from vs_portal.internal import InternalClient

from ..db import ConfigurationRow
from ..generators.wireguard import materialize_addresses
from ..schema import Configuration, Model
from .auth import admin, get_db
from .configuration import check_roles
from .errors import APIError
from .tunnel_peers import live_peers
from .versions import profile_default

router = APIRouter(prefix="/api/portal-admin", dependencies=[Depends(admin)])
_engine_lock = RLock()


def get_portal_db(request: Request):
    # Do not open the second database when the panel starts, or for anonymous
    # requests. The portal and panel deliberately use distinct engines.
    with _engine_lock:
        engine = getattr(request.app.state, "portal_engine", None)
        if engine is None:
            engine = make_engine()
            request.app.state.portal_engine = engine
    with Session(engine) as db:
        yield db


def utcnow():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def begin_write(db):
    if db.bind.dialect.name == "sqlite":
        db.execute(text("BEGIN IMMEDIATE"))


def audit(db, action, detail=None):
    db.add(Audit(actor="admin", action=action, detail=detail, at=utcnow()))


def tariff_view(row):
    return {"id": row.id, "name": row.name, "device_limit": row.device_limit,
            "term_days": row.term_days,
            "price_amount": float(row.price_amount) if row.price_amount is not None else None,
            "created_at": aware(row.created_at)}


def subscription_view(row):
    return {"subscriber_name": row.subscriber_name, "tariff_id": row.tariff_id,
            "expires_at": aware(row.expires_at), "status": row.status,
            "updated_at": aware(row.updated_at)}


def get_tariff(db, tariff_id):
    row = db.get(Tariff, tariff_id)
    if row is None:
        raise APIError(404, "portal.tariff_not_found")
    return row


def require_subscriber(db, name):
    row = db.scalar(select(ConfigurationRow).order_by(ConfigurationRow.id.desc()).limit(1))
    if row is None or not any(s.name == name for s in row.configuration.subscribers):
        raise APIError(404, "portal.subscriber_not_found")
    return row


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


class InviteBody(Model):
    tariff_id: int = Field(ge=1)
    activate: bool = False


class SubscriptionPatch(Model):
    tariff_id: int | None = Field(default=None, ge=1)
    renew: bool = False


def save_tariff(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, "portal.tariff_exists") from None


@router.get("/tariffs")
def list_tariffs(db: Session = Depends(get_portal_db)):
    return [tariff_view(row) for row in db.scalars(select(Tariff).order_by(Tariff.id))]


@router.post("/tariffs", status_code=201)
def create_tariff(body: TariffBody, db: Session = Depends(get_portal_db)):
    row = Tariff(**body.model_dump(), created_at=utcnow())
    db.add(row)
    audit(db, "tariff.create", body.name)
    save_tariff(db)
    return tariff_view(row)


@router.get("/tariffs/{tariff_id}")
def read_tariff(tariff_id: int, db: Session = Depends(get_portal_db)):
    return tariff_view(get_tariff(db, tariff_id))


@router.put("/tariffs/{tariff_id}")
def replace_tariff(tariff_id: int, body: TariffBody, db: Session = Depends(get_portal_db)):
    begin_write(db)
    row = get_tariff(db, tariff_id)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    audit(db, "tariff.update", str(tariff_id))
    save_tariff(db)
    return tariff_view(row)


@router.patch("/tariffs/{tariff_id}")
def update_tariff(tariff_id: int, body: TariffPatch, db: Session = Depends(get_portal_db)):
    values = body.model_dump(exclude_unset=True)
    if any(value is None and key != "price_amount" for key, value in values.items()):
        raise APIError(422, "request.invalid")
    begin_write(db)
    row = get_tariff(db, tariff_id)
    for key, value in values.items():
        setattr(row, key, value)
    audit(db, "tariff.update", str(tariff_id))
    save_tariff(db)
    return tariff_view(row)


@router.delete("/tariffs/{tariff_id}", status_code=204)
def delete_tariff(tariff_id: int, db: Session = Depends(get_portal_db)):
    begin_write(db)
    row = get_tariff(db, tariff_id)
    if db.scalar(select(Subscription).where(Subscription.tariff_id == tariff_id)) is not None:
        raise APIError(409, "portal.tariff_in_use")
    db.delete(row)
    audit(db, "tariff.delete", str(tariff_id))
    db.commit()
    return Response(status_code=204)


@router.post("/subscribers/{name}/invite", status_code=201)
def create_invite(name: str, body: InviteBody, request: Request, response: Response,
                  panel_db: Session = Depends(get_db), db: Session = Depends(get_portal_db)):
    require_subscriber(panel_db, name)
    begin_write(db)
    tariff = get_tariff(db, body.tariff_id)
    now = utcnow()
    # Only the newest password-reset invitation can be redeemed. Never include
    # an invite token or its generated password in audit records.
    db.execute(delete(Invite).where(Invite.subscriber_name == name, Invite.used_at.is_(None)))
    password = secrets.token_urlsafe(18) if body.activate else None
    row = Invite(token=secrets.token_urlsafe(32), subscriber_name=name,
                 password_hash=request.app.state.auth.hasher.hash(password) if password else None,
                 expires_at=now + timedelta(days=7), used_at=None, created_at=now)
    db.add(row)
    subscription = db.get(Subscription, name)
    if subscription is None:
        subscription = Subscription(subscriber_name=name, tariff_id=tariff.id,
                                    expires_at=now + timedelta(days=tariff.term_days),
                                    status="active", updated_at=now)
        db.add(subscription)
    # A password-reset invitation is not a renewal and must not grant extra time.
    audit(db, "invite.create", name)
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    result = {"token": row.token, "subscriber_name": name, "expires_at": aware(row.expires_at),
              "invite_path": f"/invite/{row.token}"}
    if password is not None:
        result["password"] = password
    return result


@router.delete("/invites/{token}", status_code=204)
def revoke_invite(token: str, db: Session = Depends(get_portal_db)):
    begin_write(db)
    row = db.get(Invite, token)
    if row is None:
        raise APIError(404, "portal.invite_not_found")
    if row.used_at is not None:
        raise APIError(409, "portal.invite_used")
    audit(db, "invite.revoke", row.subscriber_name)
    db.delete(row)
    db.commit()
    return Response(status_code=204)


def cascade_subscriber(configuration, name):
    """Drop a subscriber and every configuration artifact it owns.

    The subscriber record, its device peers in every tunnel and its device
    routing rules leave the document together; otherwise the stored draft
    fails peer.subscriber_reference / routing.subscriber_reference at the
    next save or apply. Service/transport peers (peer.subscriber is None,
    CONTEXT.md) belong to no subscriber and are never touched.
    """
    data = configuration.model_dump(mode='json')
    data['subscribers'] = [subscriber for subscriber in data['subscribers']
                           if subscriber['name'] != name]
    data['tunnels'] = [{**tunnel, 'peers': [peer for peer in tunnel['peers']
                                            if peer.get('subscriber') != name]}
                       for tunnel in data['tunnels']]
    data['routing_rules'] = [rule for rule in data['routing_rules']
                             if not (rule['subject'].get('kind') == 'device'
                                     and rule['subject'].get('subscriber') == name)]
    return Configuration.model_validate(data)


@router.delete("/subscribers/{name}", status_code=204)
def delete_subscriber(name: str, panel_db: Session = Depends(get_db),
                      db: Session = Depends(get_portal_db)):
    """Delete a subscriber together with everything it owns.

    Portal side: account, subscription, invites, devices and their operation
    queue go in one transaction — a leftover Subscription row would keep the
    portal worker issuing device operations for a subscriber the configuration
    no longer knows. Config side: the cascade lands in the current draft
    (created when none), mirroring the panel editor's save semantics, and
    removed device peers drop from a running tunnel immediately (live_peers).
    """
    row = require_subscriber(panel_db, name)
    begin_write(db)
    # DeviceOp references Device by id (PRAGMA foreign_keys=ON), so the
    # operation queue must go first; the rest are plain subscriber-owned rows.
    for model in (DeviceOp, Device, Invite, Subscription, Account):
        db.execute(delete(model).where(model.subscriber_name == name))
    audit(db, "subscriber.delete", name)
    db.commit()
    draft = panel_db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))
    old = draft.configuration if draft is not None else row.configuration
    configuration = materialize_addresses(cascade_subscriber(old, name))
    check_roles(configuration, old)
    if draft is None:
        next_id = (panel_db.scalar(select(func.max(ConfigurationRow.id))) or 0) + 1
        draft = ConfigurationRow(id=next_id, status='draft', configuration=configuration,
                                 profile=row.profile or profile_default())
        panel_db.add(draft)
    else:
        draft.configuration = configuration
    panel_db.commit()
    live_peers(configuration, old)
    return Response(status_code=204)


@router.get("/subscribers/{name}/subscription")
def read_subscription(name: str, panel_db: Session = Depends(get_db),
                      db: Session = Depends(get_portal_db)):
    require_subscriber(panel_db, name)
    row = db.get(Subscription, name)
    if row is None:
        raise APIError(404, "portal.subscription_not_found")
    return subscription_view(row)


@router.patch("/subscribers/{name}/subscription")
def update_subscription(name: str, body: SubscriptionPatch, response: Response,
                        panel_db: Session = Depends(get_db), db: Session = Depends(get_portal_db)):
    require_subscriber(panel_db, name)
    begin_write(db)
    row = db.get(Subscription, name)
    if row is None:
        raise APIError(404, "portal.subscription_not_found")
    tariff = get_tariff(db, body.tariff_id if body.tariff_id is not None else row.tariff_id)
    row.tariff_id = tariff.id
    pending = []
    if body.renew:
        try:
            row.expires_at = aware(row.expires_at) + timedelta(days=tariff.term_days)
        except OverflowError:
            raise APIError(422, "portal.subscription_term_invalid") from None
        row.status = "active"
        # Persist retries before the internal call. A busy apply must not lose a
        # paid/administrative renewal; the portal worker drains these operations.
        for device in db.scalars(select(Device).where(Device.subscriber_name == name,
                                                      Device.status == "active")):
            existing = db.scalar(select(DeviceOp).where(
                DeviceOp.device_id == device.id, DeviceOp.op == "activate",
                DeviceOp.status == "pending"))
            if existing is None:
                existing = DeviceOp(subscriber_name=name, op="activate", device_id=device.id,
                                    label=device.label, status="pending", created_at=utcnow())
                db.add(existing)
            pending.append(existing)
    row.updated_at = utcnow()
    audit(db, "subscription.renew" if body.renew else "subscription.update", name)
    db.commit()
    if pending:
        try:
            result = InternalClient().renew(name)
        except APIError as exc:
            if exc.code != "apply.busy" and exc.status < 500:
                for op in pending:
                    op.status, op.detail = "failed", exc.code
                db.commit()
                raise
            result = {"status": "pending"}
        if result.get("status") in {"applied", "confirmed"}:
            for op in pending:
                op.status, op.applied_at = "applied", utcnow()
            db.commit()
        else:
            response.status_code = 202
    response.headers["Cache-Control"] = "no-store"
    return subscription_view(row)
