import os
from typing import Annotated
from fastapi import APIRouter, Body, Depends, Path, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..agent.rpc import ApplyParams, ConfirmParams, EmptyParams, build_request, AgentClient, AgentRPCError
from ..agent.daemon import UnixSocketTransport
from ..db import ConfigurationRow
from ..generators.singbox import generate_singbox
from ..generators.wireguard import materialize_addresses
from ..schema import Configuration
from .auth import admin, current_user, get_db
from .configuration import check_roles, parse_configuration, redact, structural_diff, validate
from .errors import APIError

router = APIRouter(dependencies=[Depends(current_user)])
PositiveID = Annotated[int, Path(ge=1)]


def agent_call(method, body):
    transport = UnixSocketTransport(os.environ.get('VS_ROUTER_AGENT_SOCKET', '/run/vs-router/agent.sock'))
    try:
        return AgentClient(transport).call(method, body)
    except (OSError, EOFError):
        raise APIError(503, 'agent.unavailable') from None
    except AgentRPCError as exc:
        raise APIError(409, exc.error.message) from None
    finally:
        transport.close()


def version(db, version_id):
    row = db.get(ConfigurationRow, version_id)
    if row is None:
        raise APIError(404, "version.not_found")
    return row


def draft(db):
    row = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == "draft"))
    if row is None:
        raise APIError(404, "draft.not_found")
    return row


def view(row):
    return redact(row.snapshot().model_dump(mode="json"))


@router.get("/versions")
def versions(db: Session = Depends(get_db)):
    return [view(row) for row in db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc()))]


@router.get("/versions/{id}")
def get_version(id: PositiveID, db: Session = Depends(get_db)):
    return view(version(db, id))


@router.get("/draft/tproxy/preview", dependencies=[Depends(admin)])
def preview_tproxy(response: Response, db: Session = Depends(get_db)):
    """Inspect the saved draft only; this is not live configuration or readiness."""
    row = draft(db)
    response.headers['Cache-Control'] = 'no-store'
    return {'version_id': row.id, 'singbox': generate_singbox(row.snapshot())}


@router.post("/draft", status_code=201, dependencies=[Depends(admin)])
def create_draft(body: dict | None = Body(default=None), db: Session = Depends(get_db)):
    if db.scalar(select(ConfigurationRow.id).where(ConfigurationRow.status == "draft")) is not None:
        raise APIError(409, "draft.exists")
    previous = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    old = previous.configuration if previous else Configuration()
    configuration = parse_configuration(body, old.model_dump(mode="json")) if body is not None else old
    check_roles(configuration, old)
    # Store the deterministic tunnel/peer addresses so every client (any
    # browser build) sees them; explicit values are preserved.
    configuration = materialize_addresses(configuration)
    # Explicit monotonic allocation matches save_version's persisted snapshots.
    next_id = (db.scalar(select(func.max(ConfigurationRow.id))) or 0) + 1
    row = ConfigurationRow(id=next_id, status="draft", configuration=configuration)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise APIError(409, "draft.exists") from None
    return view(row)


@router.put("/draft", dependencies=[Depends(admin)])
def update_draft(body: dict = Body(), db: Session = Depends(get_db)):
    row = draft(db)
    configuration = parse_configuration(body, row.configuration.model_dump(mode="json"))
    check_roles(configuration, row.configuration)
    configuration = materialize_addresses(configuration)
    row.configuration = configuration
    db.commit()
    return view(row)


@router.post("/draft/validate", dependencies=[Depends(admin)])
def validate_draft(body: dict | None = Body(default=None), db: Session = Depends(get_db)):
    row = draft(db)
    old = row.configuration.model_dump(mode="json")
    return validate(old if body is None else body, old)


@router.delete("/draft", status_code=204, dependencies=[Depends(admin)])
def delete_draft(db: Session = Depends(get_db)):
    db.delete(draft(db))
    db.commit()
    return Response(status_code=204)


@router.get("/diff/{id1}/{id2}")
def diff(id1: PositiveID, id2: PositiveID, db: Session = Depends(get_db)):
    first, second = version(db, id1), version(db, id2)
    return structural_diff(first.configuration.model_dump(mode="json"),
                           second.configuration.model_dump(mode="json"))


@router.post("/apply", dependencies=[Depends(admin)])
def apply(body: ApplyParams, db: Session = Depends(get_db)):
    build_request("apply_version", body)
    row = version(db, body.version_id)
    if row.status != "draft":
        raise APIError(409, "version.not_draft")
    result = validate(row.configuration.model_dump(mode="json"))
    if not result["valid"]:
        raise APIError(422, "configuration.invalid", result["errors"])
    return agent_call("apply_version", body)


@router.get("/apply/status", dependencies=[Depends(admin)])
def apply_status(response: Response):
    """Host-owned marker, not a guess reconstructed from configuration rows."""
    response.headers['Cache-Control'] = 'no-store'
    return agent_call('status', EmptyParams())


@router.post("/confirm", dependencies=[Depends(admin)])
def confirm(body: ConfirmParams, db: Session = Depends(get_db)):
    build_request("confirm_version", body)
    version(db, body.version_id)
    return agent_call("confirm_version", body)


@router.post("/rollback", dependencies=[Depends(admin)])
def rollback(body: EmptyParams = Body(default=EmptyParams())):
    build_request("rollback", body)
    return agent_call("rollback", body)
