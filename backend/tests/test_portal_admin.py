"""Admin portal contract: two isolated in-memory DBs; no sockets or root."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vs_portal.models import (Account, Audit, Device, DeviceOp, Invite,
                              Subscription, Tariff, make_engine)
from vs_router.api.errors import APIError
from vs_router.app import create_app
from vs_router.db import Base as PanelBase, ConfigurationRow, UserRow
from vs_router.schema import Configuration
from vs_router.secrets import encrypt_secret
from test_portal_internal import rig  # shared two-DB fixture, only agent RPC is stubbed

pytestmark = pytest.mark.anyio
PASSWORD = "portal-test-password"
TEST_SECRET = encrypt_secret("test-device-material", Fernet.generate_key())


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def portal_admin_api(monkeypatch):
    monkeypatch.delenv("VS_PORTAL_DATABASE_URL", raising=False)
    panel_engine = make_engine("sqlite://")
    portal_engine = make_engine("sqlite://")
    PanelBase.metadata.create_all(panel_engine)
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic-portal"))
    config.set_main_option("sqlalchemy.url", "sqlite://")
    with portal_engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
    app = create_app(panel_engine)
    app.state.portal_engine = portal_engine
    with Session(panel_engine) as db:
        db.add(ConfigurationRow(id=1, status="confirmed", profile="panel",
                                configuration=Configuration(subscribers=[{"name": "alice"}, {"name": "bob"}])))
        db.add(UserRow(username="admin", password_hash=app.state.auth.hasher.hash(PASSWORD), role="admin"))
        db.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://panel.test") as client:
        yield client, panel_engine, portal_engine, app
    panel_engine.dispose()
    portal_engine.dispose()


async def login(client):
    response = await client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200


async def tariff(client, name="monthly", limit=3, days=30):
    response = await client.post("/api/portal-admin/tariffs", json={
        "name": name, "device_limit": limit, "term_days": days, "price_amount": 150.50})
    assert response.status_code == 201, response.text
    return response.json()


async def invite(client, tariff_id, *, activate=False, name="alice"):
    return await client.post(f"/api/portal-admin/subscribers/{name}/invite", json={
        "tariff_id": tariff_id, "activate": activate})


async def test_criterion_8_admin_required_and_operator_forbidden(portal_admin_api):
    client, panel, portal, app = portal_admin_api
    assert (await client.get("/api/portal-admin/tariffs")).status_code == 401
    await login(client)
    with Session(panel) as db:
        db.scalar(select(UserRow)).role = "operator"
        db.commit()
    for method, url, body in [
        ("GET", "/api/portal-admin/tariffs", None),
        ("POST", "/api/portal-admin/tariffs", {"name": "bad", "device_limit": 1, "term_days": 1}),
        ("PATCH", "/api/portal-admin/subscribers/alice/subscription", {"renew": True}),
        ("POST", "/api/portal-admin/subscribers/alice/invite", {"tariff_id": 1}),
        ("DELETE", "/api/portal-admin/invites/token", None),
    ]:
        response = await client.request(method, url, json=body)
        assert response.status_code == 403, response.text
    with Session(portal) as db:
        assert db.scalar(select(Tariff)) is None


async def test_criterion_8_tariff_crud_constraints_and_price(portal_admin_api):
    client = portal_admin_api[0]
    await login(client)
    row = await tariff(client)
    base = f"/api/portal-admin/tariffs/{row['id']}"
    assert (await client.get(base)).json()["price_amount"] == 150.50
    assert (await client.get("/api/portal-admin/tariffs")).json() == [row]
    assert (await client.post("/api/portal-admin/tariffs", json={
        "name": "monthly", "device_limit": 1, "term_days": 1})).status_code == 409
    for field, value in [("device_limit", 0), ("term_days", 0), ("name", ""), ("price_amount", -1)]:
        assert (await client.patch(base, json={field: value})).status_code == 422
    assert (await client.patch(base, json={"device_limit": None})).status_code == 422
    assert (await client.patch(base, json={"name": "renamed", "price_amount": None})).json()["price_amount"] is None
    assert (await client.put(base, json={"name": "replaced", "device_limit": 7, "term_days": 90})).json()["term_days"] == 90
    assert (await client.delete(base)).status_code == 204
    assert (await client.get(base)).status_code == 404


async def test_criterion_8_invite_existing_subscriber_revocation_and_term(portal_admin_api):
    client, _, engine, _ = portal_admin_api
    await login(client)
    row = await tariff(client)
    assert (await invite(client, row["id"], name="missing")).status_code == 404
    before = datetime.now(timezone.utc)
    response = await invite(client, row["id"])
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert "password" not in data
    assert len(data["token"]) >= 43
    with Session(engine) as db:
        record = db.get(Invite, data["token"])
        assert record.password_hash is None and record.used_at is None
        subscription = db.get(Subscription, "alice")
        expires = subscription.expires_at.replace(tzinfo=timezone.utc)
        assert before + timedelta(days=30) <= expires <= datetime.now(timezone.utc) + timedelta(days=30)
        assert subscription.tariff_id == row["id"]
    assert (await client.delete(f"/api/portal-admin/tariffs/{row['id']}")).status_code == 409
    assert (await client.delete(f"/api/portal-admin/invites/{data['token']}")).status_code == 204
    with Session(engine) as db:
        assert db.get(Invite, data["token"]) is None
        audit = list(db.scalars(select(Audit)))
        assert {x.action for x in audit} >= {"invite.create", "invite.revoke"}
        assert all(data["token"] not in (x.detail or "") for x in audit)


async def test_criterion_8_generated_password_activates_and_used_invite_not_revoked(portal_admin_api, monkeypatch):
    from vs_portal.app import create_app as portal_app
    client, _, engine, _ = portal_admin_api
    await login(client)
    row = await tariff(client)
    response = await invite(client, row["id"], activate=True)
    assert response.status_code == 201
    data = response.json()
    assert len(data["password"]) >= 8
    with Session(engine) as db:
        record = db.get(Invite, data["token"])
        assert record.password_hash.startswith("$argon2id$")
        assert data["password"] not in record.password_hash
    from vs_portal.internal import InternalClient
    monkeypatch.setattr(InternalClient, "state", lambda self, name: {"subscription": {"status": "active"}})
    async with AsyncClient(transport=ASGITransport(app=portal_app(engine)), base_url="https://portal.test") as subscriber:
        activation = await subscriber.post("/api/portal/invite/activate", json={"token": data["token"]})
        assert activation.status_code in (200, 201), activation.text
        logged = await subscriber.post("/api/portal/login", json={"username": "alice", "password": data["password"]})
        assert logged.status_code == 200, logged.text
    assert (await client.delete(f"/api/portal-admin/invites/{data['token']}")).status_code == 409
    with Session(engine) as db:
        assert db.get(Account, "alice").password_hash.startswith("$argon2id$")
        assert all(data["password"] not in (row.detail or "") for row in db.scalars(select(Audit)))


async def test_criterion_8_password_reset_does_not_extend_subscription(portal_admin_api):
    client, _, engine, _ = portal_admin_api
    await login(client)
    row = await tariff(client)
    first = (await invite(client, row["id"])).json()
    with Session(engine) as db:
        expires = db.get(Subscription, "alice").expires_at
    second = (await invite(client, row["id"])).json()
    with Session(engine) as db:
        assert db.get(Invite, first["token"]) is None
        assert db.get(Invite, second["token"]) is not None
        assert db.get(Subscription, "alice").expires_at == expires


async def test_criterion_8_downgrade_preserves_devices_and_renew_adds_term(portal_admin_api, monkeypatch):
    from vs_router.api import portal_admin
    client, _, engine, _ = portal_admin_api
    await login(client)
    high = await tariff(client)
    low = await tariff(client, "small", limit=1, days=14)
    await invite(client, high["id"])
    with Session(engine) as db:
        original = db.get(Subscription, "alice").expires_at
        for index in range(3):
            db.add(Device(subscriber_name="alice", name=f"peer{index}", label="phone", public_key="public",
                          private_key=TEST_SECRET, preshared_key=TEST_SECRET,
                          allowed_ips=[f"10.0.0.{index+2}/32"], status="active", created_at=datetime.now(timezone.utc)))
        db.commit()
    calls = []
    monkeypatch.setattr(portal_admin.InternalClient, "renew", lambda self, name: calls.append(name) or {"status": "applied"})
    url = "/api/portal-admin/subscribers/alice/subscription"
    response = await client.patch(url, json={"tariff_id": low["id"]})
    assert response.status_code == 200 and not calls
    with Session(engine) as db:
        assert db.get(Subscription, "alice").expires_at == original
        assert len(list(db.scalars(select(Device).where(Device.status == "active")))) == 3
    response = await client.patch(url, json={"renew": True})
    assert response.status_code == 200, response.text
    assert calls == ["alice"]
    with Session(engine) as db:
        subscription = db.get(Subscription, "alice")
        assert subscription.expires_at == original + timedelta(days=14)
        assert subscription.status == "active"
        assert all(op.status == "applied" for op in db.scalars(select(DeviceOp)))


async def test_criterion_8_renew_busy_persists_retry_and_keeps_material(portal_admin_api, monkeypatch):
    from vs_router.api import portal_admin
    client, _, engine, _ = portal_admin_api
    await login(client)
    row = await tariff(client)
    await invite(client, row["id"])
    with Session(engine) as db:
        subscription = db.get(Subscription, "alice")
        subscription.status = "expired"
        subscription.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        db.add(Device(subscriber_name="alice", name="phone", label="phone", public_key="public",
                      private_key=TEST_SECRET, preshared_key=None, allowed_ips=["10.0.0.2/32"],
                      status="active", created_at=datetime.now(timezone.utc)))
        db.commit()
    def busy(self, name):
        raise APIError(409, "apply.busy")
    monkeypatch.setattr(portal_admin.InternalClient, "renew", busy)
    response = await client.patch("/api/portal-admin/subscribers/alice/subscription", json={"renew": True})
    assert response.status_code == 202, response.text
    with Session(engine) as db:
        assert db.get(Subscription, "alice").status == "active"
        op = db.scalar(select(DeviceOp))
        assert op.op == "activate" and op.status == "pending"
        assert db.scalar(select(Device)).private_key == TEST_SECRET


async def test_criterion_9_portal_migrated_separate_from_panel(portal_admin_api):
    _, panel, portal, _ = portal_admin_api
    panel_tables = set(inspect(panel).get_table_names())
    portal_tables = set(inspect(portal).get_table_names())
    assert "portal_accounts" not in panel_tables
    assert "configuration_versions" not in portal_tables
    assert portal_tables == {"alembic_version", "portal_accounts", "portal_invites", "portal_tariffs",
                             "portal_subscriptions", "portal_devices", "portal_device_ops", "portal_audit"}
    with portal.connect() as connection:
        assert connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar() == "0002"


async def test_criterion_8_panel_second_engine_lazy_and_sqlite_wal(tmp_path, monkeypatch):
    path = tmp_path / "lazy.db"
    monkeypatch.setenv("VS_PORTAL_DATABASE_URL", f"sqlite:///{path}")
    panel = make_engine("sqlite://")
    PanelBase.metadata.create_all(panel)
    app = create_app(panel)
    assert not path.exists() and not hasattr(app.state, "portal_engine")
    with Session(panel) as db:
        db.add(UserRow(username="admin", password_hash=app.state.auth.hasher.hash(PASSWORD), role="admin"))
        db.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://panel.test") as client:
        assert (await client.get("/api/portal-admin/tariffs")).status_code == 401
        assert not path.exists()
        config = Config()
        config.set_main_option("script_location", str(Path(__file__).parents[1] / "alembic-portal"))
        config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
        command.upgrade(config, "head")
        await login(client)
        assert (await client.get("/api/portal-admin/tariffs")).json() == []
    with app.state.portal_engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
    app.state.portal_engine.dispose()
    panel.dispose()


def test_criterion_6_7_real_portal_internal_roundtrip_and_retry(rig):
    import httpx
    from fastapi.testclient import TestClient
    from vs_portal.app import create_app as create_portal
    from vs_portal.devices import process_pending

    class Bridge(httpx.BaseTransport):
        def handle_request(self, request):
            result = rig[0].request(request.method, request.url.path,
                                    headers=dict(request.headers), content=request.content)
            return httpx.Response(result.status_code, headers=result.headers, content=result.content)

    app = create_portal(rig[2], internal_transport=Bridge())
    with Session(rig[2]) as db:
        db.add(Account(subscriber_name="alice", status="active",
                       password_hash=app.state.auth.hasher.hash(PASSWORD)))
        db.commit()
    client = TestClient(app, base_url="https://portal.test")
    assert client.post("/api/portal/login", json={"username": "alice", "password": PASSWORD}).status_code == 200
    rig[4]["status"] = "pending"
    queued = client.post("/api/portal/devices", json={"label": "roundtrip"})
    assert queued.status_code == 202, queued.text
    assert queued.json()["status"] == "pending"
    rig[4]["status"] = "confirmed"
    process_pending(rig[2], app.state.internal, datetime.now(timezone.utc))
    with Session(rig[2]) as db:
        device = db.scalar(select(Device))
        name, public, address = device.name, device.public_key, device.allowed_ips
        assert device.status == "active"
        assert db.get(DeviceOp, queued.json()["operation_id"]).status == "applied"
    exported = client.get(f"/api/portal/devices/{name}/export?format=conf")
    assert exported.status_code == 200, exported.text
    assert "PrivateKey = " in exported.text and "Endpoint = vpn.example.org:20500" in exported.text
    assert "Address = " + ", ".join(address) in exported.text
    with Session(rig[1]) as db:
        applied = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == "confirmed")
                            .order_by(ConfigurationRow.id.desc()))
        assert applied.configuration.tunnels[0].peers[0].public_key == public
    for operation in ("deactivate", "activate"):
        response = client.post(f"/api/portal/devices/{name}/{operation}")
        assert response.status_code == 200 and response.json()["status"] == "applied", response.text
    again = client.get(f"/api/portal/devices/{name}/export?format=conf")
    assert again.text == exported.text
    with Session(rig[2]) as db:
        sub = db.get(Subscription, "alice")
        sub.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    process_pending(rig[2], app.state.internal, datetime.now(timezone.utc))
    with Session(rig[1]) as db:
        applied = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == "confirmed")
                            .order_by(ConfigurationRow.id.desc()))
        assert not applied.configuration.tunnels[0].peers
    assert client.post("/api/portal/devices", json={"label": "expired"}).status_code == 403
    with Session(rig[2]) as db:
        sub = db.get(Subscription, "alice")
        sub.status = "active"
        sub.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        db.commit()
    process_pending(rig[2], app.state.internal, datetime.now(timezone.utc))
    with Session(rig[1]) as db:
        applied = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == "confirmed")
                            .order_by(ConfigurationRow.id.desc()))
        assert applied.configuration.tunnels[0].peers[0].public_key == public
    deleted = client.delete(f"/api/portal/devices/{name}")
    assert deleted.status_code == 200 and deleted.json()["status"] == "applied", deleted.text
    with Session(rig[2]) as db:
        removed = db.scalar(select(Device))
        assert removed.status == "removed" and removed.private_key is None and not removed.allowed_ips
    assert client.get(f"/api/portal/devices/{name}/export?format=conf").status_code == 404
    client.close()


def test_criterion_6_expiry_queue_obsolete_after_renewal(rig):
    import httpx
    from vs_portal.devices import process_pending
    from vs_portal.internal import InternalClient
    from test_portal_internal import create, last, post

    device_id = create(rig)
    assert post(rig, {"op": "create", "device_id": device_id}).status_code == 200
    public = last(rig).tunnels[0].peers[0].public_key

    def bridge(request):
        result = rig[0].request(request.method, request.url.path,
                                headers=dict(request.headers), content=request.content)
        return httpx.Response(result.status_code, content=result.content)

    internal = InternalClient(transport=httpx.MockTransport(bridge))
    with Session(rig[2]) as db:
        sub = db.get(Subscription, "alice")
        sub.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    rig[4]["status"] = "pending"
    process_pending(rig[2], internal, datetime.now(timezone.utc))
    with Session(rig[2]) as db:
        assert db.scalar(select(DeviceOp)).status == "pending"
        sub = db.get(Subscription, "alice")
        sub.status = "active"
        sub.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        db.commit()
    rig[4]["status"] = "confirmed"
    process_pending(rig[2], internal, datetime.now(timezone.utc))
    assert last(rig).tunnels[0].peers[0].public_key == public
