"""Authenticated, secret-safe node UI setup for the master bridge."""
import secrets

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_router.api import host
from vs_router.api.errors import APIError
from vs_router.app import create_app
from vs_router.db import Base, MasterBridgeSetting, UserRow
from vs_router.internal_app import MASTER_TOKEN_KEY, _read_master_tokens
from vs_router.schema import EncryptedSecret
from vs_router.secrets import decrypt_secret

pytestmark = pytest.mark.anyio
CREDS = {"username": "admin", "password": "correct-password"}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def api(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("VS_ROUTER_SECRET_KEY", key.decode())
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    app = create_app(engine)
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="https://router.test") as client:
        yield client, engine, app, key
    engine.dispose()


async def sign_in(client):
    assert (await client.post("/api/setup", json=CREDS)).status_code == 201
    response = await client.post("/api/auth/login", json=CREDS)
    assert response.status_code == 200


def setup_body(token=None):
    return {
        "token": token or secrets.token_urlsafe(32),
        "hostname": "node.example.test",
        "source_ip": "192.0.2.15",
    }


async def test_master_bridge_setup_requires_admin_and_same_origin(api, monkeypatch):
    client, _, _, _ = api
    body = setup_body()
    assert (await client.post("/api/host/master-bridge", json=body)).status_code == 401

    await sign_in(client)
    monkeypatch.setattr(host, "agent_call", lambda *_: {"published": True})
    cross_origin = await client.post(
        "/api/host/master-bridge", json=body,
        headers={"origin": "https://attacker.test"})
    assert cross_origin.status_code == 403
    assert cross_origin.json()["code"] == "request.cross_origin"
    assert cross_origin.headers["cache-control"] == "no-store"


async def test_master_bridge_setup_encrypts_token_and_never_returns_it(api, monkeypatch):
    client, engine, _, key = api
    await sign_in(client)
    body = setup_body()
    calls = []
    monkeypatch.setattr(host, "agent_call",
                        lambda method, params: calls.append((method, params)) or {"published": True})

    response = await client.post("/api/host/master-bridge", json=body)
    assert response.status_code == 200, response.text
    assert response.json() == {"credential_installed": True, "credential_state": "pending_verification", "publication_state": "configured_on_disk"}
    assert response.headers["cache-control"] == "no-store"
    assert body["token"] not in response.text
    assert calls[0][0] == "set_master_bridge_publication"
    assert calls[0][1].model_dump(mode="json") == {
        "hostname": body["hostname"], "source_ip": body["source_ip"]}

    with Session(engine) as db:
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        assert row is not None
        assert body["token"] not in str(row.value)
        assert decrypt_secret(EncryptedSecret.model_validate(row.value["current"]), key) == body["token"]
        assert _read_master_tokens(db) == (body["token"], "")


async def test_master_bridge_setup_same_token_retry_is_idempotent(api, monkeypatch):
    client, _, _, _ = api
    await sign_in(client)
    body = setup_body()
    calls = []
    monkeypatch.setattr(host, "agent_call",
                        lambda method, params: calls.append((method, params)) or {"published": True})

    first = await client.post("/api/host/master-bridge", json=body)
    second = await client.post("/api/host/master-bridge", json=body)
    assert first.status_code == second.status_code == 200
    assert len(calls) == 2


async def test_master_bridge_setup_allows_replacing_unverified_credential(api, monkeypatch):
    client, engine, _, _ = api
    await sign_in(client)
    first_body = setup_body()
    calls = []
    monkeypatch.setattr(host, "agent_call",
                        lambda method, params: calls.append((method, params)) or {"published": True})
    first = await client.post('/api/host/master-bridge', json=first_body)
    assert first.status_code == 200
    assert first.json()['credential_state'] == 'pending_verification'

    replacement = setup_body()
    response = await client.post("/api/host/master-bridge", json=replacement)
    assert response.status_code == 200
    assert response.json()['credential_state'] == 'pending_verification'
    assert len(calls) == 2
    with Session(engine) as db:
        assert _read_master_tokens(db) == (replacement["token"], "")
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        assert row is not None and row.value['setup_pending'] is True


async def test_master_auth_verifies_token_and_prevents_replacement(api, monkeypatch):
    from vs_router import internal_app as bridge
    from vs_router.internal_app import create_internal_app

    client, engine, _, _ = api
    await sign_in(client)
    body = setup_body()

    def node_agent(method, params):
        if method == 'master_bridge_publication_status':
            return {'publication_state': 'configured_on_disk'}
        return {'published': True}

    monkeypatch.setattr(host, 'agent_call', node_agent)
    saved = await client.post('/api/host/master-bridge', json=body)
    assert saved.status_code == 200
    assert saved.json()['credential_state'] == 'pending_verification'
    with Session(engine) as db:
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        assert row is not None and row.value['setup_pending'] is True

    monkeypatch.setattr(bridge.versions, 'agent_call', lambda *_: {})
    internal = create_internal_app(engine=engine, portal_engine=engine)
    async with AsyncClient(transport=ASGITransport(app=internal),
                           base_url='http://router.test') as master_client:
        denied = await master_client.get('/internal/master/state', headers={
            'authorization': f"Bearer {secrets.token_urlsafe(32)}"})
        assert denied.status_code == 403
        with Session(engine) as db:
            row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
            assert row is not None and row.value['setup_pending'] is True
        verified = await master_client.get('/internal/master/state', headers={
            'authorization': f"Bearer {body['token']}"})
    assert verified.status_code == 200
    with Session(engine) as db:
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        assert row is not None and row.value['setup_pending'] is False

    status = await client.get('/api/host/master-bridge')
    assert status.json()['credential_state'] == 'verified'
    replacement = setup_body()
    rejected = await client.post('/api/host/master-bridge', json=replacement)
    assert rejected.status_code == 409
    with Session(engine) as db:
        assert _read_master_tokens(db) == (body['token'], '')


async def test_master_bridge_setup_persists_before_publication_and_retry_recovers(api, monkeypatch):
    client, engine, _, _ = api
    await sign_in(client)
    body = setup_body()
    attempts = []

    def publish(method, params):
        attempts.append((method, params))
        if len(attempts) == 1:
            raise APIError(503, "agent.unavailable")
        return {"published": True}

    monkeypatch.setattr(host, "agent_call", publish)
    failed = await client.post("/api/host/master-bridge", json=body)
    assert failed.status_code == 503
    assert failed.json()["code"] == "agent.unavailable"
    with Session(engine) as db:
        assert _read_master_tokens(db) == (body["token"], "")

    retried = await client.post("/api/host/master-bridge", json=body)
    assert retried.status_code == 200
    assert retried.json() == {"credential_installed": True, "credential_state": "pending_verification", "publication_state": "configured_on_disk"}
    assert len(attempts) == 2


async def test_status_distinguishes_saved_credential_from_missing_publication(api, monkeypatch):
    client, _, _, _ = api
    await sign_in(client)
    body = setup_body()

    def agent(method, params):
        if method == 'set_master_bridge_publication':
            raise APIError(503, 'agent.unavailable')
        assert method == 'master_bridge_publication_status'
        return {'publication_state': 'absent'}

    monkeypatch.setattr(host, 'agent_call', agent)
    assert (await client.post('/api/host/master-bridge', json=body)).status_code == 503
    status = await client.get('/api/host/master-bridge')
    assert status.status_code == 200
    assert status.json() == {
        'credential_installed': True, 'credential_state': 'pending_verification',
        'publication_state': 'absent'}


async def test_master_bridge_setup_rejects_invalid_token_without_persisting(api, monkeypatch):
    client, engine, _, _ = api
    await sign_in(client)
    calls = []
    monkeypatch.setattr(host, "agent_call", lambda *args: calls.append(args))
    body = setup_body("not-a-bridge-token")

    response = await client.post("/api/host/master-bridge", json=body)
    assert response.status_code == 422
    assert response.json()["code"] == "request.invalid"
    assert response.json()["details"] == [{
        "path": ["body", "token"], "type": "value_error",
        "message": ""}]
    assert response.headers["cache-control"] == "no-store"
    assert body["token"] not in response.text
    assert calls == []
    with Session(engine) as db:
        assert db.get(MasterBridgeSetting, MASTER_TOKEN_KEY) is None


async def test_master_bridge_setup_rejects_invalid_source_ip_without_echoing_input(api, monkeypatch):
    client, engine, _, _ = api
    await sign_in(client)
    calls = []
    monkeypatch.setattr(host, "agent_call", lambda *args: calls.append(args))
    body = setup_body()
    body["source_ip"] = "not-an-ip"

    response = await client.post("/api/host/master-bridge", json=body)
    assert response.status_code == 422
    assert response.json()["code"] == "request.invalid"
    assert response.json()["details"] == [{
        "path": ["body", "source_ip"], "type": "value_error", "message": ""}]
    assert body["source_ip"] not in response.text
    assert body["token"] not in response.text
    assert calls == []
    with Session(engine) as db:
        assert db.get(MasterBridgeSetting, MASTER_TOKEN_KEY) is None


async def test_master_bridge_setup_and_status_are_admin_only(api):
    client, engine, app, _ = api
    await sign_in(client)
    with Session(engine) as db:
        db.add(UserRow(username='operator',
                       password_hash=app.state.auth.hasher.hash('operator-password'),
                       role='operator'))
        db.commit()
    logged = await client.post('/api/auth/login', json={
        'username': 'operator', 'password': 'operator-password'})
    assert logged.status_code == 200
    assert (await client.get('/api/host/master-bridge')).status_code == 403
    assert (await client.post('/api/host/master-bridge', json=setup_body())).status_code == 403
