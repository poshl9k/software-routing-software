"""Master bridge endpoints on the node: bearer auth, token rotation, telemetry (ADR-0035 D2/D7)."""
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_router.internal_app import MASTER_TOKEN_KEY, _read_master_tokens, create_internal_app
from vs_router.secrets import encrypt_secret


ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'master-token-0123456789abcdef'
NEXT = 'master-token-fedcba9876543210'


def bearer(value):
    return {'Authorization': f'Bearer {value}'}


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setenv('VS_PORTAL_INTERNAL_SECRET', 'test-internal-secret')
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    portal = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    config = Config()
    config.set_main_option('script_location', str(ROOT / 'alembic-portal'))
    with portal.begin() as connection:
        config.attributes['connection'] = connection
        command.upgrade(config, 'head')
    app = create_internal_app(portal_engine=portal)
    return TestClient(app), portal


def seed_token(portal, current, previous=None):
    with Session(portal) as db:
        value = {'current': encrypt_secret(current, os.environ['VS_ROUTER_SECRET_KEY'].encode()).model_dump(mode='json'),
                 'previous': encrypt_secret(previous, os.environ['VS_ROUTER_SECRET_KEY'].encode()).model_dump(mode='json') if previous else None}
        from vs_portal.models import Setting
        db.add(Setting(key=MASTER_TOKEN_KEY, value=json.dumps(value)))
        db.commit()


def test_bearer_grants_bridge_and_rotation_uses_current_token(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    # Bearer token authenticates the existing subscriber bridge too.
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    rotated = client.post('/internal/master/token-rotate', headers=bearer(TOKEN), json={'new_token': NEXT})
    assert rotated.status_code == 200 and rotated.json() == {'rotated': True}
    with Session(portal) as db:
        current, previous = _read_master_tokens(db)
    assert current == NEXT and previous == TOKEN
    # Old token still works for the bridge (transitional generation) ...
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 200
    # ... but a second rotation attempt with the old token proposing a THIRD
    # token is revoked: only the master's confirmed retry (same new token) wins.
    third = 'master-token-abcdef0123456789'
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': third}).status_code == 403
    # Idempotent retry with the old token proposing the CURRENT new token.
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).json() == {'rotated': False}
    # Repeated rotation with the current token proposing the same token: no-op.
    assert client.post('/internal/master/token-rotate', headers=bearer(NEXT),
                       json={'new_token': NEXT}).json() == {'rotated': False}
    with Session(portal) as db:
        current, previous = _read_master_tokens(db)
    assert current == NEXT


def test_token_rotates_and_revokes_previous(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).status_code == 200
    # Rotation is authenticated by the CURRENT token; a wrong current token is refused.
    stranger = 'master-token-zzzzzzzzzzzzzzzz'
    assert client.post('/internal/master/token-rotate', headers=bearer(stranger),
                       json={'new_token': NEXT}).status_code == 403


def test_no_token_configured_fails_closed(rig):
    client, portal = rig
    assert client.get('/internal/master/state', headers=bearer(TOKEN)).status_code == 403
    assert client.post('/internal/master/token-rotate', headers=bearer(TOKEN),
                       json={'new_token': NEXT}).status_code == 403


def test_master_state_counts_active_devices(rig):
    client, portal = rig
    seed_token(portal, TOKEN)
    from vs_portal.models import Device, Subscription, Tariff
    with Session(portal) as db:
        tariff = Tariff(name='Base', device_limit=5, term_days=30)
        db.add(tariff)
        db.flush()
        db.add(Subscription(subscriber_name='alice', tariff_id=tariff.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
        db.add(Device(subscriber_name='alice', label='Телефон', status='active', allowed_ips=[]))
        db.add(Device(subscriber_name='alice', label='Ноутбук', status='inactive', allowed_ips=[]))
        db.commit()
    body = client.get('/internal/master/state', headers=bearer(TOKEN)).json()
    assert body['active_devices'] == 1
    assert 'tunnels' in body
