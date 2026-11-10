"""Versioned client rule-sets: admin publication, public serving, validation."""
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.app import create_master_app
from vs_master.models import Audit, Base, RuleSet, make_engine
from vs_master.rulesets import normalize
from vs_router.api.errors import APIError

pytestmark = pytest.mark.anyio
PASSWORD = 'master-test-password'
NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def master(monkeypatch):
    clock = [NOW]
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    app = create_master_app(engine=engine, clock=lambda: clock[0])
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url='https://master.test') as client:
        yield client, engine, clock, key, app
    engine.dispose()


async def initialize(client):
    assert (await client.post('/api/admin/setup', json={'password': PASSWORD})).status_code == 201
    response = await client.post('/api/admin/login', json={'username': 'admin', 'password': PASSWORD})
    assert response.status_code == 200, response.text


async def test_publication_is_admin_only_immutable_and_served_by_exact_version(master):
    client, engine, _, _, _ = master
    body = {'kind': 'domain', 'version': 'ru-2026-11-01',
            'content': 'Example.COM\n# комментарий\n\n+.example.net\r\nExample.com\n'}
    assert (await client.post('/api/master-admin/rulesets', json=body)).status_code == 401
    await initialize(client)

    published = await client.post('/api/master-admin/rulesets', json=body)
    assert published.status_code == 201, published.text
    assert published.json()['entries'] == 2
    assert len(published.json()['sha256']) == 64

    served = await client.get('/api/rulesets/domain/ru-2026-11-01.yaml')
    assert served.status_code == 200
    assert served.headers['content-type'].startswith('application/yaml')
    assert served.headers['etag'].strip('"') == published.json()['sha256']
    assert served.text == ('payload:\n'
                           '  - "example.com"\n'
                           '  - "+.example.net"\n')

    duplicate = await client.post('/api/master-admin/rulesets', json=body)
    assert duplicate.status_code == 409
    assert duplicate.json()['error']['code'] == 'master.ruleset_exists'

    listing = (await client.get('/api/master-admin/rulesets')).json()
    assert listing['current']['domain']['version'] == 'ru-2026-11-01'
    assert listing['current']['ipcidr'] is None
    assert [row['version'] for row in listing['rulesets']] == ['ru-2026-11-01']

    with Session(engine) as db:
        actions = {audit.action for audit in db.scalars(select(Audit))}
        assert 'master.ruleset.publish' in actions
        stored = db.scalar(select(RuleSet))
        assert stored is not None and stored.content == 'example.com\n+.example.net\n'


@pytest.mark.parametrize('body,code', [
    ({'kind': 'geosite', 'version': 'v1', 'content': 'example.com'}, 'master.ruleset_kind'),
    ({'kind': 'domain', 'version': 'Bad Version', 'content': 'example.com'}, 'master.ruleset_version'),
    ({'kind': 'domain', 'version': 'v1', 'content': '  \n# only comments\n'}, 'master.ruleset_content'),
    ({'kind': 'domain', 'version': 'v1', 'content': 'bad entry.com'}, 'master.ruleset_entry'),
    ({'kind': 'ipcidr', 'version': 'v1', 'content': '10.0.0.0/8\nnot-a-network'}, 'master.ruleset_entry'),
])
async def test_publication_rejects_invalid_input(master, body, code):
    client, _, _, _, _ = master
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets', json=body)
    assert response.status_code == 422
    assert response.json()['error']['code'] == code


def test_normalize_is_deterministic_and_deduplicates():
    text, entries, digest = normalize('ipcidr', '10.0.0.1/8\n10.0.0.0/8\n\n192.168.0.0/16\n')
    assert text == '10.0.0.0/8\n192.168.0.0/16\n'
    assert entries == 2 and len(digest) == 64
    assert normalize('ipcidr', '10.0.0.1/8\n\n10.0.0.0/8\n192.168.0.0/16\n') == (text, entries, digest)
    assert normalize('domain', 'Example.com\n')[0] == 'example.com\n'


async def test_unknown_and_unpublished_versions_are_not_found(master):
    client, _, _, _, _ = master
    response = await client.get('/api/rulesets/domain/never-published.yaml')
    assert response.status_code == 404
    assert response.json()['error']['code'] == 'master.ruleset_not_found'


def test_normalize_rejects_oversized_content():
    with pytest.raises(APIError):
        normalize('domain', 'a' * (2 * 1024 * 1024 + 1))
