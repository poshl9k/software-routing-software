"""Rule-set import from a declared https source: guards, parsing, publication."""
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master import ruleset_import
from vs_master.app import create_master_app
from vs_master.models import Audit, Base, RuleSet, make_engine

pytestmark = pytest.mark.anyio
PASSWORD = 'master-test-password'
NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
PUBLIC_IP = '93.184.216.34'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def master(monkeypatch):
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    app = create_master_app(engine=engine, clock=lambda: NOW)
    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url='https://master.test') as client:
        yield client, engine, app
    engine.dispose()


async def initialize(client):
    assert (await client.post('/api/admin/setup', json={'password': PASSWORD})).status_code == 201
    assert (await client.post('/api/admin/login', json={
        'username': 'admin', 'password': PASSWORD})).status_code == 200


def fake_source(monkeypatch, body=b'', status=200, address=PUBLIC_IP):
    def getaddrinfo(host, port, **kwargs):
        return [(2, 1, 6, '', (address, port or 443))]

    class Response:
        status_code = status
        content = body

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url):
            return Response()

    monkeypatch.setattr(ruleset_import.socket, 'getaddrinfo', getaddrinfo)
    monkeypatch.setattr(ruleset_import.httpx, 'Client', Client)


async def test_import_geosite_source_and_publish_version(master, monkeypatch):
    client, engine, _ = master
    fake_source(monkeypatch, b'# comment\ndomain:example.ru\nfull:mail.ru\n\nplain.org\nru\n')
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'ru-domains-1',
        'url': 'https://lists.example/ru-domains.txt'})
    assert response.status_code == 201, response.text
    assert response.json()['entries'] == 4
    served = await client.get('/api/rulesets/domain/ru-domains-1.yaml')
    assert served.text == ('payload:\n'
                           '  - "example.ru"\n  - "mail.ru"\n  - "plain.org"\n'
                           '  - "+.ru"\n')
    with Session(engine) as db:
        assert db.scalar(select(RuleSet.version)) == 'ru-domains-1'
        assert {audit.action for audit in db.scalars(select(Audit))} >= {'master.ruleset.import'}


async def test_import_cidr_source_for_ip_kind(master, monkeypatch):
    client, _, _ = master
    fake_source(monkeypatch, b'cidr:5.5.5.0/24\n77.88.8.0/24\n')
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'ipcidr', 'version': 'ru-ips-1', 'url': 'https://lists.example/ru-ips.txt'})
    assert response.status_code == 201, response.text
    assert response.json()['entries'] == 2


@pytest.mark.parametrize('url,code', [
    ('http://lists.example/x.txt', 'master.ruleset_source_invalid'),
    ('https://user:pw@lists.example/x.txt', 'master.ruleset_source_invalid'),
    ('https://lists.example:0/x.txt', 'master.ruleset_source_invalid'),
])
async def test_import_rejects_unsafe_source_urls(master, monkeypatch, url, code):
    client, _, _ = master
    fake_source(monkeypatch)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'v1', 'url': url})
    assert response.status_code == 422
    assert response.json()['error']['code'] == code


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.5', '169.254.169.254', '::1'])
async def test_import_refuses_private_resolution(master, monkeypatch, address):
    client, _, _ = master
    fake_source(monkeypatch, address=address)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'v1', 'url': 'https://lists.example/x.txt'})
    assert response.status_code == 422
    assert response.json()['error']['code'] == 'master.ruleset_source_forbidden'


@pytest.mark.parametrize('body,code', [
    (b'keyword:bank', 'master.ruleset_format_unsupported'),
    (b'include:tld-ru', 'master.ruleset_format_unsupported'),
    (b'[\n{"domain": "example.ru"}\n]', 'master.ruleset_format_unsupported'),
    (b'', 'master.ruleset_content'),
])
async def test_import_rejects_unsupported_or_empty_payloads(master, monkeypatch, body, code):
    client, _, _ = master
    fake_source(monkeypatch, body)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'v1', 'url': 'https://lists.example/x.txt'})
    assert response.status_code == 422
    assert response.json()['error']['code'] == code


async def test_import_duplicate_version_conflicts(master, monkeypatch):
    client, _, _ = master
    fake_source(monkeypatch, b'example.ru\n')
    await initialize(client)
    payload = {'kind': 'domain', 'version': 'v1', 'url': 'https://lists.example/x.txt'}
    assert (await client.post('/api/master-admin/rulesets/import', json=payload)).status_code == 201
    duplicate = await client.post('/api/master-admin/rulesets/import', json=payload)
    assert duplicate.status_code == 409
    assert duplicate.json()['error']['code'] == 'master.ruleset_exists'


async def test_import_requires_admin(master, monkeypatch):
    client, _, _ = master
    fake_source(monkeypatch, b'example.ru\n')
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'v1', 'url': 'https://lists.example/x.txt'})
    assert response.status_code == 401


async def test_source_refresh_publishes_only_when_upstream_changes(master, monkeypatch):
    client, _, _ = master
    await initialize(client)
    fake_source(monkeypatch, b'example.ru\n')
    created = await client.post('/api/master-admin/rulesets/sources', json={
        'name': 'ru-domains', 'kind': 'domain', 'url': 'https://lists.example/ru.txt',
        'interval_seconds': 3600})
    assert created.status_code == 201, created.text
    source_id = created.json()['id']

    first = await client.post(f'/api/master-admin/rulesets/sources/{source_id}/refresh')
    assert first.status_code == 200, first.text
    assert first.json()['published'] is True
    assert first.json()['version'].startswith('ru-domains-')
    assert (await client.get(f"/api/rulesets/domain/{first.json()['version']}.yaml")).status_code == 200

    unchanged = await client.post(f'/api/master-admin/rulesets/sources/{source_id}/refresh')
    assert unchanged.json() == {'version': first.json()['version'], 'published': False}

    fake_source(monkeypatch, b'example.ru\nnew.example\n')
    changed = await client.post(f'/api/master-admin/rulesets/sources/{source_id}/refresh')
    assert changed.json()['published'] is True
    assert changed.json()['version'] != first.json()['version']
    listing = (await client.get('/api/master-admin/rulesets/sources')).json()
    assert listing[0]['version'] == changed.json()['version']
    assert (await client.delete(f'/api/master-admin/rulesets/sources/{source_id}')).status_code == 204
    assert (await client.get('/api/master-admin/rulesets/sources')).json() == []


async def test_source_creation_validates_url_and_admin_only(master, monkeypatch):
    client, _, _ = master
    fake_source(monkeypatch)
    payload = {'name': 'ru-ips', 'kind': 'ipcidr', 'url': 'http://lists.example/ru.txt'}
    assert (await client.post('/api/master-admin/rulesets/sources', json=payload)).status_code == 401
    await initialize(client)
    assert (await client.post('/api/master-admin/rulesets/sources', json=payload)).status_code == 422
    payload['url'] = 'https://lists.example/ru.txt'
    payload['kind'] = 'geosite'
    assert (await client.post('/api/master-admin/rulesets/sources', json=payload)).status_code == 422


def test_refresh_due_sources_records_error_and_respects_interval(monkeypatch):
    from datetime import timedelta
    from sqlalchemy import select
    from vs_master.models import RuleSetSource
    from vs_master.ruleset_import import refresh_due_sources
    from vs_router.api.errors import APIError

    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(RuleSetSource(name='fail', kind='domain', url='https://lists.example/x.txt',
                             interval_seconds=3600, created_at=NOW))
        db.commit()

    def boom(url):
        raise APIError(422, 'master.ruleset_fetch')

    monkeypatch.setattr(ruleset_import, 'validate_source_url', lambda value: value)
    monkeypatch.setattr(ruleset_import, 'fetch_source', boom)
    assert refresh_due_sources(engine, NOW) == 0
    with Session(engine) as db:
        source = db.scalar(select(RuleSetSource))
        assert source.last_error == 'master.ruleset_fetch'
        assert source.last_checked_at is not None

    # Inside the interval nothing is fetched again, even with a working upstream.
    calls = []
    monkeypatch.setattr(ruleset_import, 'fetch_source',
                        lambda url: (calls.append(url), 'example.ru\n')[1])
    assert refresh_due_sources(engine, NOW + timedelta(minutes=5)) == 0
    assert calls == []
    assert refresh_due_sources(engine, NOW + timedelta(hours=2)) == 1
    with Session(engine) as db:
        source = db.scalar(select(RuleSetSource))
        assert source.last_error is None and source.version is not None


async def test_import_singbox_json_rule_set(master, monkeypatch):
    client, _, _ = master
    payload = (b'{"version": 3, "rules": ['
               b'{"domain": ["exact.ru"], "domain_suffix": [".suffix.ru", "plain.ru"]},'
               b'{"ip_cidr": ["5.5.5.0/24"]}]}')
    fake_source(monkeypatch, payload)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'ru-domains-json-1',
        'url': 'https://lists.example/ru.json'})
    assert response.status_code == 201, response.text
    assert response.json()['entries'] == 3
    served = await client.get('/api/rulesets/domain/ru-domains-json-1.yaml')
    assert served.text == ('payload:\n'
                           '  - "exact.ru"\n'
                           '  - "+.suffix.ru"\n'
                           '  - "+.plain.ru"\n')


async def test_import_singbox_json_ip_cidr(master, monkeypatch):
    client, _, _ = master
    fake_source(monkeypatch, b'{"version": 3, "rules": [{"ip_cidr": ["5.5.5.0/24", "77.88.8.0/24"],'
                             b' "domain": ["ignored.ru"]}]}')
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'ipcidr', 'version': 'ru-ips-json-1', 'url': 'https://lists.example/ru.json'})
    assert response.status_code == 201, response.text
    assert response.json()['entries'] == 2


@pytest.mark.parametrize('payload,code', [
    (b'{"version": 3, "rules": [{"domain_keyword": ["bank"]}]}',
     'master.ruleset_format_unsupported'),
    (b'{"version": 3, "rules": [{"domain_regex": ["^a\\.ru$"]}]}',
     'master.ruleset_format_unsupported'),
    (b'{"version": 3, "rules": [{"network": "udp"}]}',
     'master.ruleset_format_unsupported'),
    (b'{not json', 'master.ruleset_format_unsupported'),
    (b'{"version": 3}', 'master.ruleset_format_unsupported'),
    (b'{"version": 3, "rules": [{"ip_cidr": ["5.5.5.0/24"]}]}', 'master.ruleset_content'),
])
async def test_import_rejects_unpublishable_json_matchers(master, monkeypatch, payload, code):
    client, _, _ = master
    fake_source(monkeypatch, payload)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'domain', 'version': 'v1', 'url': 'https://lists.example/ru.json'})
    assert response.status_code == 422
    assert response.json()['error']['code'] == code


async def test_import_ripe_delegated_ru_prefixes(master, monkeypatch):
    client, _, _ = master
    body = (b'2|ripencc|1794265199|167930|19700101|20261109|+0100\n'
            b'ripencc|*|ipv4|*|100858|summary\n'
            b'ripencc|RU|ipv4|2.56.24.0|512|20190313|allocated\n'
            b'ripencc|RU|ipv4|10.0.0.0|384|20190313|allocated\n'
            b'ripencc|DE|ipv4|9.9.9.0|256|20190313|allocated\n'
            b'ripencc|RU|ipv6|2001:640::|32|19991115|allocated\n')
    fake_source(monkeypatch, body)
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'ipcidr', 'version': 'ru-ripe-1',
        'url': 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'})
    assert response.status_code == 201, response.text
    served = await client.get('/api/rulesets/ipcidr/ru-ripe-1.yaml')
    payload = [line.strip('  - "') for line in served.text.splitlines()[1:]]
    # Summarized ranges, DE excluded, IPv6 kept as its own prefix.
    assert '2.56.24.0/23' in payload
    assert '10.0.0.0/24' in payload and '10.0.1.0/25' in payload
    assert not any(entry.startswith('9.9.9.') for entry in payload)
    assert '2001:640::/32' in payload


async def test_ipcidr_source_keeps_ipv6_prefixes(master, monkeypatch):
    client, _, _ = master
    # Telegram publishes IPv6 CIDRs next to IPv4 ones; a bare "2001:67c:..." has
    # no dot and must not be mistaken for a TLD by the domain heuristic.
    fake_source(monkeypatch, b'91.108.56.0/22\n2001:67c:4e8::/48\n')
    await initialize(client)
    response = await client.post('/api/master-admin/rulesets/import', json={
        'kind': 'ipcidr', 'version': 'tg-ips-1',
        'url': 'https://core.telegram.org/resources/cidr.txt'})
    assert response.status_code == 201, response.text
    assert response.json()['entries'] == 2
    served = await client.get('/api/rulesets/ipcidr/tg-ips-1.yaml')
    assert '2001:67c:4e8::/48' in served.text
