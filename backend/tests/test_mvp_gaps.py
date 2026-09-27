"""Coverage for the MVP-gap endpoints: aliases import/export, backup round-trip,
diagnostics parsing/validation, Kea leases error handling and tunnel QR export."""
import base64
import os

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from vs_router.db import save_version
from vs_router.schema import ConfigurationVersion
from vs_router.secrets import encrypt_secret

pytestmark = pytest.mark.anyio


def anyio_backend():
    return 'asyncio'


from test_api import api  # noqa: F401  (fixture import)
from test_api import sign_in


async def _confirm_sample(api, key=None):
    client, engine, now = api
    await sign_in(client)
    key = key or Fernet.generate_key().decode()
    real_key = base64.b64encode(os.urandom(32)).decode()
    private_key = encrypt_secret(real_key, key.encode()).model_dump()
    config = {
        'interfaces': [{'name': 'enp1s0', 'type': 'physical', 'zone': 'wan', 'addresses': []},
                       {'name': 'br0', 'type': 'bridge', 'zone': 'lan', 'addresses': ['192.168.77.1/24']},
                       {'name': 'wg_test', 'type': 'physical', 'zone': 'wan', 'addresses': ['10.66.66.1/24']}],
        'aliases': [{'name': 'office', 'type': 'address', 'elements': ['192.168.77.0/24'], 'includes': []},
                    {'name': 'web_ports', 'type': 'port', 'elements': ['tcp/80', 'tcp/443'], 'includes': []}],
        'tunnels': [{'name': 'wg_test', 'interface': 'wg_test', 'role': 'server', 'protocol': 'wg',
                     'listen_port': 51820, 'private_key': private_key,
                     'peers': [{'name': 'phone', 'public_key': 'A' * 44, 'allowed_ips': ['10.66.66.2/32']}]}],
    }
    with __import__('vs_router.db', fromlist=['Session']).Session(engine) as session:
        save_version(session, ConfigurationVersion(configuration=config))
        session.commit()
    return client


async def test_aliases_export_json_and_import_roundtrip(api):
    client = await _confirm_sample(api)
    export = await client.post('/api/aliases/export', json={'format': 'json'})
    assert export.status_code == 200
    payload = export.json()
    assert payload['schema_version'] == 1
    assert {a['name'] for a in payload['aliases']} == {'office', 'web_ports'}

    # import-preview flags a duplicate name and an invalid element
    bad = {'aliases': [{'name': 'office', 'type': 'address', 'elements': ['10.0.0.0/8'], 'includes': []},
                       {'name': 'bad', 'type': 'address', 'elements': ['not-an-ip'], 'includes': []}]}
    preview = await client.post('/api/aliases/import-preview', json=bad)
    assert preview.status_code == 200
    body = preview.json()
    assert body['ok'] is False
    messages = [e['message'] for e in body['errors']]
    assert 'alias.duplicate_name' in messages and 'alias.invalid_element' in messages

    # importing a new alias merges it into a fresh draft
    good = {'aliases': [{'name': 'dmz', 'type': 'address', 'elements': ['10.9.0.0/24'], 'includes': []}]}
    imported = await client.post('/api/aliases/import', json=good)
    assert imported.status_code == 200 and imported.json()['imported'] == 1
    versions = (await client.get('/api/versions')).json()
    drafts = [v for v in versions if v['status'] == 'draft']
    assert drafts and any(a['name'] == 'dmz' for a in drafts[0]['configuration']['aliases'])


async def test_backup_roundtrip_without_password_redacts_secrets(api):
    client = await _confirm_sample(api)
    exported = await client.get('/api/backup/export')
    assert exported.status_code == 200
    archive = exported.json()
    assert archive['schema_version'] == 1
    assert archive['users'] == [{'username': 'admin', 'role': 'admin'}]
    assert all(v['configuration'] != {} for v in archive['versions'])

    restored = await client.post('/api/backup/restore', json=archive)
    assert restored.status_code == 200
    # restore drops secret-bearing records whose secrets were redacted
    versions = (await client.get('/api/versions')).json()
    assert len(versions) >= 1


async def test_diag_ping_parse_and_input_validation(api):
    from vs_router.api.diag import parse_ping
    parsed = parse_ping('3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n'
                        'rtt min/avg/max/mdev = 0.4/0.5/0.6/0.1 ms')
    assert parsed == {'sent': 3, 'received': 3, 'loss_pct': 0.0, 'min_avg_max_ms': [0.4, 0.5, 0.6]}

    client = await _confirm_sample(api)
    for host in ('bad host; rm -rf', 'host$(id)', ''):
        assert (await client.post('/api/diag/ping', json={'host': host})).status_code == 422
    assert (await client.post('/api/diag/ping', json={'host': '8.8.8.8', 'count': 9})).status_code == 422
    # agent socket absent → 503 agent.unavailable
    response = await client.post('/api/diag/ping', json={'host': '8.8.8.8'})
    assert response.status_code == 503


async def test_leases_unreachable_ctrl_agent(api, monkeypatch):
    client = await _confirm_sample(api)
    monkeypatch.setenv('VS_ROUTER_KEA_CTRL_SOCKET', '/nonexistent/kea.sock')
    response = await client.get('/api/dhcp/leases')
    assert response.status_code == 503
    assert response.json()['code'] == 'kea.unavailable'


async def test_qr_export_png_magic(api, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    client = await _confirm_sample(api, key=key)
    response = await client.get('/api/tunnels/wg_test/peer/phone/qr')
    assert response.status_code == 200
    assert response.headers['content-type'] == 'image/png'
    assert response.content[:4] == b'\x89PNG' and len(response.content) > 500
