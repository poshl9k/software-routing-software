"""Coverage for the MVP-gap endpoints: aliases import/export, backup round-trip,
diagnostics parsing/validation, Kea leases error handling and tunnel QR export."""
import base64
import json
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
    assert restored.status_code == 409
    assert restored.json()['code'] == 'draft.exists'
    assert (await client.delete('/api/draft')).status_code == 204
    restored = await client.post('/api/backup/restore', json=archive)
    assert restored.status_code == 409
    assert restored.json()['code'] == 'backup.partial_requires_confirmation'
    assert (await client.get('/api/versions')).json() == []
    restored = await client.post('/api/backup/restore', json={**archive, 'allow_partial': True})
    assert restored.status_code == 200
    assert restored.json()['restored'] == 1
    # Import is an unapplied draft, never a fake confirmed host snapshot.
    versions = (await client.get('/api/versions')).json()
    assert len(versions) == 1
    assert versions[0]['status'] == 'draft'
    assert versions[0]['configuration']['tunnels'] == []


async def test_backup_import_only_latest_as_draft_keeps_confirmed_history(api):
    from vs_router.db import ConfigurationRow, Session
    client = await _confirm_sample(api)
    _, engine, _ = api
    with Session(engine) as session:
        row = session.get(ConfigurationRow, 1)
        assert row is not None
        row.status = 'confirmed'
        session.commit()
    archive = (await client.get('/api/backup/export')).json()
    newer = {**archive['versions'][0], 'id': 42,
             'configuration': {**archive['versions'][0]['configuration'], 'aliases': []}}
    archive['versions'].append(newer)
    response = await client.post('/api/backup/restore', json={**archive, 'allow_partial': True})
    assert response.status_code == 200
    assert response.json() == {'restored': 1, 'skipped': 1}
    versions = (await client.get('/api/versions')).json()
    assert [(v['id'], v['status']) for v in versions] == [(2, 'draft'), (1, 'confirmed')]
    assert versions[0]['configuration']['aliases'] == []
    assert versions[1]['configuration']['aliases'] != []


async def test_backup_import_does_not_parse_skipped_history(api):
    client = await _confirm_sample(api)
    archive = (await client.get('/api/backup/export')).json()
    archive['versions'].insert(0, {'invalid': 'skipped'})
    assert (await client.delete('/api/draft')).status_code == 204
    response = await client.post('/api/backup/restore', json={**archive, 'allow_partial': True})
    assert response.status_code == 200
    assert response.json() == {'restored': 1, 'skipped': 1}


async def test_password_backup_export_uses_post_body(api, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    client = await _confirm_sample(api, key=key)
    response = await client.post('/api/backup/export', json={
        'include_secrets': True, 'password': 'local-example-password',
    })
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json()['versions'][0]['secret_blob']['ciphertext']
    assert response.json()['versions'][0]['configuration']['tunnels'][0]['private_key'] == {'redacted': True}
    legacy = await client.get('/api/backup/export', params={'include_secrets': 'true', 'password': 'ignored'})
    assert legacy.status_code == 200
    assert 'secret_blob' not in legacy.json()['versions'][0]


async def test_password_backup_import_rejects_different_host_key(api, monkeypatch):
    from vs_router.api.backup import _derive_key
    from vs_router.db import ConfigurationRow, Session
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    client = await _confirm_sample(api, key=key)
    archive = (await client.post('/api/backup/export', json={
        'include_secrets': True, 'password': 'example-password',
    })).json()
    # Old archives wrapped host-key ciphertext without a format tag.
    with Session(api[1]) as db:
        source = db.get(ConfigurationRow, 1)
        assert source is not None
        configuration = source.snapshot().model_dump(mode='json')['configuration']
    salt = os.urandom(16)
    archive['versions'][0]['secret_blob'] = {
        'salt': base64.b64encode(salt).decode(),
        'ciphertext': Fernet(_derive_key('example-password', salt)).encrypt(
            json.dumps(configuration).encode()).decode(),
    }
    assert (await client.delete('/api/draft')).status_code == 204
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    response = await client.post('/api/backup/restore', json={**archive, 'password': 'example-password'})
    assert response.status_code == 400
    assert response.json()['code'] == 'backup.secret_key_mismatch'
    assert (await client.get('/api/versions')).json() == []
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    response = await client.post('/api/backup/restore', json={**archive, 'password': 'example-password'})
    assert response.status_code == 200
    versions = (await client.get('/api/versions')).json()
    assert versions[0]['status'] == 'draft'
    assert len(versions[0]['configuration']['tunnels']) == 1


async def test_password_backup_import_requires_archive_password(api, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    client = await _confirm_sample(api, key=key)
    archive = (await client.post('/api/backup/export', json={
        'include_secrets': True, 'password': 'example-password',
    })).json()
    assert (await client.delete('/api/draft')).status_code == 204
    response = await client.post('/api/backup/restore', json=archive)
    assert response.status_code == 400
    assert response.json()['code'] == 'backup.password_required'
    assert (await client.get('/api/versions')).json() == []


async def test_password_backup_reencrypts_secrets_for_another_host(api, monkeypatch):
    from vs_router.db import ConfigurationRow, Session
    from vs_router.schema import Configuration
    from vs_router.secrets import decrypt_secret
    source_key = Fernet.generate_key()
    target_key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', source_key.decode())
    client = await _confirm_sample(api, key=source_key.decode())
    _, engine, _ = api
    with Session(engine) as db:
        source = db.get(ConfigurationRow, 1)
        assert source is not None
        updated = source.configuration.model_dump(mode='json')
        updated['tunnels'][0]['peers'][0]['preshared_key'] = encrypt_secret(
            'ephemeral-peer-key', source_key).model_dump(mode='json')
        source.configuration = Configuration.model_validate(updated)
        db.commit()
        original = source.configuration.tunnels[0].private_key
        original_peer = source.configuration.tunnels[0].peers[0].preshared_key
    archive = (await client.post('/api/backup/export', json={
        'include_secrets': True, 'password': 'example-password',
    })).json()
    assert archive['versions'][0]['secret_blob']['format'] == 'plaintext-v1'
    assert 'ephemeral-peer-key' not in json.dumps(archive)
    assert decrypt_secret(original, source_key) not in json.dumps(archive)
    assert (await client.delete('/api/draft')).status_code == 204
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', target_key.decode())
    rejected = await client.post('/api/backup/restore', json={**archive, 'password': 'wrong-password'})
    assert rejected.status_code == 400
    assert rejected.json()['code'] == 'backup.bad_payload'
    assert (await client.get('/api/versions')).json() == []
    response = await client.post('/api/backup/restore', json={**archive, 'password': 'example-password'})
    assert response.status_code == 200
    with Session(engine) as db:
        imported = db.get(ConfigurationRow, 1)
        assert imported is not None
        replacement = imported.configuration.tunnels[0].private_key
        replacement_peer = imported.configuration.tunnels[0].peers[0].preshared_key
    assert replacement.ciphertext != original.ciphertext
    assert decrypt_secret(replacement, target_key) == decrypt_secret(original, source_key)
    assert original_peer is not None and replacement_peer is not None
    assert replacement_peer.ciphertext != original_peer.ciphertext
    assert decrypt_secret(replacement_peer, target_key) == decrypt_secret(original_peer, source_key)


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
    monkeypatch.setenv('VS_ROUTER_KEA_CTRL_URL', 'http://127.0.0.1:1/')
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


async def test_peer_keypair_endpoint_and_export(api, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key)
    client = await _confirm_sample(api, key=key)
    client, engine, now = api
    pair = await client.post('/api/keygen/peer-keypair')
    assert pair.status_code == 200
    body = pair.json()
    assert len(base64.b64decode(body['private_key'])) == 32
    assert len(base64.b64decode(body['public_key'])) == 32

    # a peer with a panel-generated private key exports a complete client config
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from sqlalchemy import select as _select
    from vs_router.db import ConfigurationRow
    from vs_router.secrets import decrypt_secret
    raw_private = base64.b64decode(body['private_key'])
    public = base64.b64encode(X25519PrivateKey.from_private_bytes(raw_private)
                              .public_key().public_bytes_raw()).decode()
    with __import__('vs_router.db', fromlist=['Session']).Session(engine) as session:
        config = session.scalar(_select(ConfigurationRow)
                                .order_by(ConfigurationRow.id.desc())).snapshot().configuration
    tunnel = config.model_copy(update={
        'tunnels': tuple(
            t.model_copy(update={'peers': tuple(
                p.model_copy(update={'public_key': public,
                                     'private_key': encrypt_secret(body['private_key'], key.encode())})
                if i == 0 else p for i, p in enumerate(t.peers))})
            for t in config.tunnels)})
    await client.put('/api/draft', json=config.model_dump(mode='json'))
    exported = await client.get('/api/tunnels/wg_test/peer/phone/qr')
    assert exported.status_code == 200
    from vs_router.generators.wireguard import generate_wg_bundle
    version = __import__('vs_router.schema', fromlist=['ConfigurationVersion']).ConfigurationVersion(
        id=1, status='draft', configuration=tunnel)
    bundle = generate_wg_bundle(version, {})
    conf = bundle['wg_test.peer-phone.conf']
    assert 'TEMPLATE' not in conf
    assert f"PrivateKey = {body['private_key']}" in conf
    # [Peer] PublicKey in a client config is the SERVER's derived public key
    assert 'PublicKey = ' in conf
