"""Subscriber data contracts and host-profile apply policy; no host changes."""
import json
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

from test_agent_apply import FakeExecutor, FakeFS
from test_api import anyio_backend, api, sign_in
from vs_router.agent import apply as apply_mod
from vs_router.agent.apply import ApplyEngine, ApplyError, host_files
from vs_router.api import versions
from vs_router.api.configuration import parse_configuration, structural_diff, validate
from vs_router.api.errors import APIError
from vs_router.api.versions import diff_summary
from vs_router.db import ConfigurationRow
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.secrets import encrypt_secret

pytestmark = pytest.mark.anyio


def subscriber_document():
    return {
        'schema_version': 1,
        'subscribers': [{'name': 'alice', 'label': 'Home'},
                        {'name': 'bob', 'label': None}],
        'interfaces': [{'name': 'wg0'}],
        'tunnels': [{
            'name': 'vpn', 'interface': 'wg0', 'role': 'server', 'protocol': 'wg',
            'listen_port': 51820,
            'private_key': {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'},
            'peers': [
                {'name': 'phone', 'public_key': 'P' * 44, 'subscriber': 'alice'},
                {'name': 'laptop', 'public_key': 'Q' * 44, 'subscriber': 'alice'},
                {'name': 'tablet', 'public_key': 'R' * 44, 'subscriber': 'bob'},
                {'name': 'transport', 'public_key': 'S' * 44},
            ],
        }],
    }


def assert_validation_code(error, code):
    assert error.value.code == 'configuration.invalid'
    assert any(detail['message'] == code for detail in error.value.details)


def test_criterion_1_roundtrip_and_diff():
    document = subscriber_document()
    config = parse_configuration(document)
    assert [(s.name, s.label) for s in config.subscribers] == [('alice', 'Home'), ('bob', None)]
    assert [(p.name, p.subscriber) for p in config.tunnels[0].peers] == [
        ('phone', 'alice'), ('laptop', 'alice'), ('tablet', 'bob'), ('transport', None)]
    restored = parse_configuration(json.loads(config.model_dump_json()))
    assert restored == config
    assert restored.schema_version == 1

    before = Configuration()
    changes = structural_diff(before.model_dump(mode='json'), config.model_dump(mode='json'))
    assert any(c['path'].startswith('/subscribers/') for c in changes)
    unbound = json.loads(json.dumps(document))
    for peer in unbound['tunnels'][0]['peers']:
        peer.pop('subscriber', None)
    binding_changes = structural_diff(parse_configuration(unbound).model_dump(mode='json'),
                                      config.model_dump(mode='json'))
    assert any(c['path'] == '/tunnels/0/peers/0/subscriber' and
               c['before'] is None and c['after'] == 'alice' for c in binding_changes)
    summary = diff_summary(changes)
    assert next(row for row in summary if row['area'] == 'subscribers')['title'] == 'Абоненты'
    assert any(row['area'] == 'tunnels' for row in summary)


def test_criterion_2_duplicate_subscriber_names():
    document = subscriber_document()
    document['subscribers'].append({'name': 'alice', 'label': 'Another'})
    with pytest.raises(APIError) as failure:
        parse_configuration(document)
    assert_validation_code(failure, 'subscriber.duplicate_name')
    result = validate(document)
    assert result['valid'] is False
    assert result['errors'][0]['code'] == 'configuration.invalid'
    assert any(detail['message'] == 'subscriber.duplicate_name'
               for detail in result['errors'][0]['details'])


@pytest.mark.parametrize('name', ['', '1alice', 'alice-bob', 'alice bob', 'a' * 32])
def test_criterion_2_invalid_subscriber_name(name):
    document = subscriber_document()
    document['subscribers'][0]['name'] = name
    with pytest.raises(APIError) as failure:
        parse_configuration(document)
    assert failure.value.code == 'configuration.invalid'
    assert any(detail['path'] == ['subscribers', 0, 'name'] for detail in failure.value.details)
    result = validate(document)
    assert result['valid'] is False
    assert any(detail['path'] == ['subscribers', 0, 'name']
               for detail in result['errors'][0]['details'])


async def test_criterion_3_7_missing_subscriber_rejected_on_save(api, monkeypatch):
    client, database, _ = api
    monkeypatch.setattr(versions, 'live_peers', Mock())
    await sign_in(client)
    document = subscriber_document()
    document['tunnels'][0]['private_key'] = encrypt_secret('tunnel-key', Fernet.generate_key()).model_dump()
    orphan = json.loads(json.dumps(document))
    orphan['tunnels'][0]['peers'][0]['subscriber'] = 'missing'
    with pytest.raises(APIError) as failure:
        parse_configuration(orphan)
    assert_validation_code(failure, 'peer.subscriber_reference')

    rejected = await client.post('/api/draft', json=orphan)
    assert rejected.status_code == 422
    assert rejected.json()['code'] == 'configuration.invalid'
    assert any(row['message'] == 'peer.subscriber_reference' for row in rejected.json()['details'])
    assert (await client.get('/api/versions')).json() == []

    created = await client.post('/api/draft', json=document)
    assert created.status_code == 201, created.text
    assert created.json()['configuration']['tunnels'][0]['private_key'] == {'redacted': True}
    saved = created.json()['configuration']
    assert [s['name'] for s in saved['subscribers']] == ['alice', 'bob']
    assert saved['tunnels'][0]['peers'][0]['subscriber'] == 'alice'
    with Session(database) as session:
        persisted = session.get(ConfigurationRow, created.json()['id']).configuration
        assert persisted.tunnels[0].private_key.ciphertext == document['tunnels'][0]['private_key']['ciphertext']

    deleted = json.loads(json.dumps(saved))
    deleted['subscribers'] = [s for s in deleted['subscribers'] if s['name'] != 'alice']
    rejected = await client.put('/api/draft', json=deleted)
    assert rejected.status_code == 422
    assert rejected.json()['code'] == 'configuration.invalid'
    assert any(row['message'] == 'peer.subscriber_reference' for row in rejected.json()['details'])
    readback = (await client.get(f"/api/versions/{created.json()['id']}")).json()
    assert readback['configuration'] == saved
    assert readback['configuration']['tunnels'][0]['private_key'] == {'redacted': True}
    assert 'ciphertext' not in json.dumps(readback)
    with Session(database) as session:
        assert [s.name for s in session.get(ConfigurationRow, created.json()['id']).configuration.subscribers] == [
            'alice', 'bob']


def test_criterion_4_unbound_service_peer_valid():
    document = subscriber_document()
    config = parse_configuration(document)
    assert config.tunnels[0].peers[-1].subscriber is None
    document['subscribers'] = []
    document['tunnels'][0]['peers'] = [document['tunnels'][0]['peers'][-1]]
    service = parse_configuration(document)
    assert service.subscribers == ()
    assert service.tunnels[0].peers[0].subscriber is None
    explicit = json.loads(json.dumps(document))
    explicit['tunnels'][0]['peers'][0]['subscriber'] = None
    assert parse_configuration(explicit).tunnels[0].peers[0].subscriber is None


@pytest.mark.parametrize('marker,dhcp,version_profile,expected', [
    ('router', True, 'router', 'profile.subscribers_not_supported'),
    ('router', False, 'router', 'profile.capability_mismatch'),
    ('router', True, 'panel', 'configuration.profile_mismatch'),
    ('panel', False, 'panel', None),
    (None, True, 'router', None),
    (None, False, 'panel', None),
])
def test_criterion_5_apply_profile_guard_and_panel_success(
    monkeypatch, marker, dhcp, version_profile, expected,
):
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: marker)
    monkeypatch.setattr(apply_mod.shutil, 'which',
                        lambda name: f'/usr/sbin/{name}' if dhcp else None)
    fs, executor = FakeFS(), FakeExecutor()
    management = Mock(side_effect=AssertionError('management must not be probed'))
    probe = Mock(side_effect=AssertionError('panel must not be probed'))
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which),
                         management_provider=management if expected else None,
                         panel_probe=probe if expected else None)
    document = {'id': 1, 'profile': version_profile,
                'configuration': {'schema_version': 1, 'subscribers': [{'name': 'alice'}]}}
    if expected:
        with pytest.raises(ApplyError) as failure:
            engine.apply_version(document)
        assert failure.value.code == expected
        assert fs.files == {}
        assert executor.calls == []
        management.assert_not_called()
        probe.assert_not_called()
    else:
        result = engine.apply_version(document)
        assert result.status == 'confirmed'
        assert executor.calls
        assert fs.files


def test_criterion_6_legacy_document_parses_and_applies(monkeypatch):
    old = subscriber_document()
    old.pop('subscribers')
    for peer in old['tunnels'][0]['peers']:
        peer.pop('subscriber', None)
    parsed = parse_configuration(old)
    assert validate(old)['valid'] is True
    assert parsed.schema_version == 1
    assert parsed.subscribers == ()
    assert all(peer.subscriber is None for peer in parsed.tunnels[0].peers)
    assert ConfigurationVersion.model_validate({'id': 1, 'configuration': {}}).configuration.subscribers == ()

    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which))
    result = engine.apply_version({'id': 1, 'profile': 'router',
                                   'configuration': {'schema_version': 1}})
    assert result.status == 'confirmed'
    assert executor.calls
    assert fs.files
