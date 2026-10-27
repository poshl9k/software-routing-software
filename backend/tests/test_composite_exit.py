"""Composite URL-test exits and client-tunnel handshake visibility (no host/network)."""
import base64
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from vs_router.api import tunnels as tunnels_api
from vs_router.app import create_app
from vs_router.db import ConfigurationRow
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion

pytestmark = pytest.mark.anyio

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}
SERVER_KEY = 'S' * 44


def document(*, enabled=False, members=None):
    if members is None:
        members = [
            {'kind': 'tunnel', 'name': 'client_vpn'},
            {'kind': 'outbound', 'tag': 'proxy1'},
            {'kind': 'interface', 'interface': 'uplink'},
        ]
    return {
        'interfaces': [
            {'name': 'tun1'},
            {'name': 'wg0'},
            {'name': 'uplink', 'zone': 'wan', 'addresses': ['198.51.100.2/24']},
        ],
        'tunnels': [
            {'name': 'client_vpn', 'interface': 'tun1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET, 'endpoint': 'vpn.example:51820',
             'server_public_key': SERVER_KEY},
            {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
             'protocol': 'wg', 'private_key': SECRET, 'listen_port': 51821},
        ],
        'proxies': {'enabled': enabled,
                    'outbounds': [{'tag': 'proxy1', 'type': 'vless',
                                   'server': 'proxy.example', 'port': 443}],
                    'groups': [{'tag': 'auto', 'type': 'urltest', 'exits': members,
                                'url': 'https://probe.example/204',
                                'interval_minutes': 5, 'tolerance_ms': 80}]},
        'routing_rules': [{'name': 'via_auto', 'ip_cidr': ['203.0.113.0/24'],
                           'exit': {'kind': 'group', 'tag': 'auto'}}],
    }


def version(data):
    return ConfigurationVersion.model_validate({'profile': 'panel', 'configuration': data})


def invalid(data, code):
    with pytest.raises(ValidationError, match=code):
        version(data)


def test_composite_urltest_all_three_member_kinds_and_order():
    saved = version(document())
    assert [e.model_dump(exclude_none=True) for e in saved.configuration.proxies.groups[0].exits] == [
        {'kind': 'tunnel', 'name': 'client_vpn'},
        {'kind': 'outbound', 'tag': 'proxy1'},
        {'kind': 'interface', 'interface': 'uplink'},
    ]
    assert len(saved.configuration.proxies.groups[0].exits) == 3
    assert saved.configuration.model_dump(mode='json')['proxies']['groups'][0]['exits'] == [
        {'kind': 'tunnel', 'name': 'client_vpn'},
        {'kind': 'outbound', 'tag': 'proxy1'},
        {'kind': 'interface', 'interface': 'uplink'},
    ]
    output = generate_singbox(saved)
    by_tag = {o['tag']: o for o in output['outbounds']}
    assert by_tag['auto'] == {'type': 'urltest', 'tag': 'auto',
                              'outbounds': ['routing-tunnel:client_vpn', 'proxy1', 'exit_uplink'],
                              'url': 'https://probe.example/204',
                              'interval': '5m', 'tolerance': 80}
    assert by_tag['routing-tunnel:client_vpn'] == {
        'type': 'direct', 'tag': 'routing-tunnel:client_vpn', 'bind_interface': 'tun1'}
    assert by_tag['exit_uplink'] == {'type': 'direct', 'tag': 'exit_uplink',
                                      'bind_interface': 'uplink'}
    assert by_tag['proxy1']['type'] == 'vless'
    assert output['route']['rules'][0] == {
        'ip_cidr': ['203.0.113.0/24'], 'action': 'route', 'outbound': 'auto'}
    assert output['route']['final'] == 'direct'  # Disabled legacy proxies stay disabled.
    assert set(by_tag) == {'direct', 'auto', 'proxy1', 'exit_uplink',
                           'routing-tunnel:client_vpn'}
    assert all(tag in by_tag for tag in by_tag['auto']['outbounds'])
    assert generate_singbox(saved) == output
    assert 'ciphertext' not in json.dumps(output)


def test_reference_render_when_disabled_and_unreferenced_when_enabled():
    data = document(enabled=False)
    data['routing_rules'] = []
    assert generate_singbox(version(data))['outbounds'] == [{'type': 'direct', 'tag': 'direct'}]
    data['proxies']['enabled'] = True
    rendered = generate_singbox(version(data))
    tags = {o['tag'] for o in rendered['outbounds']}
    assert {'auto', 'proxy1', 'routing-tunnel:client_vpn', 'exit_uplink'} <= tags
    assert rendered['route']['final'] == 'auto'


@pytest.mark.parametrize('members,code', [
    ([{'kind': 'tunnel', 'name': 'server_vpn'}], 'routing.tunnel_client_required'),
    ([{'kind': 'interface', 'interface': 'wg0'}], 'routing.tunnel_client_required'),
    ([{'kind': 'tunnel', 'name': 'missing'}], 'routing.tunnel_reference'),
    ([{'kind': 'interface', 'interface': 'missing'}], 'routing.exit_interface_reference'),
    ([{'kind': 'outbound', 'tag': 'missing'}], 'routing.outbound_reference'),
    ([{'kind': 'tunnel', 'name': 'client_vpn'}] * 2, 'proxy.group_duplicate_member'),
    ([{'kind': 'direct'}], 'proxy.group_exit_kind'),
    ([{'kind': 'block'}], 'proxy.group_exit_kind'),
    ([{'kind': 'group', 'tag': 'auto'}], 'proxy.group_exit_kind'),
])
def test_invalid_composite_members(members, code):
    invalid(document(members=members), code)


def test_mixed_empty_and_selector_rejected():
    data = document()
    data['proxies']['groups'][0]['outbounds'] = ['proxy1']
    invalid(data, 'proxy.group_mixed_members')
    data = document(members=[])
    invalid(data, 'proxy.group_empty')
    data = document()
    data['proxies']['groups'][0]['type'] = 'selector'
    invalid(data, 'proxy.group_exits_urltest_required')


def test_collisions_with_declared_and_sanitized_generated_tags():
    data = document(members=[{'kind': 'interface', 'interface': 'uplink'}])
    data['proxies']['outbounds'].append({'tag': 'exit_uplink', 'type': 'direct'})
    invalid(data, 'proxy.tag_collision')
    data = document(members=[{'kind': 'interface', 'interface': 'eth.0'},
                             {'kind': 'interface', 'interface': 'eth-0'}])
    data['interfaces'].extend([{'name': 'eth.0'}, {'name': 'eth-0'}])
    invalid(data, 'proxy.tag_collision')
    data = document(members=[{'kind': 'interface', 'interface': 'uplink'}])
    data['proxies']['groups'].append({'tag': 'exit_uplink', 'type': 'selector',
                                     'outbounds': ['proxy1']})
    invalid(data, 'proxy.tag_collision')


def test_composite_nested_under_legacy_selector_and_shared_exit_dedup():
    data = document()
    data['proxies']['groups'].append({'tag': 'outer', 'type': 'selector',
                                     'outbounds': ['auto']})
    data['routing_rules'][0]['exit']['tag'] = 'outer'
    data['routing_rules'].append({'name': 'also_tunnel', 'ip_cidr': ['192.0.2.0/24'],
                                  'exit': {'kind': 'tunnel', 'name': 'client_vpn'}})
    rendered = generate_singbox(version(data))
    tags = [outbound['tag'] for outbound in rendered['outbounds']]
    assert set(tags) == {'direct', 'outer', 'auto', 'proxy1',
                         'routing-tunnel:client_vpn', 'exit_uplink'}
    assert len(tags) == len(set(tags))
    assert next(o for o in rendered['outbounds'] if o['tag'] == 'outer')['outbounds'] == ['auto']


def test_unreferenced_composite_still_validates_references():
    data = document(members=[{'kind': 'tunnel', 'name': 'server_vpn'}])
    data['routing_rules'] = []
    invalid(data, 'routing.tunnel_client_required')


def test_no_implicit_direct_or_wan_and_explicit_wan_only():
    data = document(members=[{'kind': 'tunnel', 'name': 'client_vpn'},
                             {'kind': 'outbound', 'tag': 'proxy1'}])
    group = next(o for o in generate_singbox(version(data))['outbounds'] if o['tag'] == 'auto')
    assert group['outbounds'] == ['routing-tunnel:client_vpn', 'proxy1']
    assert 'direct' not in group['outbounds'] and 'exit_uplink' not in group['outbounds']
    assert 'exit_uplink' not in {o['tag'] for o in generate_singbox(version(data))['outbounds']}


def test_legacy_group_serialization_and_rendering_unchanged():
    data = document()
    data['proxies']['groups'] = [{'tag': 'auto', 'type': 'urltest',
                                  'outbounds': ['proxy1'], 'interval_minutes': 5}]
    saved = version(data)
    group = saved.configuration.model_dump(mode='json')['proxies']['groups'][0]
    assert 'exits' not in group
    assert group['outbounds'] == ['proxy1']
    rendered = generate_singbox(saved)
    assert {'tag': 'auto', 'type': 'urltest', 'outbounds': ['proxy1'],
            'interval': '5m'} in rendered['outbounds']


@pytest.fixture
async def api(tmp_path):
    url = f"sqlite:///{tmp_path / 'composite.db'}"
    config = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    config.set_main_option('sqlalchemy.url', url)
    command.upgrade(config, 'head')
    engine = create_engine(url, connect_args={'check_same_thread': False})
    async with AsyncClient(transport=ASGITransport(app=create_app(engine)),
                           base_url='https://router.test') as client:
        yield client, engine
    engine.dispose()


async def setup_client(api, monkeypatch):
    client, engine = api
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    creds = {'username': 'admin', 'password': 'correct-password'}
    assert (await client.post('/api/setup', json=creds)).status_code == 201
    assert (await client.post('/api/auth/login', json=creds)).status_code == 200
    data = document()
    data['proxies'] = {'enabled': False}
    data['routing_rules'] = []
    data['tunnels'][0]['private_key'] = {
        'plaintext': base64.b64encode(b'k' * 32).decode()}
    data['tunnels'][1]['private_key'] = {
        'plaintext': base64.b64encode(b'q' * 32).decode()}
    response = await client.post('/api/draft', json=data)
    assert response.status_code == 201, response.text
    return client, engine


async def test_availability_auth_unapplied_and_no_server(api, monkeypatch):
    client, engine = api
    call = Mock()
    monkeypatch.setattr(tunnels_api, 'agent_call', call)
    assert (await client.get('/api/tunnels/availability')).status_code == 401
    call.assert_not_called()
    await setup_client(api, monkeypatch)
    response = await client.get('/api/tunnels/availability')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == {'client_vpn': {'state': 'unknown', 'last_handshake': None}}
    call.assert_not_called()  # Draft-only tunnel is not applied.
    with Session(engine) as db:
        row = db.scalars(select(ConfigurationRow)).first()
        assert row is not None
        row.status = 'confirmed'
        db.commit()
    call.return_value = {'tun1': [{'public_key': SERVER_KEY, 'latest_handshake': 0}]}
    assert (await client.get('/api/tunnels/availability')).json() == {
        'client_vpn': {'state': 'never_handshaked', 'last_handshake': 0}}
    call.assert_called_with('tunnel_activity', {})


@pytest.mark.parametrize('stamp,expected', [
    (0, 'never_handshaked'), (820, 'recent_handshake'), (821, 'recent_handshake'),
    (819, 'stale_handshake'),
])
async def test_availability_handshake_threshold(api, monkeypatch, stamp, expected):
    client, engine = await setup_client(api, monkeypatch)
    with Session(engine) as db:
        row = db.scalars(select(ConfigurationRow)).first()
        assert row is not None
        row.status = 'confirmed'
        db.commit()
    monkeypatch.setattr(tunnels_api.time, 'time', lambda: 1000)
    call = Mock(return_value={'tun1': [
        {'public_key': 'not-server', 'latest_handshake': 999},
        {'public_key': SERVER_KEY, 'latest_handshake': stamp, 'endpoint': 'private'},
    ]})
    monkeypatch.setattr(tunnels_api, 'agent_call', call)
    response = await client.get('/api/tunnels/availability')
    assert response.status_code == 200
    assert response.json() == {'client_vpn': {'state': expected, 'last_handshake': stamp}}
    assert 'private' not in response.text and SERVER_KEY not in response.text


@pytest.mark.parametrize('live', [
    None, [], {'tun1': None}, {'tun1': []}, {'tun1': [{}]},
    {'tun1': [{'public_key': 'different', 'latest_handshake': 0}]},
    {'tun1': [{'public_key': SERVER_KEY, 'latest_handshake': None}]},
    {'tun1': [{'public_key': SERVER_KEY, 'latest_handshake': True}]},
    {'tun1': [{'public_key': SERVER_KEY, 'latest_handshake': '999'}]},
    {'tun1': [{'public_key': SERVER_KEY, 'latest_handshake': 1001}]},
])
async def test_availability_malformed_and_missing_telemetry_unknown(api, monkeypatch, live):
    client, engine = await setup_client(api, monkeypatch)
    with Session(engine) as db:
        row = db.scalars(select(ConfigurationRow)).first()
        assert row is not None
        row.status = 'confirmed'
        db.commit()
    monkeypatch.setattr(tunnels_api.time, 'time', lambda: 1000)
    monkeypatch.setattr(tunnels_api, 'agent_call', Mock(return_value=live))
    assert (await client.get('/api/tunnels/availability')).json() == {
        'client_vpn': {'state': 'unknown', 'last_handshake': None}}


async def test_availability_agent_failure_and_changed_draft_unknown(api, monkeypatch):
    client, engine = await setup_client(api, monkeypatch)
    with Session(engine) as db:
        row = db.scalars(select(ConfigurationRow)).first()
        assert row is not None
        row.status = 'confirmed'
        db.commit()
    call = Mock(side_effect=RuntimeError('agent unavailable'))
    monkeypatch.setattr(tunnels_api, 'agent_call', call)
    assert (await client.get('/api/tunnels/availability')).json() == {
        'client_vpn': {'state': 'unknown', 'last_handshake': None}}
    # New draft changes the server identity; old live handshake is not evidence.
    with Session(engine) as db:
        confirmed = db.scalars(select(ConfigurationRow)).first()
        assert confirmed is not None
        changed = confirmed.configuration.model_copy(update={
            'tunnels': tuple(t.model_copy(update={'server_public_key': 'N' * 44})
                             if t.role == 'client' else t
                             for t in confirmed.configuration.tunnels)})
        db.add(ConfigurationRow(status='draft', profile='panel', configuration=changed))
        db.commit()
    call.return_value = {'tun1': [{'public_key': 'N' * 44, 'latest_handshake': 999}]}
    call.side_effect = None
    assert (await client.get('/api/tunnels/availability')).json() == {
        'client_vpn': {'state': 'unknown', 'last_handshake': None}}
