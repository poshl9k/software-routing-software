"""Routing policy contract and profile safety, without host networking."""
import json
from ipaddress import ip_address, ip_network
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.fernet import Fernet

from scenarios import scenario
from test_agent_apply import FakeExecutor, FakeFS
from vs_router.agent import apply as apply_mod, tproxy_apply
from vs_router.agent.apply import ApplyEngine, ApplyError, host_files
from vs_router.api.configuration import parse_configuration, structural_diff, validate
from vs_router.api.errors import APIError
from vs_router.api.versions import diff_summary
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.secrets import encrypt_secret


SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document():
    return {
        'schema_version': 1,
        'subscribers': [{'name': 'alice'}, {'name': 'bob'}],
        'interfaces': [{'name': 'wg0'}, {'name': 'wg1'}],
        'tunnels': [
            {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
             'protocol': 'wg', 'listen_port': 51820, 'private_key': SECRET,
             'peers': [{'name': 'phone', 'public_key': 'P' * 44,
                        'subscriber': 'alice'},
                       {'name': 'laptop', 'public_key': 'Q' * 44,
                        'subscriber': 'bob'},
                       {'name': 'transport', 'public_key': 'R' * 44}]},
            {'name': 'client_vpn', 'interface': 'wg1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET,
             'endpoint': 'vpn.example:51820', 'server_public_key': 'S' * 44},
        ],
        'proxies': {'enabled': False, 'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                    'groups': [{'tag': 'group1', 'type': 'selector',
                                'outbounds': ['proxy1']}]},
    }


def rule(name='site', **overrides):
    return {'name': name, 'ip_cidr': ['203.0.113.0/24'], **overrides}


def invalid(document_value, code):
    with pytest.raises(APIError) as failure:
        parse_configuration(document_value)
    assert failure.value.code == 'configuration.invalid'
    assert any(detail['message'] == code for detail in failure.value.details), failure.value.details


def test_router_tproxy_accepts_product_policy_without_legacy_rule():
    data = {
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['192.0.2.1/24']},
            {'name': 'wan0', 'zone': 'wan'},
        ],
        'tproxy': {'enabled': True, 'ingress_interfaces': ['lan0']},
        'routing_rules': [rule(subject={'kind': 'interface', 'interface': 'lan0'})],
    }
    version = ConfigurationVersion.model_validate({'profile': 'router', 'configuration': data})
    assert tproxy_apply.required(version)
    assert {'source_ip_cidr': ['192.0.2.0/24'], 'ip_cidr': ['203.0.113.0/24'],
            'action': 'route', 'outbound': 'direct'} in generate_singbox(version)['route']['rules']

    data['routing_rules'] = []
    invalid(data, 'tproxy.enabled_incomplete')


def test_criterion_1_roundtrip_diff_and_tproxy_isolation():
    data = document()
    data['routing_rules'] = [
        rule('straight'),
        rule('proxied', subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             domain_suffix=['example.org'], exit={'kind': 'outbound', 'tag': 'proxy1'}),
        rule('tunneled', exit={'kind': 'tunnel', 'name': 'client_vpn'}),
    ]
    parsed = parse_configuration(data)
    assert parsed.schema_version == 1
    assert [r.exit.kind for r in parsed.routing_rules] == ['direct', 'outbound', 'tunnel']
    assert [r.subject.kind for r in parsed.routing_rules] == ['server', 'device', 'server']
    assert parsed.routing_rules[0].exit.tag is None
    assert parsed.routing_rules[0].subject.peer is None
    assert parse_configuration(json.loads(parsed.model_dump_json())) == parsed
    before = Configuration()
    changes = structural_diff(before.model_dump(mode='json'), parsed.model_dump(mode='json'))
    assert any(c['path'].startswith('/routing_rules/') for c in changes)
    assert next(row for row in diff_summary(changes) if row['area'] == 'routing_rules')['title'] == 'Правила маршрутизации'
    assert parsed.tproxy == before.tproxy
    assert not any(c['path'].startswith('/tproxy') for c in changes)


def test_criterion_2_destination_required():
    data = document()
    data['routing_rules'] = [{'name': 'empty'}]
    invalid(data, 'routing.destination_required')


@pytest.mark.parametrize('target,code', [
    ({'kind': 'outbound', 'tag': 'missing'}, 'routing.outbound_reference'),
    ({'kind': 'outbound', 'tag': 'group1'}, 'routing.outbound_reference'),
    ({'kind': 'outbound', 'tag': 'direct'}, 'routing.outbound_reference'),
    ({'kind': 'tunnel', 'name': 'missing'}, 'routing.tunnel_reference'),
])
def test_criterion_3_missing_or_non_outbound_reference(target, code):
    data = document()
    data['routing_rules'] = [rule(exit=target)]
    invalid(data, code)


def test_criterion_3_disabled_proxies_still_declare_outbound():
    data = document()
    data['routing_rules'] = [rule(exit={'kind': 'outbound', 'tag': 'proxy1'})]
    assert parse_configuration(data).proxies.enabled is False


def test_criterion_4_server_tunnel_cannot_be_exit():
    data = document()
    data['routing_rules'] = [rule(exit={'kind': 'tunnel', 'name': 'server_vpn'})]
    invalid(data, 'routing.tunnel_client_required')


@pytest.mark.parametrize('subject,code', [
    ({'kind': 'device', 'subscriber': 'missing', 'peer': 'phone'}, 'routing.subscriber_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'missing'}, 'routing.device_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'laptop'}, 'routing.device_reference'),
    ({'kind': 'device', 'subscriber': 'alice', 'peer': 'transport'}, 'routing.device_reference'),
])
def test_criterion_5_device_reference_requires_own_bound_peer(subject, code):
    data = document()
    data['routing_rules'] = [rule(subject=subject)]
    invalid(data, code)


def test_criterion_5_same_peer_name_other_subscriber_does_not_resolve():
    data = document()
    data['tunnels'][0]['peers'].append(
        {'name': 'shared', 'public_key': 'T' * 44, 'subscriber': 'bob'})
    data['routing_rules'] = [rule(subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'shared'})]
    invalid(data, 'routing.device_reference')
    data['tunnels'][0]['peers'].append(
        {'name': 'shared', 'public_key': 'U' * 44, 'subscriber': 'alice'})
    assert parse_configuration(data).routing_rules[0].subject.subscriber == 'alice'


def test_criterion_5_ambiguous_only_within_own_subscriber():
    data = document()
    data['tunnels'][1]['role'] = 'server'
    data['tunnels'][1].pop('endpoint')
    data['tunnels'][1].pop('server_public_key')
    data['tunnels'][1]['listen_port'] = 51821
    data['tunnels'][1]['peers'] = [
        {'name': 'phone', 'public_key': 'T' * 44, 'subscriber': 'alice'}]
    assert parse_configuration(data).tunnels[1].peers[0].name == 'phone'
    data['routing_rules'] = [rule(subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'})]
    invalid(data, 'routing.device_ambiguous')


@pytest.mark.parametrize('destinations', [
    {'domain_suffix': ['example.org']},
    {'domain_exact': ['example.org']},
    {'ip_cidr': ['2001:db8::/32'], 'domain_exact': ['example.org']},
])
def test_criterion_6_own_dns_device_rejects_domain_destinations(destinations):
    data = document()
    data['tunnels'][0]['peers'][0]['dns_mode'] = 'own'
    data['routing_rules'] = [{'name': 'domain', 'subject': {
        'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}, **destinations}]
    invalid(data, 'routing.domain_rule_own_resolvers')


def test_criterion_6_ip_only_panel_dns_and_server_rules_valid():
    data = document()
    data['tunnels'][0]['peers'][0]['dns_mode'] = 'own'
    data['routing_rules'] = [
        rule('ipv6', subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             ip_cidr=['2001:db8::/32']),
        rule('panel', subject={'kind': 'device', 'subscriber': 'bob', 'peer': 'laptop'},
             ip_cidr=[], domain_suffix=['example.org']),
        rule('server', ip_cidr=[], domain_exact=['example.org']),
    ]
    assert len(parse_configuration(data).routing_rules) == 3


def test_criterion_7_router_apply_refuses_device_policy_before_effects(monkeypatch):
    data = document()
    data['routing_rules'] = [rule(subject={
        'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'})]
    assert parse_configuration(data).routing_rules[0].subject.kind == 'device'
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    fs, executor = FakeFS(), FakeExecutor()
    management = Mock(side_effect=AssertionError('management probe must not run'))
    panel_probe = Mock(side_effect=AssertionError('panel probe must not run'))
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which),
                         management_provider=management, panel_probe=panel_probe)
    with pytest.raises(ApplyError) as failure:
        engine.apply_version({'id': 1, 'profile': 'router', 'configuration': data})
    assert failure.value.code == 'profile.subscribers_not_supported'
    assert fs.files == {}
    assert executor.calls == []
    management.assert_not_called()
    panel_probe.assert_not_called()

    data['subscribers'] = []
    for peer in data['tunnels'][0]['peers']:
        peer.pop('subscriber', None)
    with pytest.raises(ValueError, match='routing.subscriber_reference'):
        engine.apply_version({'id': 2, 'profile': 'router', 'configuration': data})
    assert fs.files == {}
    assert executor.calls == []
    management.assert_not_called()
    panel_probe.assert_not_called()


def test_criterion_8_legacy_document_parses_validates_and_applies(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    old = {'schema_version': 1, 'interfaces': [{'name': 'wg0'}],
           'tunnels': [{'name': 'vpn', 'interface': 'wg0', 'role': 'server',
                        'protocol': 'wg', 'listen_port': 51820,
                        'private_key': encrypt_secret('A' * 43 + '=', key).model_dump(),
                        'peers': [{'name': 'phone', 'public_key': 'P' * 44}]}]}
    parsed = parse_configuration(old)
    assert parsed.schema_version == 1
    assert parsed.routing_rules == ()
    assert parsed.tunnels[0].peers[0].dns_mode == 'panel'
    assert validate(old)['valid'] is True
    assert ConfigurationVersion.model_validate({'id': 1, 'configuration': old}).configuration == parsed
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which))
    result = engine.apply_version({'id': 1, 'profile': 'router', 'configuration': old})
    assert result.status == 'confirmed', result.error
    assert executor.calls
    assert fs.files
    assert json.loads(fs.read(apply_mod.APPLIED_DIR / 'snapshot.json'))['configuration'] == old


@pytest.mark.parametrize('exit_value,code', [
    ({'kind': 'outbound'}, 'routing.outbound_tag_required'),
    ({'kind': 'tunnel'}, 'routing.tunnel_name_required'),
    ({'kind': 'direct', 'tag': 'proxy1'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'direct', 'name': 'client_vpn'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'outbound', 'tag': 'proxy1', 'name': 'client_vpn'}, 'routing.exit_fields_unexpected'),
    ({'kind': 'tunnel', 'name': 'client_vpn', 'tag': 'proxy1'}, 'routing.exit_fields_unexpected'),
])
def test_exit_shape(exit_value, code):
    data = document()
    data['routing_rules'] = [rule(exit=exit_value)]
    invalid(data, code)


@pytest.mark.parametrize('subject,code', [
    ({'kind': 'device'}, 'routing.device_required'),
    ({'kind': 'device', 'subscriber': 'alice'}, 'routing.device_required'),
    ({'kind': 'device', 'peer': 'phone'}, 'routing.device_required'),
    ({'kind': 'server', 'subscriber': 'alice'}, 'routing.subject_fields_unexpected'),
    ({'kind': 'server', 'peer': 'phone'}, 'routing.subject_fields_unexpected'),
])
def test_subject_shape(subject, code):
    data = document()
    data['routing_rules'] = [rule(subject=subject)]
    invalid(data, code)


@pytest.mark.parametrize('destination,code', [
    ({'ip_cidr': ['not-a-cidr']}, 'routing.ip_cidr_invalid'),
    ({'domain_suffix': ['bad domain']}, 'routing.domain_invalid'),
    ({'domain_exact': ['bad/domain']}, 'routing.domain_invalid'),
])
def test_destination_shape(destination, code):
    data = document()
    data['routing_rules'] = [{'name': 'invalid', **destination}]
    invalid(data, code)


def test_duplicate_rule_names():
    data = document()
    data['routing_rules'] = [rule(), rule()]
    invalid(data, 'routing.duplicate_name')


def minimal_render_document():
    """Small panel document shared with the routing renderer tests."""
    return {
        'schema_version': 1,
        'subscribers': [{'name': 'alice'}],
        'interfaces': [{'name': 'wg0'}, {'name': 'tun1'}],
        'tunnels': [
            {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
             'protocol': 'wg', 'listen_port': 51820, 'private_key': SECRET,
             'peers': [{'name': 'phone', 'public_key': 'P' * 44,
                        'subscriber': 'alice', 'allowed_ips': ['10.66.66.2/32']}]},
            {'name': 'client_vpn', 'interface': 'tun1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET, 'endpoint': 'vpn.example:51820',
             'server_public_key': 'S' * 44},
        ],
        'routing_rules': [
            {'name': 'tunnel_domain', 'domain_suffix': ['example.org'],
             'subject': {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             'exit': {'kind': 'tunnel', 'name': 'client_vpn'}},
            {'name': 'server_direct', 'ip_cidr': ['192.0.2.0/24']},
        ],
    }


def render_document(data):
    return generate_singbox(ConfigurationVersion.model_validate({
        'profile': 'panel', 'configuration': data,
    }))


def test_criterion_1_render_exits_order_and_tunnel_deduplication():
    data = minimal_render_document()
    data['proxies'] = {'enabled': False, 'outbounds': [{'tag': 'remote', 'type': 'direct'}]}
    data['routing_rules'] = [
        rule('z_direct', ip_cidr=['192.0.2.0/24']),
        rule('a_proxy', ip_cidr=['198.51.100.0/24'],
             exit={'kind': 'outbound', 'tag': 'remote'}),
        rule('b_tunnel', ip_cidr=[], domain_suffix=['example.org'],
             exit={'kind': 'tunnel', 'name': 'client_vpn'}),
        rule('c_tunnel', ip_cidr=['203.0.113.0/24'],
             exit={'kind': 'tunnel', 'name': 'client_vpn'}),
    ]
    output = render_document(data)
    assert [r['outbound'] for r in output['route']['rules'][:4]] == [
        'direct', 'remote', 'routing-tunnel:client_vpn', 'routing-tunnel:client_vpn']
    assert output['outbounds'].count({'type': 'direct', 'tag': 'routing-tunnel:client_vpn',
                                      'bind_interface': 'tun1'}) == 1
    assert sum(o['tag'] == 'remote' for o in output['outbounds']) == 1


def test_criterion_2_render_device_all_addresses_and_server_without_source():
    data = minimal_render_document()
    data['tunnels'][0]['peers'][0]['allowed_ips'] = ['10.66.66.2/32', '2001:db8::2/128']
    data['routing_rules'] = [
        rule('device', subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}),
        rule('server', ip_cidr=['192.0.2.0/24']),
    ]
    rules = render_document(data)['route']['rules']
    assert rules[0]['source_ip_cidr'] == ['10.66.66.2/32', '2001:db8::2/128']
    assert 'source_ip_cidr' not in rules[1]
    assert rules[2] == {'source_ip_cidr': ['10.66.66.2/32', '2001:db8::2/128'],
                        'action': 'reject'}
    data['tunnels'][0]['peers'][0]['allowed_ips'] = []
    with pytest.raises(ValueError, match='routing.device_address_required'):
        render_document(data)


def test_criterion_3_render_destination_matchers_and_mixed_fields() -> None:
    data = minimal_render_document()
    data['routing_rules'] = [
        rule('ip', ip_cidr=['192.0.2.0/24']),
        rule('suffix', ip_cidr=[], domain_suffix=['example.org']),
        rule('exact', ip_cidr=[], domain_exact=['api.example.org']),
        # Two destination families -> sing-box AND-s everything inside one flat
        # rule, so "network AND domain" matches nothing intentionally. The fix
        # makes the destination families a logical OR nested behind the subject
        # matcher, see Slice 3b / B3-2:
        rule('mixed', ip_cidr=['2001:db8::/32'], domain_suffix=['example.net'],
             domain_exact=['api.example.net']),
    ]
    rules = render_document(data)['route']['rules']
    assert rules == [
        {'ip_cidr': ['192.0.2.0/24'], 'action': 'route', 'outbound': 'direct'},
        {'domain_suffix': ['example.org'], 'action': 'route', 'outbound': 'direct'},
        {'domain': ['api.example.org'], 'action': 'route', 'outbound': 'direct'},
        {
            'type': 'logical', 'mode': 'or',
            'rules': [{'ip_cidr': ['2001:db8::/32']}, {'domain_suffix': ['example.net']},
                      {'domain': ['api.example.net']}],
            'action': 'route', 'outbound': 'direct',
        },
        {'source_ip_cidr': ['10.66.66.2/32'], 'action': 'reject'},
    ]
    assert not any(r.get('action') == 'sniff' for r in rules)


@pytest.mark.parametrize('enabled', [False, True])
def test_criterion_4_render_reference_integrity_and_existing_final(enabled):
    data = minimal_render_document()
    data['proxies'] = {'enabled': enabled,
                       'outbounds': [{'tag': 'remote', 'type': 'vless',
                                      'server': '203.0.113.5', 'port': 443},
                                     {'tag': 'unused', 'type': 'direct'}],
                       'groups': [{'tag': 'select', 'type': 'selector',
                                   'outbounds': ['remote']}]}
    data['routing_rules'].append(rule('proxy', exit={'kind': 'outbound', 'tag': 'remote'}))
    output = render_document(data)
    tags = [outbound['tag'] for outbound in output['outbounds']]
    assert len(tags) == len(set(tags))
    assert output['route']['final'] == ('select' if enabled else 'direct')
    assert output['route']['final'] in tags
    for row in output['route']['rules']:
        if 'outbound' in row:
            assert row['outbound'] in tags
    for outbound in output['outbounds']:
        for child in outbound.get('outbounds', []):
            assert child in tags
    assert next(o for o in output['outbounds'] if o['tag'] == 'remote') == {
        'type': 'vless', 'tag': 'remote', 'server': '203.0.113.5', 'server_port': 443,
        'uuid': '00000000-0000-0000-0000-000000000000',
    }
    assert ('unused' in tags) is enabled
    assert not any(o['type'] == 'block' for o in output['outbounds'])
    assert not any(key in output for key in ('binary', 'root', 'network', 'nftables', 'ip_rules'))


@pytest.mark.parametrize('final', ['direct', 'select'])
def test_criterion_5_render_unmatched_devices_reject_before_legacy_egress(final):
    data = minimal_render_document()
    if final == 'select':
        data['proxies'] = {'enabled': True,
                           'outbounds': [{'tag': 'remote', 'type': 'direct'}],
                           'groups': [{'tag': 'select', 'type': 'selector',
                                       'outbounds': ['remote']}]}
    data['tunnels'][0]['peers'].append(
        {'name': 'tablet', 'public_key': 'Q' * 44, 'subscriber': 'alice',
         'allowed_ips': ['10.66.66.3/32', '2001:db8::3/128']})
    data['routing_rules'] = [
        rule('permitted', ip_cidr=['198.51.100.0/24'],
             subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'}),
        rule('unavailable_tunnel', ip_cidr=[], domain_suffix=['example.org'],
             subject={'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
             exit={'kind': 'tunnel', 'name': 'client_vpn'}),
    ]
    data['tproxy'] = {'bypass': [{'name': 'legacy_direct', 'source_ip_cidr': ['10.66.66.0/24']}],
                      'rules': [{'name': 'legacy', 'ip_cidr': ['203.0.113.0/24'],
                                 'action': 'direct'}]}
    rules = render_document(data)['route']['rules']
    assert rules[0]['outbound'] == 'direct'
    assert rules[1]['outbound'] == 'routing-tunnel:client_vpn'
    assert rules[2] == {'source_ip_cidr': ['10.66.66.2/32', '10.66.66.3/32',
                                          '2001:db8::3/128'], 'action': 'reject'}
    assert rules.index(rules[2]) < next(i for i, r in enumerate(rules)
                                        if r.get('source_ip_cidr') == ['10.66.66.0/24'])
    # For each device address, first terminal match for an unmatched destination is reject.
    for source in ('10.66.66.2', '10.66.66.3', '2001:db8::3'):
        for destination in ('8.8.8.8', '203.0.113.7'):
            candidates = [r for r in rules if r.get('action') in ('route', 'reject')
                          and (not r.get('source_ip_cidr') or any(
                              ip_address(source) in ip_network(cidr)
                              for cidr in r['source_ip_cidr']))
                          and (not r.get('ip_cidr') or any(
                              ip_address(destination) in ip_network(cidr)
                              for cidr in r['ip_cidr']))
                          and not any(k in r for k in ('domain', 'domain_suffix'))]
            assert candidates[0]['action'] == 'reject'
    assert render_document(data)['route']['final'] == final


def test_criterion_6_render_exact_pipeline_repeat_and_no_mutation():
    data = minimal_render_document()
    data['routing_rules'] = [rule('z_first'), rule('a_second', ip_cidr=['198.51.100.0/24'])]
    data['tproxy'] = {'sniff': True, 'udp_timeout_seconds': 60,
                      'bypass': [{'name': 'bypass', 'ip_cidr': ['192.0.2.0/24']}],
                      'rules': [{'name': 'later', 'ip_cidr': ['203.0.113.0/24'],
                                 'order': 20, 'action': 'block'},
                                {'name': 'sooner', 'ip_cidr': ['198.51.100.0/24'],
                                 'order': 10, 'action': 'direct'}]}
    version = ConfigurationVersion.model_validate({'profile': 'panel', 'configuration': data})
    before = version.model_dump_json()
    output = generate_singbox(version)
    assert output['route']['rules'] == [
        {'action': 'sniff'}, {'action': 'route-options', 'udp_timeout': '60s'},
        {'ip_cidr': ['203.0.113.0/24'], 'action': 'route', 'outbound': 'direct'},
        {'ip_cidr': ['198.51.100.0/24'], 'action': 'route', 'outbound': 'direct'},
        {'source_ip_cidr': ['10.66.66.2/32'], 'action': 'reject'},
        {'ip_cidr': ['192.0.2.0/24'], 'action': 'route', 'outbound': 'direct'},
        {'ip_cidr': ['198.51.100.0/24'], 'action': 'route', 'outbound': 'direct'},
        {'ip_cidr': ['203.0.113.0/24'], 'action': 'reject'},
    ]
    assert generate_singbox(version) == output
    assert version.model_dump_json() == before


@pytest.mark.parametrize('name', ['empty', 'typical', 'edge'])
def test_criterion_7_render_empty_rules_byte_equal_legacy_golden(name):
    version = scenario(name)
    assert version.configuration.routing_rules == ()
    # Captured by executing the pre-slice renderer from 53dfc8d, not regenerated
    # from the implementation under test. These legacy scenarios share a route.
    expected = (Path(__file__).parent / 'golden' / 'singbox-legacy.json').read_bytes()
    assert (json.dumps(generate_singbox(version), indent=2) + '\n').encode() == expected


def test_criterion_8_render_panel_valid_router_refuses_before_generator(monkeypatch):
    data = minimal_render_document()
    assert render_document(data)['route']['rules'][0]['outbound'] == 'routing-tunnel:client_vpn'
    monkeypatch.setattr(apply_mod, 'read_profile', lambda: 'router')
    monkeypatch.setattr(apply_mod.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    generator = Mock(side_effect=AssertionError('generator must not run'))
    monkeypatch.setattr(tproxy_apply, 'generate_singbox', generator)
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         files=host_files(which=apply_mod.shutil.which))
    with pytest.raises(ApplyError) as failure:
        engine.apply_version({'id': 1, 'profile': 'router', 'configuration': data})
    assert failure.value.code == 'profile.subscribers_not_supported'
    generator.assert_not_called()
    assert fs.files == {}
    assert executor.calls == []
