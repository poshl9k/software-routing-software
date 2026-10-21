"""Routing vocabulary (ADR-0029) — R1..R9 tests plus report parent R10."""
import json
import pytest
from pydantic import ValidationError

from vs_router.api.configuration import parse_configuration
from vs_router.api.errors import APIError
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import Configuration, ConfigurationVersion, Exit, RoutingSubject
from vs_router.validators import (
    routing_exit_tag,
    routing_referenced_tags,
    routing_subject_interface_cidrs,
)

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document():
    return {
        'schema_version': 1,
        'subscribers': [{'name': 'alice'}, {'name': 'bob'}],
        'interfaces': [
            {'name': 'lan', 'addresses': ['192.168.10.1/24']},
            {'name': 'wg0', 'addresses': ['10.0.0.1/24', 'fd00::1/64']},
            {'name': 'tun1'},
            {'name': 'wan', 'zone': 'wan', 'addresses': ['198.51.100.2/24']},
        ],
        'tunnels': [
            {'name': 'server_vpn', 'interface': 'wg0', 'role': 'server',
             'protocol': 'wg', 'listen_port': 51820, 'private_key': SECRET,
             'peers': [{'name': 'phone', 'public_key': 'P' * 44,
                        'subscriber': 'alice', 'allowed_ips': ['10.66.66.2/32']},
                       {'name': 'transport', 'public_key': 'Q' * 44}]},
            {'name': 'client_vpn', 'interface': 'tun1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET,
             'endpoint': 'vpn.example:51820', 'server_public_key': 'S' * 44},
        ],
        'routing_rules': [],
    }


def invalid(document_value, code):
    with pytest.raises(APIError) as failure:
        parse_configuration(document_value)
    assert failure.value.code == 'configuration.invalid'
    assert any(detail.get('message') == code for detail in failure.value.details)


def render(data, enabled=False):
    data = dict(data)
    data.setdefault('proxies', {'enabled': False, 'outbounds': [], 'groups': []})
    data['proxies']['enabled'] = enabled
    return generate_singbox(ConfigurationVersion.model_validate({
        'profile': 'panel', 'configuration': data}))


# R1 — Exit vocabulary and exactly-one-field rule
@pytest.mark.parametrize('payload,code', [
    ({'kind': 'outbound'}, 'routing.outbound_tag_required'),
    ({'kind': 'group'}, 'routing.exit_field_required'),
    ({'kind': 'interface'}, 'routing.exit_field_required'),
    ({'kind': 'tunnel'}, 'routing.tunnel_name_required'),
])
def test_criterion_R1_required_fields(payload, code):
    with pytest.raises(ValidationError, match=code):
        Exit(**payload)


@pytest.mark.parametrize('payload', [
    {'kind': 'direct', 'tag': 'proxy1'},
    {'kind': 'direct', 'name': 'client_vpn'},
    {'kind': 'direct', 'interface': 'lan'},
    {'kind': 'block', 'tag': 'proxy1'},
    {'kind': 'block', 'interface': 'lan'},
    {'kind': 'block', 'name': 'client_vpn'},
    {'kind': 'outbound', 'tag': 'proxy1', 'name': 'client_vpn'},
    {'kind': 'outbound', 'tag': 'proxy1', 'interface': 'lan'},
    {'kind': 'group', 'tag': 'auto', 'name': 'client_vpn'},
    {'kind': 'group', 'tag': 'auto', 'interface': 'lan'},
    {'kind': 'tunnel', 'name': 'client_vpn', 'tag': 'auto'},
    {'kind': 'tunnel', 'name': 'client_vpn', 'interface': 'lan'},
    {'kind': 'interface', 'interface': 'lan', 'tag': 'auto'},
    {'kind': 'interface', 'interface': 'lan', 'name': 'client_vpn'},
])
def test_criterion_R1_forbidden_fields(payload):
    with pytest.raises(ValidationError, match='routing.exit_fields_unexpected'):
        Exit(**payload)


def test_criterion_R1_allowed_combinations():
    assert Exit(kind='direct').kind == 'direct'
    assert Exit(kind='block').kind == 'block'
    assert Exit(kind='outbound', tag='proxy1').tag == 'proxy1'
    assert Exit(kind='group', tag='auto').tag == 'auto'
    assert Exit(kind='tunnel', name='client_vpn').name == 'client_vpn'
    assert Exit(kind='interface', interface='lan').interface == 'lan'


# R2 — RoutingSubject vocabulary
def test_criterion_R2_interface_subject_required_and_forbidden():
    with pytest.raises(ValidationError, match='routing.exit_field_required'):
        RoutingSubject(kind='interface')
    assert RoutingSubject(kind='interface', interface='lan').interface == 'lan'
    with pytest.raises(ValidationError, match='routing.subject_fields_unexpected'):
        RoutingSubject(kind='interface', interface='lan', subscriber='alice')
    with pytest.raises(ValidationError, match='routing.subject_fields_unexpected'):
        RoutingSubject(kind='interface', interface='lan', peer='phone')


@pytest.mark.parametrize('payload', [
    {'kind': 'server', 'subscriber': 'alice'},
    {'kind': 'server', 'peer': 'phone'},
    {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone', 'interface': 'lan'},
])
def test_criterion_R2_subject_fields_unexpected(payload):
    with pytest.raises(ValidationError, match='routing.subject_fields_unexpected'):
        RoutingSubject(**payload)


@pytest.mark.parametrize('payload', [
    {'kind': 'device'},
    {'kind': 'device', 'subscriber': 'alice'},
    {'kind': 'device', 'peer': 'phone'},
])
def test_criterion_R2_device_required_preserved(payload):
    with pytest.raises(ValidationError, match='routing.device_required'):
        RoutingSubject(**payload)


# R3 — Exit reference validation
def test_criterion_R3_exit_group_reference():
    data = document()
    data['routing_rules'] = [{'name': 'g', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'group', 'tag': 'missing'}}]
    invalid(data, 'routing.exit_group_reference')


def test_criterion_R3_exit_interface_reference():
    data = document()
    data['routing_rules'] = [{'name': 'i', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'interface', 'interface': 'nope'}}]
    invalid(data, 'routing.exit_interface_reference')


def test_criterion_R3_interface_exit_must_be_declared_interface():
    data = document()
    data['routing_rules'] = [{'name': 'i', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'interface', 'interface': 'lan'}}]
    assert parse_configuration(data).routing_rules[0].exit.interface == 'lan'


def test_criterion_R3_non_client_tunnel_refused():
    data = document()
    data['routing_rules'] = [{'name': 't', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'tunnel', 'name': 'server_vpn'}}]
    invalid(data, 'routing.tunnel_client_required')


def test_criterion_R3_outbound_missing_reference():
    data = document()
    data['routing_rules'] = [{'name': 'o', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'outbound', 'tag': 'missing'}}]
    invalid(data, 'routing.outbound_reference')


# R4 — Subject reference validation
def test_criterion_R4_subject_interface_reference():
    data = document()
    data['routing_rules'] = [{'name': 's', 'ip_cidr': ['192.0.2.0/24'],
                              'subject': {'kind': 'interface', 'interface': 'nope'}}]
    invalid(data, 'routing.subject_interface_reference')


def test_criterion_R4_subject_interface_tunnel_interface_ok():
    data = document()
    data['routing_rules'] = [{'name': 's', 'ip_cidr': ['192.0.2.0/24'],
                              'subject': {'kind': 'interface', 'interface': 'wg0'}}]
    assert parse_configuration(data).routing_rules[0].subject.interface == 'wg0'


def test_criterion_R4_device_reference_legacy_preserved():
    data = document()
    data['routing_rules'] = [{'name': 'd', 'ip_cidr': ['192.0.2.0/24'],
                              'subject': {'kind': 'device', 'subscriber': 'alice',
                                          'peer': 'phone'}}]
    assert parse_configuration(data).routing_rules[0].subject.subscriber == 'alice'


# R5 — Subject-interface resolution
def test_criterion_R5_interface_ipv4_skip_ipv6():
    config = Configuration.model_validate(document())
    cidrs = routing_subject_interface_cidrs(config, 'lan')
    assert cidrs == ('192.168.10.0/24',)


def test_criterion_R5_interface_ipv6_only_no_address():
    data = document()
    data['interfaces'] = [i for i in data['interfaces'] if i['name'] not in ('lan', 'wg0')]
    data['interfaces'].append({'name': 'v6', 'addresses': ['fd00::1/64']})
    data['tunnels'] = []
    config = Configuration.model_validate(data)
    with pytest.raises(ValueError, match='routing.subject_interface_no_address'):
        routing_subject_interface_cidrs(config, 'v6')


def test_criterion_R5_tunnel_interface_uses_subscriber_peers():
    config = Configuration.model_validate(document())
    # wg0 carries the server tunnel: its subscriber peers' AllowedIPs are the
    # device sources, the interface address itself is not.
    cidrs = routing_subject_interface_cidrs(config, 'wg0')
    assert cidrs == ('10.66.66.2/32',)


def test_criterion_R5_tunnel_interface_no_subscriber_peer_no_address():
    data = document()
    for peer in data['tunnels'][0]['peers']:
        peer.pop('subscriber', None)
    config = Configuration.model_validate(data)
    with pytest.raises(ValueError, match='routing.subject_interface_no_address'):
        routing_subject_interface_cidrs(config, 'wg0')


def test_criterion_R5_subject_interface_no_address_on_configuration():
    data = document()
    data['routing_rules'] = [{'name': 's', 'ip_cidr': ['192.0.2.0/24'],
                              'subject': {'kind': 'interface', 'interface': 'tun1'}}]
    invalid(data, 'routing.subject_interface_no_address')


# R6 — Exit rendering
def test_criterion_R6_block_reject_rule():
    data = document()
    data['routing_rules'] = [{'name': 'b', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'block'}}]
    output = render(data)
    assert output['route']['rules'][0] == {'ip_cidr': ['192.0.2.0/24'], 'action': 'reject'}


def test_criterion_R6_group_route_and_render():
    data = document()
    data['routing_rules'] = [{'name': 'g', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'group', 'tag': 'group1'}}]
    data['proxies'] = {'enabled': True,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': [{'tag': 'group1', 'type': 'selector',
                                   'outbounds': ['proxy1']}]}
    output = render(data, enabled=True)
    assert any(r.get('outbound') == 'group1' for r in output['route']['rules'])
    tags = [outbound['tag'] for outbound in output['outbounds']]
    assert 'group1' in tags


def test_criterion_R6_interface_exit_json():
    data = document()
    data['routing_rules'] = [{'name': 'i', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'interface', 'interface': 'lan'}}]
    output = render(data)
    tag = 'exit_lan'
    # First rule is our interface-exit rule (followed by device rejects)
    assert {'action': 'route', 'ip_cidr': ['192.0.2.0/24'], 'outbound': tag} == output['route']['rules'][0]
    assert {'type': 'direct', 'tag': tag, 'bind_interface': 'lan'} in output['outbounds']


def test_criterion_R6_interface_exit_sanitized_tag():
    assert routing_exit_tag(Exit(kind='interface', interface='eth.0')) == 'exit_eth_0'
    data = document()
    data['routing_rules'] = [{'name': 'i', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'interface', 'interface': 'eth.0'}}]
    data['interfaces'].append({'name': 'eth.0', 'addresses': ['192.168.20.1/24']})
    output = render(data)
    assert {'type': 'direct', 'tag': 'exit_eth_0',
            'bind_interface': 'eth.0'} in output['outbounds']


def test_criterion_R6_interface_tag_collision_with_declared_tag():
    data = document()
    data['routing_rules'] = [{'name': 'i', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'interface', 'interface': 'lan'}}]
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'exit_lan', 'type': 'direct'}],
                       'groups': []}
    with pytest.raises(ValidationError, match='proxy.tag_collision'):
        render(data)


def test_criterion_R6_tunnel_and_interface_dedup():
    data = document()
    data['routing_rules'] = [
        {'name': 'a', 'ip_cidr': ['192.0.2.0/24'],
         'exit': {'kind': 'tunnel', 'name': 'client_vpn'}},
        {'name': 'b', 'ip_cidr': ['198.51.100.0/24'],
         'exit': {'kind': 'tunnel', 'name': 'client_vpn'}},
    ]
    output = render(data)
    rules = output['route']['rules']
    assert rules[0]['outbound'] == 'routing-tunnel:client_vpn'
    assert rules[1]['outbound'] == 'routing-tunnel:client_vpn'
    bound = [o for o in output['outbounds'] if o.get('tag') == 'routing-tunnel:client_vpn']
    assert len(bound) == 1


def test_criterion_R6_legacy_output_unchanged():
    data = document()
    data['routing_rules'] = [{'name': 's', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'outbound', 'tag': 'proxy1'}}]
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': []}
    output = render(data)
    assert {'action': 'route', 'ip_cidr': ['192.0.2.0/24'], 'outbound': 'proxy1'} == output['route']['rules'][0]
    assert {'type': 'direct', 'tag': 'proxy1'} in output['outbounds']


# R7 — referenced groups render with proxies disabled
def test_criterion_R7_group_with_members_rendered_when_disabled():
    data = document()
    data['routing_rules'] = [{'name': 'g', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'group', 'tag': 'group1'}}]
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': [{'tag': 'group1', 'type': 'selector',
                                   'outbounds': ['proxy1']}]}
    output = render(data)
    tags = [o['tag'] for o in output['outbounds']]
    assert 'group1' in tags and 'proxy1' in tags


def test_criterion_R7_nested_group_transitive_members_rendered():
    data = document()
    data['routing_rules'] = [{'name': 'g', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'group', 'tag': 'group1'}}]
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'},
                                     {'tag': 'proxy2', 'type': 'direct'}],
                       'groups': [{'tag': 'group1', 'type': 'selector',
                                   'outbounds': ['proxy1', 'inner']},
                                  {'tag': 'inner', 'type': 'urltest',
                                   'outbounds': ['proxy2']}]}
    output = render(data)
    tags = [o['tag'] for o in output['outbounds']]
    assert {'group1', 'inner', 'proxy1', 'proxy2'} <= set(tags)


def test_criterion_R7_missing_group_member_refused():
    data = document()
    data['routing_rules'] = [{'name': 'g', 'ip_cidr': ['192.0.2.0/24'],
                              'exit': {'kind': 'group', 'tag': 'group1'}}]
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': [{'tag': 'group1', 'type': 'selector',
                                   'outbounds': ['proxy1', 'ghost']}]}
    invalid(data, 'routing.exit_group_member_missing')


def test_criterion_R7_unrelated_legacy_group_still_group_reference():
    data = document()
    data['proxies'] = {'enabled': False,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': [{'tag': 'auto', 'type': 'selector',
                                   'outbounds': ['ghost']}]}
    invalid(data, 'proxy.group_reference')


# R8 — fail-closed
def test_criterion_R8_block_reject_and_unmatched_device_reject():
    data = document()
    data['routing_rules'] = [
        {'name': 'p', 'ip_cidr': ['198.51.100.0/24'],
         'subject': {'kind': 'device', 'subscriber': 'alice', 'peer': 'phone'},
         'exit': {'kind': 'block'}},
    ]
    output = render(data)
    rules = output['route']['rules']
    assert any(r.get('action') == 'reject' for r in rules)
    assert any(r.get('action') == 'reject' and 'source_ip_cidr' in r for r in rules)


# R9 — docstrings state kinds and exactly-one-field rule
def test_criterion_R9_exit_docstring():
    doc = Exit.__doc__ or ''
    for kind in ('direct', 'interface', 'outbound', 'group', 'tunnel', 'block'):
        assert kind in doc
    assert 'exactly one' in doc.lower() or 'only' in doc.lower()


def test_criterion_R9_subject_docstring():
    doc = RoutingSubject.__doc__ or ''
    for kind in ('server', 'device', 'interface'):
        assert kind in doc


# R10 — report format
def test_criterion_R10_report_contains_json_fragments():
    data = document()
    data['routing_rules'] = [
        {'name': 'interface', 'ip_cidr': ['192.0.2.0/24'],
         'subject': {'kind': 'interface', 'interface': 'lan'},
         'exit': {'kind': 'interface', 'interface': 'wan'}},
    ]
    output = render(data)
    # interface subject renders as a source_ip_cidr matcher
    assert output['route']['rules'][0]['source_ip_cidr'] == ['192.168.10.0/24']
    # interface exit renders a bound direct outbound
    assert {'type': 'direct', 'tag': 'exit_wan', 'bind_interface': 'wan'} in output['outbounds']

    data = document()
    data['routing_rules'] = [
        {'name': 'group', 'ip_cidr': ['192.0.2.0/24'],
         'exit': {'kind': 'group', 'tag': 'group1'}},
    ]
    data['proxies'] = {'enabled': True,
                       'outbounds': [{'tag': 'proxy1', 'type': 'direct'}],
                       'groups': [{'tag': 'group1', 'type': 'selector',
                                   'outbounds': ['proxy1']}]}
    output = render(data, enabled=True)
    assert {'action': 'route', 'ip_cidr': ['192.0.2.0/24'], 'outbound': 'group1'} == output['route']['rules'][0]
    assert {'tag': 'group1', 'type': 'selector', 'outbounds': ['proxy1']} in output['outbounds']