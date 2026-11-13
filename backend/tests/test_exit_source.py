"""A bound exit may pin its source address and its next hop (split-routing S3).

``bind_interface`` alone only forces the egress link; the kernel still chooses the
source by route and the gateway by the main table. On a client tunnel that source
is wrong and the peer drops the packet; on a link with two upstream routers the
main table can only prefer one default, so the second one is unreachable without a
policy route keyed by the source address.
"""
import pytest

from vs_router.api.configuration import parse_configuration
from vs_router.api.errors import APIError
from vs_router.generators.networkd import exit_policy_routes, generate_networkd
from vs_router.generators.nftables import generate_nftables
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import Configuration, ConfigurationVersion, Exit

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document(exit_value):
    return {
        'schema_version': 1,
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.10.10.1/24']},
            {'name': 'wan0', 'zone': 'wan',
             'addresses': ['192.168.170.10/16', '192.168.180.10/16']},
            {'name': 'wg1', 'addresses': ['10.66.66.5/32']},
        ],
        'tunnels': [
            {'name': 'client_vpn', 'interface': 'wg1', 'role': 'client',
             'protocol': 'wg', 'private_key': SECRET,
             'endpoint': 'vpn.example:51820', 'server_public_key': 'S' * 44},
        ],
        'routing_rules': [
            {'name': 'seg', 'subject': {'kind': 'interface', 'interface': 'lan0'},
             'ip_cidr': ['0.0.0.0/0'], 'exit': exit_value},
        ],
    }


def version(exit_value):
    parsed = parse_configuration(document(exit_value))
    return ConfigurationVersion(configuration=Configuration.model_validate(parsed))


def test_tunnel_exit_with_source_binds_the_address():
    data = generate_singbox(version({'kind': 'tunnel', 'name': 'client_vpn',
                                     'source': '10.66.66.5'}))
    outbound = next(o for o in data['outbounds'] if o.get('bind_interface') == 'wg1')
    assert outbound['inet4_bind_address'] == '10.66.66.5'


def test_exit_without_source_keeps_the_old_shape():
    data = generate_singbox(version({'kind': 'tunnel', 'name': 'client_vpn'}))
    outbound = next(o for o in data['outbounds'] if o.get('bind_interface') == 'wg1')
    assert 'inet4_bind_address' not in outbound


def test_source_must_be_an_address_of_the_exit_link():
    with pytest.raises(APIError) as failure:
        version({'kind': 'tunnel', 'name': 'client_vpn', 'source': '10.66.66.9'})
    assert any(detail['message'] == 'routing.exit_source_not_on_interface'
               for detail in failure.value.details), failure.value.details


def test_source_is_rejected_for_unbound_exits():
    with pytest.raises(ValueError):
        Exit(kind='direct', source='10.66.66.5')


def test_source_must_be_an_address_literal():
    with pytest.raises(ValueError):
        Exit(kind='interface', interface='lan0', source='not-an-address')


def test_gateway_and_source_produce_a_policy_route():
    parsed = version({'kind': 'interface', 'interface': 'wan0',
                      'source': '192.168.180.10', 'gateway': '192.168.116.254'})
    text = generate_networkd(parsed)['10-vs-router-wan0.network']
    assert '[RoutingPolicyRule]' in text
    assert 'From=192.168.180.10' in text
    assert 'Table=1000' in text
    assert 'Gateway=192.168.116.254' in text
    assert 'PreferredSource=192.168.180.10' in text


def test_policy_tables_are_stable_and_distinct():
    configuration = Configuration.model_validate(parse_configuration(document(
        {'kind': 'interface', 'interface': 'wan0',
         'source': '192.168.180.10', 'gateway': '192.168.116.254'})))
    assert exit_policy_routes(configuration)['wan0'][0][2] == 1000
    extra = configuration.routing_rules[0].model_copy(update={
        'name': 'seg2',
        'exit': configuration.routing_rules[0].exit.model_copy(update={
            'source': '192.168.170.10', 'gateway': '192.168.107.1'})})
    configuration = configuration.model_copy(
        update={'routing_rules': configuration.routing_rules + (extra,)})
    tables = [table for _source, _gateway, table in exit_policy_routes(configuration)['wan0']]
    assert tables == [1000, 1001]


def test_pinned_exit_nats_to_its_own_address_before_masquerade():
    text = generate_nftables(version({'kind': 'interface', 'interface': 'wan0',
                                      'source': '192.168.180.10',
                                      'gateway': '192.168.116.254'}))
    snat = [line for line in text.splitlines() if 'snat ip to 192.168.180.10' in line]
    masquerade = [line for line in text.splitlines() if 'counter masquerade' in line]
    assert snat and masquerade
    assert text.index(snat[0]) < text.index(masquerade[0])
    # Only the segment that chose this exit is re-addressed, never the whole link.
    assert '10.10.10.0/24' in snat[0]
    assert '192.168.170.0/16' not in snat[0]


def test_gateway_without_source_is_rejected():
    with pytest.raises(APIError) as failure:
        version({'kind': 'interface', 'interface': 'wan0', 'gateway': '192.168.116.254'})
    assert any(detail['message'] == 'routing.exit_gateway_without_source'
               for detail in failure.value.details), failure.value.details


def test_gateway_outside_every_subnet_of_the_link_is_rejected():
    with pytest.raises(APIError) as failure:
        version({'kind': 'interface', 'interface': 'wan0',
                 'source': '192.168.180.10', 'gateway': '203.0.113.1'})
    assert any(detail['message'] == 'routing.exit_gateway_unreachable'
               for detail in failure.value.details), failure.value.details


def test_one_source_cannot_pin_two_gateways():
    parsed = document({'kind': 'interface', 'interface': 'wan0',
                       'source': '192.168.180.10', 'gateway': '192.168.116.254'})
    parsed['routing_rules'].append({
        'name': 'seg_other', 'subject': {'kind': 'server'},
        'ip_cidr': ['198.51.100.0/24'],
        'exit': {'kind': 'interface', 'interface': 'wan0',
                 'source': '192.168.180.10', 'gateway': '192.168.107.1'}})
    with pytest.raises(APIError) as failure:
        parse_configuration(parsed)
    assert any(detail['message'] == 'routing.exit_source_conflict'
               for detail in failure.value.details), failure.value.details


def test_two_exits_on_one_link_get_distinct_outbounds():
    """Same interface, different source: each segment must keep its own provider."""
    parsed = document({'kind': 'interface', 'interface': 'wan0',
                       'source': '192.168.180.10', 'gateway': '192.168.116.254'})
    parsed['routing_rules'].append({
        'name': 'seg2', 'subject': {'kind': 'server'}, 'ip_cidr': ['0.0.0.0/0'],
        'exit': {'kind': 'interface', 'interface': 'wan0',
                 'source': '192.168.170.10', 'gateway': '192.168.107.1'}})
    configuration = ConfigurationVersion(configuration=Configuration.model_validate(
        parse_configuration(parsed)))
    outbounds = [o for o in generate_singbox(configuration)['outbounds']
                 if o.get('bind_interface') == 'wan0']
    assert len(outbounds) == 2
    assert {o['tag'] for o in outbounds} == {'exit_wan0_192_168_180_10',
                                             'exit_wan0_192_168_170_10'}
    assert {o['inet4_bind_address'] for o in outbounds} == {'192.168.180.10',
                                                            '192.168.170.10'}
