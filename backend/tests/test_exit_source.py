"""A bound exit may pin its source address (ADR: split-routing S3).

``bind_interface`` alone only forces the egress link; the kernel still chooses the
source by route. On a client tunnel that choice is wrong and the remote peer drops
every packet under cryptokey routing, so the exit has to state its own address.
"""
import pytest

from vs_router.api.configuration import parse_configuration
from vs_router.api.errors import APIError
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import Configuration, ConfigurationVersion, Exit

SECRET = {'encrypted': True, 'ciphertext': 'gAAAAplaceholder'}


def document(exit_value):
    return {
        'schema_version': 1,
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.10.10.1/24']},
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
