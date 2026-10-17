"""The capture path ships complete: authorization, delivery and subscriber DNS.

Each of these three pieces was missing, and each was proven on a live panel before
being written here — the contour either captured nothing at all, or captured and
delivered nothing, or answered REFUSED to the clients it exists for.
"""
import base64

import pytest

from vs_router.generators.nftables import (generate_nftables,
                                           generate_tproxy_preauthorization)
from vs_router.generators.unbound import tproxy_unbound_listener_addresses
from vs_router.schema import ConfigurationVersion
from vs_router.secrets import encrypt_secret

SECRET = encrypt_secret('private-test-key-material', base64.urlsafe_b64encode(b's' * 32)).model_dump()
CAPTURE = 'ct mark & 0x200 == 0x200 counter accept comment "tproxy_captured"'


def configured(*, ingress=('lan0',), access_control=('10.212.0.0/16',), tunnel=True):
    config = {
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.212.1.1/24']},
            {'name': 'wan0', 'zone': 'wan', 'addresses': ['192.0.2.1/24']},
            {'name': 'tun0', 'zone': 'lan', 'addresses': ['10.212.2.1/24']},
        ],
        'dns': {'interfaces': list(ingress), 'access_control': list(access_control)},
        'tproxy': {'ingress_interfaces': list(ingress)},
    }
    if tunnel:
        config['tunnels'] = [{'name': 'vpn', 'interface': 'tun0', 'role': 'server',
                              'protocol': 'wg', 'listen_port': 51820,
                              'private_key': SECRET}]
    base = ConfigurationVersion.model_validate({'configuration': config})
    tproxy = base.configuration.tproxy.model_copy(update={'enabled': True})
    return base.model_copy(update={'configuration': base.configuration.model_copy(
        update={'tproxy': tproxy})})


def test_captured_traffic_is_acceptable_only_when_the_contour_is_enabled():
    on = generate_nftables(configured())
    off = generate_nftables(ConfigurationVersion.model_validate({'configuration': {
        'interfaces': [{'name': 'lan0', 'zone': 'lan', 'addresses': ['10.212.1.1/24']}],
    }}))
    assert CAPTURE in on
    assert CAPTURE not in off
    # It is an INPUT decision, after conntrack, and the mark it keys on is written
    # only by the interception table.
    assert on.index('ct state established,related accept') < on.index(CAPTURE)
    assert on.index(CAPTURE) < on.index('chain forward')


def test_tunnel_forwarding_is_authorized_for_capture():
    text = generate_tproxy_preauthorization(configured())
    assert ('iifname "tun0" meta nfproto ipv4 meta mark set meta mark | 0x400 '
            'counter return comment "preauth_vpn_forward"') in text
    # Nothing wider is authorized: the chain still ends in the containment drop.
    assert text.rstrip().endswith('counter drop\n    }\n}')


def test_tunnel_without_a_wan_zone_authorizes_nothing():
    version = configured()
    stripped = version.model_copy(update={'configuration': version.configuration.model_copy(
        update={'interfaces': tuple(i for i in version.configuration.interfaces
                                    if i.zone != 'wan')})})
    assert 'preauth_vpn_forward' not in generate_tproxy_preauthorization(stripped)


def test_a_resolver_that_refuses_its_subscribers_is_rejected():
    with pytest.raises(ValueError, match='tproxy.dns_access_control_missing'):
        tproxy_unbound_listener_addresses(configured(access_control=()))
    with pytest.raises(ValueError, match='tproxy.dns_access_control_missing'):
        tproxy_unbound_listener_addresses(configured(access_control=('10.99.0.0/16',)))
    assert tproxy_unbound_listener_addresses(
        configured(access_control=('10.212.1.0/24',)))['selected'] == ('10.212.1.1',)
