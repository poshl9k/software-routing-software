"""Offline fixture for a VM-only DNS source-boundary experiment."""
import argparse
import json
from pathlib import Path

from vs_router.generators.nftables import (generate_nftables,
                                          generate_tproxy_containment,
                                          generate_tproxy_dns_ingress_guard,
                                          generate_tproxy_dns_listener_guard,
                                          generate_tproxy_preauthorization)
from vs_router.schema import ConfigurationVersion


def generate_cases():
    version = ConfigurationVersion.model_validate({'configuration': {
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.212.1.1/24']},
            {'name': 'lan1', 'zone': 'lan', 'addresses': ['10.212.3.1/24']},
            {'name': 'wan0', 'zone': 'wan', 'addresses': ['10.212.2.1/24']},
        ],
        'firewall_rules': [
            {'name': 'dns_local', 'ingress_zone': 'lan', 'dst': 'zone:router',
             'protocol': 'udp', 'destination_ports': '53', 'action': 'pass'},
            {'name': 'dns_external', 'ingress_zone': 'lan', 'dst': 'zone:wan',
             'protocol': 'udp', 'destination_ports': '53', 'action': 'pass'},
            {'name': 'external_port', 'ingress_zone': 'lan', 'dst': 'zone:wan',
             'protocol': 'udp', 'destination_ports': '19090', 'action': 'pass'},
        ],
        'outbound_nat_mode': 'disabled', 'anti_lockout': False,
        'dns': {'interfaces': ['lan0', 'lan1'], 'access_control': ['10.212.0.0/16']},
        'tproxy': {'enabled': False, 'ingress_interfaces': ['lan0']},
    }})
    policy = version.configuration.tproxy.model_copy(update={'enabled': True})
    enabled = version.model_copy(update={'configuration': version.configuration.model_copy(
        update={'tproxy': policy})})
    return {'kind': 'tproxy_dns_boundary_vm_v1',
            'firewall': generate_nftables(version),
            'preauth': generate_tproxy_preauthorization(enabled),
            'guard_on': generate_tproxy_containment(enabled),
            'guard_off': generate_tproxy_containment(version),
            'dns_ingress_on': generate_tproxy_dns_ingress_guard(enabled),
            'dns_ingress_off': generate_tproxy_dns_ingress_guard(version),
            'dns_listener_on': generate_tproxy_dns_listener_guard(enabled),
            'dns_listener_off': generate_tproxy_dns_listener_guard(version),
            'preauth_off': generate_tproxy_preauthorization(version)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases(), indent=2) + '\n')
    print('Generated offline boundary fixture; no network or services touched')


if __name__ == '__main__':
    main()
