"""Host-only, offline DNS baseline fixture. Never applies configuration.

Run with the backend environment and pass an output JSON path. The paired probe
is VM-only and must run on an authorized disposable guest.
"""
import argparse
import json
from pathlib import Path

from vs_router.schema import ConfigurationVersion
from vs_router.generators.nftables import generate_nftables
from vs_router.generators.unbound import generate_unbound


def generate_cases():
    version = ConfigurationVersion.model_validate({'configuration': {
        'interfaces': [
            {'name': 'lan0', 'zone': 'lan', 'addresses': ['10.212.1.1/24']},
            {'name': 'wan0', 'zone': 'wan', 'addresses': ['10.212.2.1/24']},
        ],
        'dns': {
            'interfaces': ['lan0'], 'access_control': ['10.212.1.0/24'],
            'records': [{'name': 'router.test.', 'type': 'A', 'value': '192.0.2.77'}],
            'forwards': [{'domain': 'forward.test.', 'upstreams': ['198.18.0.2']}],
            'recursive': False, 'upstreams': [],
        },
        'firewall_rules': [
            {'name': 'dns_udp', 'ingress_zone': 'lan', 'dst': 'zone:router',
             'protocol': 'udp', 'destination_ports': '53', 'action': 'pass'},
            {'name': 'dns_tcp', 'ingress_zone': 'lan', 'dst': 'zone:router',
             'protocol': 'tcp', 'destination_ports': '53', 'action': 'pass'},
        ],
        'outbound_nat_mode': 'disabled', 'anti_lockout': False,
        'tproxy': {'enabled': False},
    }})
    return {
        'kind': 'ordinary_dns_tproxy_off',
        'unbound': generate_unbound(version),
        'firewall': generate_nftables(version),
        'expected': {
            'client': '10.212.1.2', 'resolver': '10.212.1.1',
            'router_wan': '10.212.2.1', 'origin': '198.18.0.2',
            'local_name': 'router.test.', 'local_answer': '192.0.2.77',
            'forward_name': 'www.forward.test.', 'forward_name_tcp': 'tcp.forward.test.',
            'forward_answer': '203.0.113.7',
            'unknown_name': 'unknown.test.',
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases(), indent=2) + '\n')
    print('Generated ordinary DNS baseline fixture; no networking or services touched')


if __name__ == '__main__':
    main()
