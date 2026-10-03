"""Generate test-only offline preauth cases; never apply them on this machine.

From backend: .venv/bin/python tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json
Copy OUTPUT.json and tproxy_preauth_probe.py to an authorized disposable Debian VM.
Run the probe there as root, never on the host or production router.
"""
import argparse
import json
from pathlib import Path

from vs_router.schema import ConfigurationVersion
from vs_router.generators.nftables import (
    generate_nftables, generate_tproxy_preauthorization, generate_tproxy_containment,
)
from vs_router.generators.singbox import generate_singbox


def generate_cases(protocol='udp', *, input_proof=False, mark_collision=False):
    if mark_collision:
        if protocol != 'tcp':
            raise ValueError('TCP-only lab mark collision experiment')
        input_proof = True
    if input_proof and protocol != 'tcp':
        raise ValueError('TCP-only lab INPUT proof experiment')
    interfaces = [{'name': 'lan0', 'zone': 'lan'}, {'name': 'wan0', 'zone': 'wan'}]
    allow = {'name': 'allow', 'ingress_zone': 'lan', 'dst': 'zone:wan', 'protocol': protocol,
             'destination_ports': '19090', 'action': 'pass', 'order': 10}
    deny = {'name': 'deny', 'ingress_zone': 'lan', 'dst': 'zone:wan', 'protocol': protocol,
            'destination_ports': '19090', 'action': 'block', 'order': 0}
    cases = {'allow': [allow], 'deny_first': [allow, deny], 'default_deny': [],
             'allow_first': [dict(allow, order=0), dict(deny, order=10)], 'off': []}
    outputs = {}
    for name, rules in cases.items():
        version = ConfigurationVersion.model_validate({'configuration': {
            'interfaces': interfaces, 'firewall_rules': rules,
            'anti_lockout': False, 'outbound_nat_mode': 'disabled',
            'tproxy': {'ingress_interfaces': ['lan0']},
        }})
        outputs[name + '_firewall'] = generate_nftables(version)
        outputs[name + '_singbox'] = json.dumps(generate_singbox(version))
        if name != 'off':
            # Deliberate offline fixture bypass, never a product enablement path.
            policy = version.configuration.tproxy.model_copy(update={'enabled': True})
            config = version.configuration.model_copy(update={'tproxy': policy})
            version = version.model_copy(update={'configuration': config})
        outputs[name] = generate_tproxy_preauthorization(version)
        outputs[name + '_guard'] = generate_tproxy_containment(version)
    # Real ordinary firewall: local INPUT allow, otherwise default deny.
    local = {'name': 'local_' + protocol, 'ingress_zone': 'lan', 'dst': 'zone:router',
             'protocol': protocol, 'destination_ports': '19090', 'action': 'pass'}
    for name, forwards in (
        ('local', []),
        ('local_denied', []),
        ('pf', [{'name': 'wan_' + protocol, 'interface': 'wan0', 'protocol': protocol,
                 'external_port': 19091, 'target': '10.212.1.2', 'target_port': 19090}]),
    ):
        version = ConfigurationVersion.model_validate({'configuration': {
            'interfaces': interfaces, 'firewall_rules': [] if name == 'local_denied' else [local],
            'port_forwards': forwards,
            'anti_lockout': False, 'outbound_nat_mode': 'disabled',
            'tproxy': {'ingress_interfaces': ['lan0']},
        }})
        outputs[name + '_firewall'] = generate_nftables(version)
        policy = version.configuration.tproxy.model_copy(update={'enabled': True})
        version = version.model_copy(update={'configuration': version.configuration.model_copy(
            update={'tproxy': policy})})
        outputs[name + '_preauth'] = generate_tproxy_preauthorization(version)
    if input_proof:
        outputs['__input_proof__'] = True
    if mark_collision:
        outputs['__mark_collision__'] = True
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--combined', action='store_true')
    modes.add_argument('--tcp', action='store_true')
    modes.add_argument('--tcp-proof', action='store_true')
    parser.add_argument('--tcp-mark-collision', action='store_true')
    args = parser.parse_args(argv)
    if args.tcp_mark_collision and not args.tcp:
        parser.error('--tcp-mark-collision requires --tcp')
    outputs = generate_cases('tcp' if args.tcp or args.tcp_proof else 'udp',
                             input_proof=args.tcp_proof,
                             mark_collision=args.tcp_mark_collision)
    if args.combined:
        outputs['__combined__'] = 'udp'
    args.output.write_text(json.dumps(outputs))
    print('Generated test-only policies; no network changes')


if __name__ == '__main__':
    main()
