"""Host-only offline fixture for the full-stack TProxy e2e matrix probe.

Everything here comes from the *real* generators through the integrated contour
(:func:`generators.tproxy_dns.plan_tproxy_dns` and
:mod:`vs_router.agent.tproxy_apply`): the ordinary product firewall, the
preauthorization and containment guards, the interception capture (reset +
capture + conntrack INPUT guard), the three DNS guards, the sing-box engine file,
the two split Unbound configs and the policy-route data.

The public gate ``tproxy.not_available`` stays closed: an enabled configuration
is only reachable through the standard offline ``model_copy`` fixture idiom, the
same one used by ``generate_tproxy_dns_split_cases.py``. Nothing here touches a
network, a service or a host file. The output JSON is consumed by the VM-only
``tproxy_e2e_probe.py`` as root inside disposable network namespaces only.
"""
import argparse
import json
from pathlib import Path

from vs_router.agent import tproxy_apply
from vs_router.generators import marks, tproxy_dns
from vs_router.generators.nftables import (generate_nftables,
                                           generate_tproxy_containment,
                                           generate_tproxy_interception,
                                           generate_tproxy_preauthorization)
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion

#: Selected LAN holds the TProxy-selected client; ordinary LAN is unselected.
SELECTED_SUBNET = "10.212.1"
ORDINARY_SUBNET = "10.212.3"
WAN_SUBNET = "10.212.2"


def _base_version(*, firewall_rules, with_dns=True):
    configuration = {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": [f"{SELECTED_SUBNET}.1/24"]},
            {"name": "lan1", "zone": "lan", "addresses": [f"{ORDINARY_SUBNET}.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": [f"{WAN_SUBNET}.1/24"]},
        ],
        "firewall_rules": firewall_rules,
        "anti_lockout": False,
        "outbound_nat_mode": "disabled",
        "tproxy": {"ingress_interfaces": ["lan0"]},
    }
    if with_dns:
        configuration["dns"] = {
            "interfaces": ["lan0", "lan1"],
            "access_control": [f"{SELECTED_SUBNET}.0/24", f"{ORDINARY_SUBNET}.0/24"],
            "records": [{"name": "router.test.", "value": "192.0.2.77"}],
            "forwards": [{"domain": "forward.vsrprobe.org.", "upstreams": ["198.18.0.2"]}],
            "upstreams": ["198.18.0.3"],
        }
    return ConfigurationVersion.model_validate({"configuration": configuration})


def _enabled(version):
    """Offline fixture bypass: flip only the public gate, then revalidate."""
    policy = version.configuration.tproxy.model_copy(update={"enabled": True})
    configuration = version.configuration.model_copy(update={"tproxy": policy})
    return version.model_copy(update={"configuration": configuration})


def _allow_rules():
    return [
        {"name": "allow_tcp", "ingress_zone": "lan", "dst": "zone:wan", "protocol": "tcp",
         "destination_ports": "19090", "action": "pass", "order": 10},
        {"name": "allow_udp", "ingress_zone": "lan", "dst": "zone:wan", "protocol": "udp",
         "destination_ports": "19090", "action": "pass", "order": 10},
        {"name": "dns_udp", "ingress_zone": "lan", "dst": "zone:router", "protocol": "udp",
         "destination_ports": "53", "action": "pass", "order": 20},
        {"name": "dns_tcp", "ingress_zone": "lan", "dst": "zone:router", "protocol": "tcp",
         "destination_ports": "53", "action": "pass", "order": 20},
        {"name": "mgmt", "ingress_zone": "lan", "dst": "zone:router", "protocol": "tcp",
         "destination_ports": "443", "action": "pass", "order": 20},
    ]


def generate_cases():
    base = _base_version(firewall_rules=_allow_rules())
    default_deny = _base_version(firewall_rules=[], with_dns=False)
    enabled = _enabled(base)

    plan = tproxy_dns.plan_tproxy_dns(enabled, tproxy_dns.selected_uid_for(enabled))
    guards = {guard.role: guard.content for guard in plan.nft_guards}
    artifacts = tproxy_apply.build_artifacts(enabled)

    off_plan = tproxy_dns.plan_tproxy_dns(base, None)
    off_guards = {guard.role: guard.content for guard in off_plan.nft_guards}
    route = marks.POLICY_ROUTES[0]

    return {
        "kind": "tproxy_e2e_vm_v1",
        "source": "generate_nftables+plan_tproxy_dns+tproxy_apply",
        "selected_uid": plan.selected_uid,
        "listener_addresses": {k: list(v) for k, v in plan.listener_addresses.items()},
        "policy_route": {
            "rule_priority": route.rule_priority,
            "fwmark": route.fwmark,
            "table_id": route.table_id,
        },
        # Ordinary product firewall (enabled=False base; the firewall never emits TProxy).
        "ordinary_firewall": generate_nftables(base),
        "default_deny_firewall": generate_nftables(default_deny),
        # Guards phase (byte-for-byte generator output).
        "containment": generate_tproxy_containment(enabled),
        "preauth": generate_tproxy_preauthorization(enabled),
        "dns_guards": guards,
        # Readiness phase.
        "singbox": json.dumps(generate_singbox(enabled)),
        "unbound": {
            "selected": artifacts["tproxy_unbound_selected"],
            "ordinary": artifacts["tproxy_unbound_ordinary"],
        },
        # Interception phase.
        "interception": generate_tproxy_interception(enabled),
        # Explicit off: destroy exactly the tables each generator owns.
        "off": {
            "containment": generate_tproxy_containment(base),
            "preauth": generate_tproxy_preauthorization(base),
            "interception": generate_tproxy_interception(base),
            "dns_ingress": off_guards["ingress"],
            "dns_listener": off_guards["listener"],
            "dns_output": off_guards["output"],
        },
        "expected": {
            "local_record": "192.0.2.77",
            "stub_answer": "203.0.113.8",
            "origin_answer": "203.0.113.7",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases(), indent=2) + "\n")
    print("Generated offline full-stack TProxy e2e fixture; no networking touched")


if __name__ == "__main__":
    main()
