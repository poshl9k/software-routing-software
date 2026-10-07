"""Host-only offline fixture for the two-process DNS namespace probe.

The fixture is produced by the *integrated* contour path — the same
:func:`generators.tproxy_dns.plan_tproxy_dns` plan and
:mod:`vs_router.agent.tproxy_apply` artifacts that the gated apply scaffold
installs — so the VM probe exercises the exact guard/config text apply would
stage, not a hand-rolled copy. ``apply_guard``/``apply_files`` expose the
phase-1 and phase-list text for host-side consistency checks.
"""
import argparse
import json
from pathlib import Path

from vs_router.agent import tproxy_apply
from vs_router.generators import tproxy_dns
from vs_router.generators.nftables import generate_nftables
from vs_router.schema import ConfigurationVersion


def generate_cases():
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "lan1", "zone": "lan", "addresses": ["10.212.3.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": ["10.212.2.1/24"]},
        ],
        "dns": {
            "interfaces": ["lan0", "lan1"],
            "access_control": ["10.212.1.0/24", "10.212.3.0/24"],
            "records": [{"name": "router.test.", "value": "192.0.2.77"}],
            "forwards": [{"domain": "forward.vsrprobe.org.", "upstreams": ["198.18.0.2"]}],
            "upstreams": ["198.18.0.3"],
        },
        "firewall_rules": [
            {"name": "dns_udp", "ingress_zone": "lan", "dst": "zone:router",
             "protocol": "udp", "destination_ports": "53", "action": "pass"},
            {"name": "dns_tcp", "ingress_zone": "lan", "dst": "zone:router",
             "protocol": "tcp", "destination_ports": "53", "action": "pass"},
        ],
        "outbound_nat_mode": "disabled", "anti_lockout": False,
        "tproxy": {"ingress_interfaces": ["lan0"]},
    }})
    policy = version.configuration.tproxy.model_copy(update={"enabled": True})
    enabled = version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": policy})})
    plan = tproxy_dns.plan_tproxy_dns(enabled, tproxy_dns.selected_uid_for(enabled))
    guards = {guard.role: guard.content for guard in plan.nft_guards}
    artifacts = tproxy_apply.build_artifacts(enabled)
    return {
        "kind": "tproxy_dns_split_vm_v1",
        "source": "plan_tproxy_dns+tproxy_apply",
        "selected_uid": plan.selected_uid,
        "listener_addresses": {k: list(v) for k, v in plan.listener_addresses.items()},
        "apply_files": list(artifacts),
        "apply_guard": artifacts["tproxy_guards"],
        "firewall": generate_nftables(version),
        "unbound": {
            "selected": artifacts["tproxy_unbound_selected"],
            "ordinary": artifacts["tproxy_unbound_ordinary"],
        },
        "listener_guard": guards["listener"],
        "direct_guard": guards["ingress"],
        "output_guard": guards["output"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases(), indent=2) + "\n")
    print("Generated offline DNS split fixture from the integrated plan; "
          "no networking or services touched")


if __name__ == "__main__":
    main()
