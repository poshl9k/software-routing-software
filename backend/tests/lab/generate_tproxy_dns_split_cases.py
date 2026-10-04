"""Host-only offline fixture for the two-process DNS namespace probe."""
import argparse
import json
from pathlib import Path

from vs_router.schema import ConfigurationVersion
from vs_router.generators.nftables import (generate_nftables,
                                          generate_tproxy_dns_ingress_guard,
                                          generate_tproxy_dns_listener_guard,
                                          generate_tproxy_dns_output_guard)
from vs_router.generators.unbound import generate_tproxy_unbound_split


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
    return {
        "kind": "tproxy_dns_split_vm_v1",
        "firewall": generate_nftables(version),
        "unbound": generate_tproxy_unbound_split(enabled),
        "listener_guard": generate_tproxy_dns_listener_guard(enabled),
        "direct_guard": generate_tproxy_dns_ingress_guard(enabled),
        "output_guard": generate_tproxy_dns_output_guard(enabled, 29092),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases(), indent=2) + "\n")
    print("Generated offline DNS split fixture; no networking or services touched")


if __name__ == "__main__":
    main()
