"""Generate test-only offline IPv6-guard cases; never apply them on this machine.

From backend: .venv/bin/python tests/lab/generate_tproxy_ipv6_cases.py OUTPUT.json
Copy OUTPUT.json and tproxy_ipv6_guard_probe.py to an authorized disposable Debian
VM. Run the probe there as root, never on the host or production router.

The generated guard text comes byte-for-byte from
``generate_tproxy_ipv6_guard`` (enabled via the offline ``model_copy`` idiom; the
public ``tproxy.not_available`` gate stays closed).
"""
import argparse
import json
from pathlib import Path

from vs_router.schema import ConfigurationVersion
from vs_router.generators.nftables import generate_tproxy_ipv6_guard


def generate_cases():
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24", "2001:db8:1::1/64"]},
            {"name": "lan1", "zone": "lan", "addresses": ["10.213.1.1/24", "2001:db8:2::1/64"]},
            {"name": "wan0", "zone": "wan", "addresses": ["192.0.2.1/24", "2001:db8:3::1/64"]},
        ],
        "tproxy": {"ingress_interfaces": ["lan0"]},
    }})
    outputs: dict = {"off": generate_tproxy_ipv6_guard(version)}
    policy = version.configuration.tproxy.model_copy(update={"enabled": True})
    version = version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": policy})})
    outputs["guard"] = generate_tproxy_ipv6_guard(version)
    outputs["ingress"] = ["lan0"]
    outputs["__tproxy_ipv6_guard__"] = True
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    args.output.write_text(json.dumps(generate_cases()))
    print("Generated test-only IPv6-guard cases; no network changes")


if __name__ == "__main__":
    main()
