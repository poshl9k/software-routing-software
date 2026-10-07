#!/usr/bin/env python3
"""Host-only artifact builder for the TProxy REAL-reboot lifecycle lab (lab-32).

Everything here is produced by the *real* generators through the integrated
contour: the ordinary product firewall (``generate_nftables``), the guards phase
(containment + preauthorization + the three DNS guards, byte-for-byte from
``tproxy_apply.guard_content``), the interception phase
(``generate_tproxy_interception``), the sing-box engine file
(``generate_singbox``), the two split Unbound configs
(``tproxy_apply.build_artifacts``) and the owned policy route
(``marks.POLICY_ROUTES``).

The public gate ``tproxy.not_available`` stays closed: the enabled configuration
is only reachable through the standard offline ``model_copy`` idiom used by
``generate_tproxy_e2e_cases.py``. No host file, service or network is touched;
this writes plain files that the VM harness installs.

The single lab-scaffold line (``LAB_INPUT_ACCEPT``) is the *same* modelled
authorization the lab-30/31 e2e probe used to let an intercepted flow reach the
sing-box listener (the product firewall default-denies INPUT and the
interception generator only supplies an INPUT drop guard). It is labelled as
scaffold, not generator output.
"""
import argparse
import hashlib
import json
from pathlib import Path

from vs_router.agent import tproxy_apply
from vs_router.generators import marks, tproxy_dns
from vs_router.generators.nftables import (generate_nftables,
                                           generate_tproxy_interception)
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion

SELECTED_SUBNET = "10.212.1"
ORDINARY_SUBNET = "10.212.3"
WAN_SUBNET = "10.212.2"

#: Lab scaffold, byte-identical to tproxy_e2e_probe.LAB_INPUT_ACCEPT.
LAB_INPUT_ACCEPT = (
    'add rule inet vs_router input iifname "lan0" meta nfproto ipv4 '
    'meta l4proto { tcp, udp } ct mark & 0x200 == 0x200 counter accept '
    'comment "e2e_lab_tproxy_input"'
)


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


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def build(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    base = _base_version(firewall_rules=_allow_rules())
    default_deny = _base_version(firewall_rules=[], with_dns=False)
    enabled = _enabled(base)

    artifacts = tproxy_apply.build_artifacts(enabled)
    ordinary_firewall = generate_nftables(base) + "\n" + LAB_INPUT_ACCEPT + "\n"
    default_deny_firewall = generate_nftables(default_deny)
    intercept = generate_tproxy_interception(enabled)
    route = marks.POLICY_ROUTES[0]

    files = {
        "ordinary-firewall.nft": ordinary_firewall,
        "default-deny.nft": default_deny_firewall,
        "tproxy-guards.nft": artifacts["tproxy_guards"],
        "tproxy-intercept.nft": intercept,
        "singbox.json": artifacts["singbox"],
        "tproxy-unbound-selected.conf": artifacts["tproxy_unbound_selected"],
        "tproxy-unbound-ordinary.conf": artifacts["tproxy_unbound_ordinary"],
    }
    for name, content in files.items():
        (outdir / name).write_text(content)

    meta = {
        "kind": "tproxy_reboot_lab_v1",
        "source": "generate_nftables+guard_content+generate_tproxy_interception+generate_singbox",
        "selected_uid": tproxy_dns.selected_uid_for(enabled),
        "policy_route": {
            "rule_priority": route.rule_priority,
            "fwmark": route.fwmark,
            "table_id": route.table_id,
        },
        "files": {name: _sha(content) for name, content in sorted(files.items())},
        "lab_scaffold": ["ordinary-firewall.nft appends LAB_INPUT_ACCEPT (lab-30/31 model)"],
        "expected": {
            "local_record": "192.0.2.77",
            "origin_answer_default": "203.0.113.7",
            "stub_answer": "203.0.113.8",
        },
    }
    (outdir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    print("wrote", outdir, "files:", sorted(files))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("outdir", type=Path)
    build(parser.parse_args().outdir)


if __name__ == "__main__":
    main()
