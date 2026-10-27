"""Dynamic subscriber membership in sing-box, generator-only contract.

The local rule-set lets apply update subscriber addresses without rewriting the
main sing-box config. Rules whose subject is a device or tunnel interface still
embed source addresses in the main config and intentionally remain config
changes.
"""
from copy import deepcopy
from ipaddress import ip_address, ip_network

import pytest

from vs_router.generators.singbox import (
    SUBSCRIBER_PEERS_RULE_SET_PATH,
    SUBSCRIBER_PEERS_RULE_SET_TAG,
    generate_singbox,
    generate_subscriber_peers_rule_set,
)
from vs_router.schema import ConfigurationVersion


SECRET = {"encrypted": True, "ciphertext": "gAAAAplaceholder"}


def document():
    return {
        "schema_version": 1,
        "subscribers": [{"name": "alice"}],
        "interfaces": [{"name": "wg0"}],
        "tunnels": [{
            "name": "server_vpn",
            "interface": "wg0",
            "role": "server",
            "protocol": "wg",
            "listen_port": 51820,
            "private_key": SECRET,
            "peers": [{
                "name": "phone",
                "public_key": "P" * 44,
                "subscriber": "alice",
                "allowed_ips": ["10.66.66.2/32"],
            }],
        }],
        "routing_rules": [{
            "name": "server_direct",
            "ip_cidr": ["203.0.113.0/24"],
        }],
    }


def version(data):
    return ConfigurationVersion.model_validate({"profile": "panel", "configuration": data})


def add_tablet(data):
    data["tunnels"][0]["peers"].append({
        "name": "tablet",
        "public_key": "Q" * 44,
        "subscriber": "alice",
        "allowed_ips": ["10.66.66.3/32", "2001:db8::3/128"],
    })


def test_criterion_1_membership_only_changes_rule_set_not_main_config():
    before = version(document())
    after_data = deepcopy(document())
    add_tablet(after_data)
    after = version(after_data)

    assert generate_singbox(before) == generate_singbox(after)
    assert generate_subscriber_peers_rule_set(before) != generate_subscriber_peers_rule_set(after)


def test_criterion_2_unmatched_subscriber_is_rejected_through_local_rule_set():
    draft = version(document())
    generated = generate_singbox(draft)
    local_set = generate_subscriber_peers_rule_set(draft)

    assert {"type": "local", "tag": SUBSCRIBER_PEERS_RULE_SET_TAG,
            "format": "source", "path": SUBSCRIBER_PEERS_RULE_SET_PATH} \
        in generated["route"]["rule_set"]
    reject = {"rule_set": [SUBSCRIBER_PEERS_RULE_SET_TAG], "action": "reject"}
    assert reject in generated["route"]["rules"]
    assert any(ip_address("10.66.66.2") in ip_network(cidr)
               for rule in local_set["rules"] for cidr in rule["source_ip_cidr"])


def test_criterion_3_empty_peers_do_not_create_match_all_reject():
    data = document()
    data["subscribers"] = []
    data["tunnels"][0]["peers"] = []
    draft = version(data)

    assert generate_subscriber_peers_rule_set(draft) == {"version": 3, "rules": []}
    generated = generate_singbox(draft)
    assert {"rule_set": [SUBSCRIBER_PEERS_RULE_SET_TAG], "action": "reject"} \
        in generated["route"]["rules"]
    assert generated["route"]["rule_set"][-1]["path"] == SUBSCRIBER_PEERS_RULE_SET_PATH


def test_criterion_4_device_specific_rule_still_changes_main_config():
    before = version(document())
    after_data = deepcopy(document())
    add_tablet(after_data)
    after_data["routing_rules"].append({
        "name": "tablet_direct",
        "subject": {"kind": "device", "subscriber": "alice", "peer": "tablet"},
        "ip_cidr": ["198.51.100.0/24"],
    })
    after = version(after_data)

    assert generate_singbox(before) != generate_singbox(after)
    assert {"source_ip_cidr": ["10.66.66.3/32", "2001:db8::3/128"],
            "ip_cidr": ["198.51.100.0/24"],
            "action": "route", "outbound": "direct"} in generate_singbox(after)["route"]["rules"]


def test_criterion_4_tunnel_interface_rule_changes_with_membership():
    before_data = document()
    before_data["routing_rules"] = [{
        "name": "tunnel_sources",
        "subject": {"kind": "interface", "interface": "wg0"},
        "ip_cidr": ["198.51.100.0/24"],
    }]
    after_data = deepcopy(before_data)
    add_tablet(after_data)

    before = generate_singbox(version(before_data))
    after = generate_singbox(version(after_data))
    assert before != after
    assert after["route"]["rules"][0]["source_ip_cidr"] == [
        "10.66.66.2/32", "10.66.66.3/32",
    ]


def test_criterion_5_generation_is_deterministic_under_peer_order():
    ordered_data = document()
    add_tablet(ordered_data)
    reversed_data = deepcopy(ordered_data)
    reversed_data["tunnels"][0]["peers"].reverse()
    ordered, reversed_ = version(ordered_data), version(reversed_data)

    assert generate_singbox(ordered) == generate_singbox(reversed_)
    assert generate_subscriber_peers_rule_set(ordered) == generate_subscriber_peers_rule_set(reversed_)
    assert generate_subscriber_peers_rule_set(ordered) == {
        "version": 3,
        "rules": [{"source_ip_cidr": [
            "10.66.66.2/32", "10.66.66.3/32", "2001:db8::3/128",
        ]}],
    }


def test_criterion_6_internal_rule_set_tag_is_reserved():
    data = document()
    data["rule_sets"] = [{
        "name": SUBSCRIBER_PEERS_RULE_SET_TAG,
        "format": "json",
        "url": "https://example.org/user.json",
    }]

    with pytest.raises(ValueError, match="routing.ruleset_tag_reserved"):
        generate_singbox(version(data))
