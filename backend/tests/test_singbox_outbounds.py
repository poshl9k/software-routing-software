"""Offline contract -> sing-box outbound/group generator (plan stage 3, additive).

Covers deterministic rendering of the disabled-by-default ``proxies`` section:
outbounds (local + proxied), selector/urltest groups, route linkage to the
default tag, reference integrity, secret non-leakage and legacy stability. No
fetch, no apply, TProxy gate stays closed.
"""
import json

import pytest
from pydantic import ValidationError

from vs_router.generators.singbox import (
    IMPLICIT_DIRECT_TAG,
    PLACEHOLDER_PASSWORD,
    PLACEHOLDER_UUID,
    generate_singbox,
)
from vs_router.schema import ConfigurationVersion

CIPHERTEXT = "gAAAAABm-encrypted-secret-blob"


def outbound(tag, type="vless", **overrides):
    row = {"tag": tag, "type": type, "server": "203.0.113.10", "port": 443}
    if type in ("direct", "block"):
        row = {"tag": tag, "type": type}
    row.update(overrides)
    return row


def version(proxies=None, tproxy=None):
    configuration = {"proxies": proxies} if proxies is not None else {}
    if tproxy is not None:
        configuration["tproxy"] = tproxy
    return ConfigurationVersion.model_validate({"configuration": configuration})


def enabled_proxies(**overrides):
    proxies = {
        "enabled": True,
        "outbounds": [
            outbound("proxy_b", type="trojan", tls=True),
            outbound("proxy_a"),
        ],
        "groups": [
            {"tag": "auto", "type": "urltest", "outbounds": ["proxy_a"]},
            {"tag": "select", "type": "selector", "outbounds": ["proxy_a", "proxy_b", "auto"]},
        ],
    }
    proxies.update(overrides)
    return proxies


# --------------------------------------------------------------------------
# generation from the contract
# --------------------------------------------------------------------------

def test_empty_section_is_legacy_output():
    assert generate_singbox(ConfigurationVersion()) == generate_singbox(version({"enabled": False}))


def test_empty_output_matches_legacy_shape():
    generated = generate_singbox(ConfigurationVersion())
    assert generated["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert generated["route"]["final"] == "direct"
    assert generated["route"]["rules"] == []


def test_disabled_but_populated_section_keeps_legacy_output():
    populated = enabled_proxies(enabled=False)
    generated = generate_singbox(version(populated))
    assert generated["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert generated["route"]["final"] == "direct"


def test_enabled_section_renders_outbounds_and_groups():
    generated = generate_singbox(version(enabled_proxies()))
    tags = [o["tag"] for o in generated["outbounds"]]
    assert tags == ["direct", "proxy_a", "proxy_b", "auto", "select"]
    by_tag = {o["tag"]: o for o in generated["outbounds"]}
    assert by_tag["proxy_a"] == {
        "type": "vless", "tag": "proxy_a", "server": "203.0.113.10", "server_port": 443,
        "uuid": PLACEHOLDER_UUID,
    }
    assert by_tag["proxy_b"]["type"] == "trojan"
    assert by_tag["proxy_b"]["tls"] == {"enabled": True}
    assert by_tag["auto"] == {"type": "urltest", "tag": "auto", "outbounds": ["proxy_a"]}
    assert by_tag["select"]["type"] == "selector"


def test_final_route_field_links_to_selector_group():
    generated = generate_singbox(version(enabled_proxies()))
    assert generated["route"]["final"] == "select"


def test_default_tag_falls_back_to_urltest_then_direct():
    only_auto = enabled_proxies(groups=[{"tag": "auto", "type": "urltest", "outbounds": ["proxy_a"]}])
    assert generate_singbox(version(only_auto))["route"]["final"] == "auto"
    no_groups = enabled_proxies(groups=[])
    assert generate_singbox(version(no_groups))["route"]["final"] == "direct"


def test_urltest_renders_url_and_interval():
    proxies = enabled_proxies(groups=[{
        "tag": "auto", "type": "urltest", "outbounds": ["proxy_a"],
        "url": "https://www.gstatic.com/generate_204", "interval_minutes": 5,
    }])
    generated = generate_singbox(version(proxies))
    auto = next(o for o in generated["outbounds"] if o["tag"] == "auto")
    assert auto["url"] == "https://www.gstatic.com/generate_204"
    assert auto["interval"] == "5m"


def test_local_direct_block_outbounds_have_no_remote_fields():
    proxies = enabled_proxies(outbounds=[
        outbound("bypass", type="direct"), outbound("deny", type="block"),
    ], groups=[])
    generated = generate_singbox(version(proxies))
    by_tag = {o["tag"]: o for o in generated["outbounds"]}
    assert by_tag["bypass"] == {"type": "direct", "tag": "bypass"}
    assert by_tag["deny"] == {"type": "block", "tag": "deny"}


# --------------------------------------------------------------------------
# ordering and reference integrity
# --------------------------------------------------------------------------

def test_output_is_sorted_regardless_of_contract_order():
    ordered = enabled_proxies()
    shuffled = enabled_proxies(
        outbounds=[outbound("proxy_a"), outbound("proxy_b", type="trojan", tls=True)],
        groups=[
            {"tag": "select", "type": "selector", "outbounds": ["proxy_a", "proxy_b", "auto"]},
            {"tag": "auto", "type": "urltest", "outbounds": ["proxy_a"]},
        ],
    )
    assert generate_singbox(version(ordered)) == generate_singbox(version(shuffled))


def test_group_references_resolve_to_rendered_tags():
    proxies = enabled_proxies()
    generated = generate_singbox(version(proxies))
    tags = {o["tag"] for o in generated["outbounds"]}
    for group in (o for o in generated["outbounds"] if o["type"] in ("selector", "urltest")):
        for reference in group["outbounds"]:
            assert reference in tags
    assert generated["route"]["final"] in tags


def test_group_preserves_declared_priority_order():
    proxies = enabled_proxies(groups=[{
        "tag": "select", "type": "selector", "outbounds": ["proxy_b", "proxy_a"],
    }])
    generated = generate_singbox(version(proxies))
    select = next(o for o in generated["outbounds"] if o["tag"] == "select")
    assert select["outbounds"] == ["proxy_b", "proxy_a"]


def test_reserved_direct_tag_rejected():
    with pytest.raises(ValidationError, match="proxy.tag_reserved"):
        version({"enabled": True, "outbounds": [outbound("direct", type="direct")]})
    with pytest.raises(ValidationError, match="proxy.tag_reserved"):
        version({"enabled": True, "groups": [{"tag": "direct", "type": "selector", "outbounds": ["p"]}],
                 "outbounds": [outbound("p")]})


# --------------------------------------------------------------------------
# secret handling
# --------------------------------------------------------------------------

def test_secret_ciphertext_absent_and_placeholder_used():
    proxies = {
        "enabled": True,
        "outbounds": [
            outbound("ss", type="shadowsocks", secret={"ciphertext": CIPHERTEXT}),
            outbound("vless", type="vless", secret={"ciphertext": CIPHERTEXT}),
            outbound("trojan", type="trojan", tls=True, secret={"ciphertext": CIPHERTEXT}),
        ],
        "groups": [],
    }
    generated = generate_singbox(version(proxies))
    blob = json.dumps(generated, sort_keys=True)
    assert CIPHERTEXT not in blob
    assert "ciphertext" not in blob
    assert "encrypted" not in blob
    by_tag = {o["tag"]: o for o in generated["outbounds"]}
    assert by_tag["vless"]["uuid"] == PLACEHOLDER_UUID
    assert by_tag["trojan"]["password"] == PLACEHOLDER_PASSWORD
    assert by_tag["ss"]["password"] == PLACEHOLDER_PASSWORD
    assert by_tag["ss"]["method"]


# --------------------------------------------------------------------------
# determinism and idempotence
# --------------------------------------------------------------------------

def test_generation_is_deterministic():
    proxies = enabled_proxies()
    assert generate_singbox(version(proxies)) == generate_singbox(version(proxies))


def test_tproxy_rules_unchanged_by_proxy_section():
    tproxy = {"rules": [{"name": "blocked", "domain_suffix": ["example.org"],
                         "action": "block", "order": 1}]}
    base = generate_singbox(version(None, tproxy))
    with_proxies = generate_singbox(version(enabled_proxies(), tproxy))
    assert with_proxies["route"]["rules"] == base["route"]["rules"]
    assert with_proxies["inbounds"] == base["inbounds"]
    assert with_proxies["outbounds"][0] == {"type": "direct", "tag": IMPLICIT_DIRECT_TAG}


# --------------------------------------------------------------------------
# TProxy rule destination ("route" to a named outbound)
# --------------------------------------------------------------------------

def test_tproxy_route_rule_targets_outbound():
    tproxy = {"rules": [{"name": "via_proxy", "ip_cidr": ["203.0.113.0/24"],
                         "action": "route", "outbound": "proxy_a", "order": 0}]}
    generated = generate_singbox(version(enabled_proxies(), tproxy))
    assert generated["route"]["rules"][-1] == {
        "ip_cidr": ["203.0.113.0/24"], "action": "route", "outbound": "proxy_a"}


def test_tproxy_route_requires_an_existing_rendered_outbound():
    # Unknown tag.
    with pytest.raises(ValidationError, match="tproxy.outbound_unavailable"):
        version(enabled_proxies(), {"rules": [{"name": "r", "ip_cidr": ["10.0.0.0/8"],
                                               "action": "route", "outbound": "ghost"}]})
    # Declared proxy outbounds are not rendered while the section is disabled.
    with pytest.raises(ValidationError, match="tproxy.outbound_unavailable"):
        version(None, {"rules": [{"name": "r", "ip_cidr": ["10.0.0.0/8"],
                                  "action": "route", "outbound": "proxy_a"}]})


def test_tproxy_route_without_outbound_is_rejected():
    with pytest.raises(ValidationError, match="tproxy.outbound_required"):
        version(enabled_proxies(), {"rules": [{"name": "r", "ip_cidr": ["10.0.0.0/8"],
                                               "action": "route"}]})


def test_tproxy_outbound_on_a_non_route_action_is_rejected():
    with pytest.raises(ValidationError, match="tproxy.outbound_unexpected"):
        version(enabled_proxies(), {"rules": [{"name": "r", "ip_cidr": ["10.0.0.0/8"],
                                               "action": "block", "outbound": "proxy_a"}]})
