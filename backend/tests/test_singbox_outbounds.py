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
    IMPLICIT_BLOCK_TAG,
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


def version(proxies=None, tproxy=None, *, rule_sets=None):
    configuration = {"proxies": proxies} if proxies is not None else {}
    if tproxy is not None:
        configuration["tproxy"] = tproxy
    if rule_sets is not None:
        configuration["rule_sets"] = rule_sets
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


def test_tproxy_rule_set_matcher():
    source = {"name": "geo", "format": "text-domain", "url": "https://example.org/geo.txt"}
    generated = generate_singbox(version(tproxy={"rules": [{"name": "r", "rule_sets": ["geo"]}]},
                                        rule_sets=[source]))
    assert generated["route"]["rules"] == [
        {"rule_set": ["geo"], "action": "route", "outbound": "direct"}]


def test_tproxy_source_port_and_protocol_matchers():
    generated = generate_singbox(version(tproxy={"rules": [{
        "name": "r", "source_ip_cidr": ["192.0.2.0/24"], "ports": ["443"],
        "protocol": "tcp",
    }]}))
    assert generated["route"]["rules"] == [{
        "type": "logical", "mode": "or", "rules": [
            {"source_ip_cidr": ["192.0.2.0/24"]}, {"port": [443]}, {"network": ["tcp"]},
        ], "action": "route", "outbound": "direct",
    }]


def test_tproxy_port_range_matcher():
    generated = generate_singbox(version(tproxy={"rules": [{"name": "r", "ports": ["80-90"]}]}))
    assert generated["route"]["rules"] == [
        {"port_range": ["80:90"], "action": "route", "outbound": "direct"}]


def test_tproxy_multiple_matchers_keep_declared_matcher_order():
    source = {"name": "geo", "format": "text-domain", "url": "https://example.org/geo.txt"}
    generated = generate_singbox(version(tproxy={"rules": [{
        "name": "r", "domain_suffix": ["example.org"], "ip_cidr": ["203.0.113.0/24"],
        "source_ip_cidr": ["192.0.2.0/24"], "rule_sets": ["geo"],
        "ports": ["443", "80-90"], "protocol": "udp", "action": "block",
    }]}, rule_sets=[source]))
    assert generated["route"]["rules"][-1] == {
        "type": "logical", "mode": "or", "rules": [
            {"domain_suffix": ["example.org"]}, {"ip_cidr": ["203.0.113.0/24"]},
            {"source_ip_cidr": ["192.0.2.0/24"]}, {"rule_set": ["geo"]},
            {"port": [443]}, {"port_range": ["80:90"]}, {"network": ["udp"]},
        ], "action": "reject",
    }


def test_tproxy_rule_set_must_be_declared():
    with pytest.raises(ValidationError, match="tproxy.ruleset_unavailable"):
        version(tproxy={"rules": [{"name": "r", "rule_sets": ["missing"]}]})


def test_tproxy_source_cidr_requires_ipv4():
    with pytest.raises(ValidationError, match="tproxy.source_ipv4_required"):
        version(tproxy={"rules": [{"name": "r", "source_ip_cidr": ["2001:db8::/32"]}]})


# --------------------------------------------------------------------------
# TProxy final action (slice S3)
# --------------------------------------------------------------------------

def test_final_block_renders_block_outbound_and_route():
    generated = generate_singbox(version(enabled_proxies(), tproxy={"final": "block"}))
    by_tag = {o["tag"]: o for o in generated["outbounds"]}
    assert by_tag[IMPLICIT_BLOCK_TAG] == {"type": "block", "tag": IMPLICIT_BLOCK_TAG}
    assert generated["route"]["final"] == IMPLICIT_BLOCK_TAG


def test_final_route_uses_named_outbound():
    generated = generate_singbox(version(enabled_proxies(),
                                         tproxy={"final": "route", "final_outbound": "proxy_a"}))
    assert generated["route"]["final"] == "proxy_a"


def test_final_route_requires_outbound():
    with pytest.raises(ValidationError, match="tproxy.final_outbound_required"):
        version(enabled_proxies(), tproxy={"final": "route"})


def test_final_route_unknown_outbound_rejected():
    with pytest.raises(ValidationError, match="tproxy.final_outbound_unavailable"):
        version(enabled_proxies(), tproxy={"final": "route", "final_outbound": "ghost"})


def test_final_outbound_unexpected_when_not_route():
    with pytest.raises(ValidationError, match="tproxy.final_outbound_unexpected"):
        version(enabled_proxies(), tproxy={"final": "direct", "final_outbound": "proxy_a"})


def test_reserved_block_tag_rejected():
    with pytest.raises(ValidationError, match="proxy.tag_reserved"):
        version({"enabled": True, "outbounds": [outbound("block", type="block")]})
    with pytest.raises(ValidationError, match="proxy.tag_reserved"):
        version({"enabled": True, "groups": [{"tag": "block", "type": "selector", "outbounds": ["p"]}],
                 "outbounds": [outbound("p")]})


# Offline DNS policy preview; the public TProxy availability gate stays closed.
def dns_preview(dns):
    draft = version(tproxy={"dns": dns})
    enabled_tproxy = draft.configuration.tproxy.model_copy(update={"enabled": True})
    offline = draft.model_copy(update={
        "configuration": draft.configuration.model_copy(update={"tproxy": enabled_tproxy})
    })
    return generate_singbox(offline)

def test_dns_servers_and_rule_render_in_declared_order():
    rendered = dns_preview({
        "servers": [
            {"tag": "primary", "server": "1.1.1.1", "detour": "direct"},
            {"tag": "secondary", "type": "tls", "server": "9.9.9.9",
             "server_port": 853, "tls_name": "dns.example"},
            {"tag": "doh", "type": "https", "server": "dns.example",
             "domain_resolver": "primary"},
        ],
        "rules": [{"name": "internal", "domain_suffix": ["example.org"],
                   "server": "secondary"}],
    })
    assert rendered["dns"] == {
        "servers": [
            {"tag": "primary", "type": "udp", "server": "1.1.1.1", "detour": "direct"},
            {"tag": "secondary", "type": "tls", "server": "9.9.9.9",
             "server_port": 853, "tls": {"server_name": "dns.example"}},
            {"tag": "doh", "type": "https", "server": "dns.example",
             "path": "/dns-query", "domain_resolver": "primary", "tls": {}},
        ],
        "rules": [{"domain_suffix": ["example.org"], "server": "secondary"}],
        "final": "primary",
    }
    assert rendered["route"]["default_domain_resolver"] == {"server": "primary"}
    legacy = generate_singbox(version())
    assert rendered["inbounds"] == legacy["inbounds"]
    assert rendered["outbounds"] == legacy["outbounds"]
    assert {k: v for k, v in rendered["route"].items() if k != "default_domain_resolver"} == legacy["route"]


def test_dns_https_tls_name_and_custom_path():
    rendered = dns_preview({"servers": [
        {"tag": "bootstrap", "server": "1.1.1.1"},
        {"tag": "secure", "type": "https", "server": "dns.example", "path": "/custom",
         "tls_name": "dns.alt", "domain_resolver": "bootstrap"},
    ]})
    assert rendered["dns"]["servers"][1] == {
        "tag": "secure", "type": "https", "server": "dns.example", "path": "/custom",
        "domain_resolver": "bootstrap", "tls": {"server_name": "dns.alt"},
    }

def test_dns_route_default_domain_resolver_first_ip_literal():
    rendered = dns_preview({"servers": [
        {"tag": "hostname", "server": "dns.example"},
        {"tag": "ip6", "server": "2001:db8::1"},
        {"tag": "ip4", "server": "1.1.1.1"},
    ]})
    assert rendered["route"]["default_domain_resolver"] == {"server": "ip6"}


def test_dns_logical_or_rule_and_rules_order():
    rendered = dns_preview({
        "servers": [{"tag": "resolver", "server": "1.1.1.1"}],
        "rules": [
            {"name": "combined", "domain_suffix": ["example.org"],
             "rule_sets": ["list_a"], "server": "resolver"},
            {"name": "sets", "rule_sets": ["list_b"], "server": "resolver"},
        ],
    })
    assert rendered["dns"]["rules"] == [
        {"type": "logical", "mode": "or", "rules": [
            {"domain_suffix": ["example.org"]}, {"rule_set": ["list_a"]},
        ], "server": "resolver"},
        {"rule_set": ["list_b"], "server": "resolver"},
    ]


def test_dns_no_default_domain_resolver_when_no_dns():
    assert "dns" not in dns_preview({})
    assert "default_domain_resolver" not in dns_preview({})["route"]
    assert "dns" not in generate_singbox(version())
    assert "default_domain_resolver" not in generate_singbox(version())["route"]
    assert dns_preview({"servers": [{"tag": "only", "server": "1.1.1.1"}]})["dns"] == {
        "servers": [{"tag": "only", "type": "udp", "server": "1.1.1.1"}], "final": "only",
    }

def test_dns_hostname_only_fails_bootstrap_required():
    with pytest.raises(ValidationError, match="tproxy.dns_bootstrap_required"):
        version(tproxy={"dns": {"servers": [{"tag": "h", "type": "udp", "server": "dns.google"}]}})

@pytest.mark.parametrize(("dns", "error"), [
    ({"servers": [{"tag": "bad", "server": ""}]},
     "tproxy.dns_server_required"),
    ({"servers": [{"tag": "ok", "type": "tls", "server": "1.1.1.1"}]},
     "tproxy.dns_tls_name_required"),
    ({"servers": [{"tag": "ok", "type": "udp", "server": "example.com"}]},
     "tproxy.dns_bootstrap_required"),
    ({"servers": [{"tag": "ok", "type": "udp", "server": "1.1.1.1"}],
      "rules": [{"name": "empty", "server": "ok"}]},
     "tproxy.dns_rule_matcher_required"),
    ({"rules": [{"name": "r", "domain_suffix": ["example.org"], "server": "missing"}]},
     "tproxy.dns_servers_required"),
    ({"servers": [{"tag": "same", "type": "udp", "server": "1.1.1.1"},
                  {"tag": "same", "type": "tls", "server": "9.9.9.9", "tls_name": "x"}]},
     "tproxy.dns_server_duplicate"),
    ({"servers": [{"tag": "ok", "type": "udp", "server": "1.1.1.1"}],
      "rules": [{"name": "same", "domain_suffix": ["a.test"], "server": "ok"},
                {"name": "same", "rule_sets": ["list_a"], "server": "ok"}]},
     "tproxy.dns_rule_duplicate"),
    ({"servers": [{"tag": "ok", "type": "udp", "server": "1.1.1.1"}],
      "rules": [{"name": "r", "domain_suffix": ["a.test"], "server": "missing"}]},
     "tproxy.dns_rule_server_unavailable"),
])
def test_dns_validator_codes(dns, error):
    with pytest.raises(ValidationError, match=error):
        version(tproxy={"dns": dns})

SB = "/home/poshl9k/.hermes/cache/scratch/vm-lab/sb-extract/sing-box-1.14.2-linux-amd64/sing-box"


def test_dns_policy_passes_singbox_check(tmp_path):
    import subprocess
    from pathlib import Path

    sb = Path(SB)
    if not sb.exists():
        pytest.skip("pinned sing-box not available")
    preview = dns_preview({
        "servers": [
            {"tag": "primary", "server": "1.1.1.1", "detour": "direct"},
            {"tag": "secure", "type": "tls", "server": "9.9.9.9",
             "server_port": 853, "tls_name": "cloudflare-dns.com"},
            {"tag": "doh", "type": "https", "server": "dns.example",
             "domain_resolver": "primary"},
        ],
        "rules": [{"name": "internal", "domain_suffix": ["example.org"],
                   "server": "secure"}],
    })
    config = tmp_path / "c.json"
    config.write_text(json.dumps(preview))
    check = subprocess.run([str(sb), "check", "-c", str(config)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
