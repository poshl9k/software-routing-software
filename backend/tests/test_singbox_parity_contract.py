"""Additive sing-box parity contract; no network or host changes."""
import pytest
from pydantic import ValidationError

from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion, TProxyRule, ProxySubscription


def preview(**configuration):
    version = ConfigurationVersion.model_validate({"configuration": configuration})
    return generate_singbox(version)


def test_flat_matchers_and_protocol_alias():
    rules = preview(tproxy={"rules": [{"name": "match", "domain_exact": ["a.test"],
        "source_mac": ["aa:bb:cc:dd:ee:ff"], "inbound": ["tproxy-tcp"],
        "ip_is_private": False, "network": "tcp", "protocol": "tcp"}]})["route"]["rules"]
    assert rules[0] == {"action": "sniff"}
    assert rules[1] == {"domain": ["a.test"], "source_mac_address": ["aa:bb:cc:dd:ee:ff"],
        "inbound": ["tproxy-tcp"], "ip_is_private": False, "network": ["tcp"],
        "action": "route", "outbound": "direct"}


def test_domain_matchers_render_individually_and_logical_and():
    for key, rendered_key in (("domain_keyword", "domain_keyword"),
                              ("domain_regex", "domain_regex")):
        rules = preview(tproxy={"rules": [{"name": "single", key: ["shop"]}]})["route"]["rules"]
        assert rules[-1][rendered_key] == ["shop"]
    rules = preview(tproxy={"rules": [{"name": "both", "logical_mode": "and",
        "logical_rules": [{"name": "first", "domain_exact": ["shop.test"]},
                          {"name": "second", "domain_keyword": ["shop"]}]}]})["route"]["rules"]
    assert rules[-1]["mode"] == "and"
    assert rules[-1]["rules"] == [{"domain": ["shop.test"]}, {"domain_keyword": ["shop"]}]


def test_logical_or_and_engine_options():
    rendered = preview(tproxy={"sniff": True, "udp_timeout_seconds": 90,
        "rules": [{"name": "either", "logical_mode": "or", "logical_rules": [
            {"name": "one", "ip_cidr": ["10.0.0.0/8"], "ports": ["443"]},
            {"name": "two", "source_mac": ["aa:bb:cc:dd:ee:ff"]}]}]})
    assert rendered["route"]["rules"] == [
        {"action": "sniff"}, {"action": "route-options", "udp_timeout": "90s"},
        {"type": "logical", "mode": "or", "rules": [
            {"ip_cidr": ["10.0.0.0/8"], "port": [443]},
            {"source_mac_address": ["aa:bb:cc:dd:ee:ff"]}],
         "action": "route", "outbound": "direct"}]


@pytest.mark.parametrize(("changes", "code"), [
    ({"source_mac": ["ab:cd"]}, "tproxy.source_mac_invalid"),
    ({"domain_regex": ["("]}, "tproxy.domain_regex_invalid"),
    ({"domain_keyword": [" "]}, "tproxy.matcher_empty"),
    ({"domain_exact": ["a.test"], "domain_keyword": ["shop"]}, "tproxy.domain_matchers_conflict"),
    ({"ip_is_private": "true"}, "bool_type"),
    ({"network": "udp", "protocol": "tcp"}, "tproxy.network_conflict"),
    ({"logical_mode": "or"}, "tproxy.logical_rules_required"),
    ({"logical_rules": [{"name": "one", "ip_cidr": ["10.0.0.0/8"]},
                        {"name": "two", "ports": ["443"]}]}, "tproxy.logical_mode_required"),
])
def test_bad_matchers(changes, code):
    with pytest.raises(ValidationError, match=code):
        TProxyRule.model_validate({"name": "test", "ip_cidr": ["10.0.0.0/8"], **changes})


def test_nested_logical_rule_rejected():
    inner = {"name": "inner", "logical_mode": "or", "logical_rules": [
        {"name": "a", "ports": ["80"]}, {"name": "b", "ports": ["443"]}]}
    with pytest.raises(ValidationError, match="tproxy.logical_nested"):
        TProxyRule.model_validate({"name": "outer", "logical_mode": "or",
            "logical_rules": [inner, {"name": "third", "ports": ["53"]}]})


def test_group_tolerance_only_urltest():
    config = preview(proxies={"enabled": True, "outbounds": [{"tag": "p", "type": "direct"}],
        "groups": [{"tag": "auto", "type": "urltest", "outbounds": ["p"], "tolerance_ms": 0},
                   {"tag": "pick", "type": "selector", "outbounds": ["p"], "tolerance_ms": 5}]})
    assert config["outbounds"][-2]["tolerance"] == 0
    assert "tolerance" not in config["outbounds"][-1]


def test_subscription_inline_and_headers():
    sub = ProxySubscription(name="list", url="", inline=True, inline_content="vless://example",
                            headers=("Authorization: bearer token",), mode="urltest",
                            test_tolerance_ms=0)
    assert sub.mode == "urltest"
    preview(proxies={"subscriptions": [sub.model_dump()]})
    with pytest.raises(ValidationError, match="proxy.subscription_https_required"):
        preview(proxies={"subscriptions": [{"name": "list", "url": "http://bad"}]})


@pytest.mark.parametrize(("changes", "code"), [
    ({"inline": True}, "proxy.subscription_inline_content_required"),
    ({"headers": ["bad header"]}, "proxy.subscription_header_invalid"),
    ({"filter_include": "["}, "proxy.subscription_filter_invalid"),
    ({"test_interval_minutes": 0}, "greater_than_equal"),
    ({"test_tolerance_ms": 5001}, "less_than_equal"),
])
def test_subscription_bad_values(changes, code):
    with pytest.raises(ValidationError, match=code):
        ProxySubscription.model_validate({"name": "list", "url": "https://example.org", **changes})
