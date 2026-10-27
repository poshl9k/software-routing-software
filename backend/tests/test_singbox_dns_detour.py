"""DNS detours derived from product routing, without root or network."""
import pytest

from vs_router.api.configuration import validate
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion, RoutingRule


TUNNEL_EXIT = {"kind": "tunnel", "name": "client_vpn"}
PROXY_EXIT = {"kind": "outbound", "tag": "remote"}


def document():
    return {
        "interfaces": [{"name": "wg1"}],
        "tunnels": [{"name": "client_vpn", "interface": "wg1", "role": "client",
                     "protocol": "wg", "endpoint": "vpn.example:51820",
                     "server_public_key": "S" * 44,
                     "private_key": {"encrypted": True, "ciphertext": "gAAAAplaceholder"}}],
        "proxies": {"outbounds": [{"tag": "remote", "type": "vless",
                                   "server": "203.0.113.5", "port": 443}]},
        "tproxy": {"dns": {
            "servers": [{"tag": "resolver", "server": "9.9.9.9"},
                        {"tag": "unused", "server": "1.1.1.1"}],
            "rules": [{"name": "domain", "domain_suffix": ["example.org"],
                       "server": "resolver"}],
        }},
    }


def rule(name="site", target=None, **matchers):
    return {"name": name, "exit": target or TUNNEL_EXIT,
            **(matchers or {"domain_suffix": ["example.org"]})}


def version(data):
    return ConfigurationVersion.model_validate({"profile": "panel", "configuration": data})


def servers(data):
    return {s["tag"]: s for s in generate_singbox(version(data))["dns"]["servers"]}


def test_criterion_1_suffix_tunnel_detour_and_no_mutation():
    data = document()
    data["routing_rules"] = [rule()]
    parsed = version(data)
    before = parsed.model_dump_json()
    output = generate_singbox(parsed)
    assert output["dns"]["servers"][0]["detour"] == "routing-tunnel:client_vpn"
    assert "detour" not in output["dns"]["servers"][1]
    assert {"domain_suffix": ["example.org"], "action": "route",
            "outbound": "routing-tunnel:client_vpn"} in output["route"]["rules"]
    assert {"type": "direct", "tag": "routing-tunnel:client_vpn",
            "bind_interface": "wg1"} in output["outbounds"]
    assert parsed.model_dump_json() == before
    assert generate_singbox(parsed) == output


def test_criterion_2_suffix_outbound_detour():
    data = document()
    data["routing_rules"] = [rule(target=PROXY_EXIT)]
    output = generate_singbox(version(data))
    assert output["dns"]["servers"][0]["detour"] == "remote"
    assert {"domain_suffix": ["example.org"], "action": "route",
            "outbound": "remote"} in output["route"]["rules"]
    assert any(o["tag"] == "remote" for o in output["outbounds"])


@pytest.mark.parametrize("explicit", ["direct", "remote", ""])
def test_criterion_3_explicit_detour_wins_even_over_ambiguity(explicit):
    data = document()
    data["tproxy"]["dns"]["servers"][0]["detour"] = explicit
    data["routing_rules"] = [rule(), rule("conflict", PROXY_EXIT)]
    assert validate(data)["valid"] is True
    assert servers(data)["resolver"]["detour"] == explicit


def test_criterion_4_direct_exit_omits_detour():
    data = document()
    data["routing_rules"] = [rule(target={"kind": "direct"})]
    assert "detour" not in servers(data)["resolver"]


def test_criterion_5_ambiguous_validation_and_generator_refusal():
    data = document()
    parsed = version(data)
    data["routing_rules"] = [rule(), rule("conflict", PROXY_EXIT)]
    result = validate(data)
    assert result["valid"] is False
    assert any(detail["message"] == "tproxy.dns_detour_ambiguous"
               for error in result["errors"] for detail in error["details"])
    with pytest.raises(ValueError, match="tproxy.dns_detour_ambiguous"):
        version(data)
    # model_copy bypasses Pydantic validation: generation must still fail closed.
    unsafe = parsed.model_copy(update={"configuration": parsed.configuration.model_copy(
        update={"routing_rules": tuple(RoutingRule.model_validate(r)
                                       for r in data["routing_rules"])})})
    with pytest.raises(ValueError, match="^tproxy.dns_detour_ambiguous$"):
        generate_singbox(unsafe)


def test_criterion_6_no_routing_rules_preserves_dns_exactly():
    data = document()
    dns = generate_singbox(version(data))["dns"]
    assert dns == {
        "servers": [{"tag": "resolver", "type": "udp", "server": "9.9.9.9"},
                    {"tag": "unused", "type": "udp", "server": "1.1.1.1"}],
        "rules": [{"domain_suffix": ["example.org"], "server": "resolver"}],
        "final": "resolver",
    }
    assert all("detour" not in server for server in dns["servers"])


@pytest.mark.parametrize("dns_suffix,matcher,domain,matched", [
    ("example.org", "domain_suffix", "api.example.org", True),
    ("api.example.org", "domain_suffix", "example.org", True),
    ("Example.ORG", "domain_suffix", "EXAMPLE.org", True),
    ("example.org", "domain_suffix", "notexample.org", False),
    ("example.org", "domain_suffix", "example.org.evil", False),
    ("example.org", "domain_exact", "example.org", True),
    ("example.org", "domain_exact", "api.example.org", True),
    ("Example.ORG", "domain_exact", "API.EXAMPLE.ORG", True),
    ("api.example.org", "domain_exact", "example.org", False),
    ("example.org", "domain_exact", "notexample.org", False),
    ("example.org", "domain_exact", "example.org.evil", False),
    (".example.org", "domain_exact", "example.org", False),
    (".example.org", "domain_exact", "api.example.org", True),
    (".example.org", "domain_suffix", "example.org", True),
])
def test_criterion_1_domain_intersection(dns_suffix, matcher, domain, matched):
    data = document()
    data["tproxy"]["dns"]["rules"][0]["domain_suffix"] = [dns_suffix]
    data["routing_rules"] = [{**rule(), "domain_suffix": [], matcher: [domain]}]
    rendered = servers(data)["resolver"]
    if matched:
        assert rendered["detour"] == "routing-tunnel:client_vpn"
    else:
        assert "detour" not in rendered


def test_criterion_5_duplicate_exit_and_direct_do_not_create_ambiguity():
    data = document()
    data["routing_rules"] = [rule(), rule("same_exit"),
                             rule("direct", {"kind": "direct"})]
    assert validate(data)["valid"] is True
    assert servers(data)["resolver"]["detour"] == "routing-tunnel:client_vpn"


def test_criterion_5_collects_all_dns_rules_for_each_server():
    data = document()
    data["tproxy"]["dns"]["rules"].append({
        "name": "other_domain", "domain_suffix": ["example.net"], "server": "resolver"})
    data["routing_rules"] = [rule(), rule("other_exit", PROXY_EXIT,
                                         domain_exact=["www.example.net"])]
    with pytest.raises(ValueError, match="tproxy.dns_detour_ambiguous"):
        version(data)
    data["tproxy"]["dns"]["rules"][1]["server"] = "unused"
    rendered = servers(data)
    assert rendered["resolver"]["detour"] == "routing-tunnel:client_vpn"
    assert rendered["unused"]["detour"] == "remote"


@pytest.mark.parametrize("explicit", [None, "remote"])
def test_criterion_6_ruleset_only_dns_rule_retains_typed_detour(explicit):
    data = document()
    data["rule_sets"] = [{"name": "sites", "format": "srs",
                          "url": "https://example.org/sites.srs"}]
    data["tproxy"]["dns"]["rules"] = [
        {"name": "ruleset", "rule_sets": ["sites"], "server": "resolver"}]
    data["tproxy"]["dns"]["servers"][0]["detour"] = explicit
    data["routing_rules"] = [rule(), rule("conflict", PROXY_EXIT)]
    rendered = servers(data)["resolver"]
    if explicit is None:
        assert "detour" not in rendered
    else:
        assert rendered["detour"] == explicit


def test_criterion_6_ip_only_routing_contributes_no_detour():
    data = document()
    data["routing_rules"] = [rule(ip_cidr=["0.0.0.0/0"])]
    assert "detour" not in servers(data)["resolver"]
