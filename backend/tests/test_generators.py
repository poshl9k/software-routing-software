from pathlib import Path
import json
import pytest
from pydantic import ValidationError
from vs_router.generators import generate_kea, generate_nftables, generate_unbound
from vs_router.schema import ConfigurationVersion
from scenarios import scenario


@pytest.mark.parametrize("name", ["empty", "typical", "edge"])
@pytest.mark.parametrize("generator,extension", [(generate_nftables, "nft"), (generate_unbound, "conf"), (generate_kea, "json")])
def test_golden(name, generator, extension):
    version = scenario(name)
    before = version.model_dump_json()
    result = generator(version)
    assert result == (Path(__file__).parent / "golden" / f"{name}.{extension}").read_text()
    assert generator(version) == result
    assert version.model_dump_json() == before


def test_nft_security_and_order():
    output = generate_nftables(scenario("edge"))
    forward = output.split("chain forward {")[1].split("chain prerouting")[0]
    assert forward.index('iifname !=') < forward.index('ct state established')
    assert forward.index('oifname !=') < forward.index('ct state established')
    assert forward.index('"blocked"') < forward.index('"web_allow"') < forward.index('"reject_rest"')
    assert 'ct status dnat ct original ip daddr 203.0.113.3 ct original proto-dst 443' in forward
    assert 'counter accept\n' not in forward
    assert 'udp dport' not in forward
    assert 'eth2' not in output
    assert output.index('counter return') < output.index('snat ip to') < output.index('counter masquerade')


@pytest.mark.parametrize("mode,manual,auto", [("automatic", False, True), ("hybrid", True, True), ("manual", True, False), ("disabled", False, False)])
def test_nat_modes(mode, manual, auto):
    data = scenario("edge").model_dump()
    data["configuration"]["outbound_nat_mode"] = mode
    output = generate_nftables(ConfigurationVersion.model_validate(data))
    assert ("snat ip to" in output) == manual
    assert ("masquerade" in output) == auto


def test_kea_both_reservation_kinds():
    subnet = json.loads(generate_kea(scenario("edge")))["Dhcp4"]["subnet4"][0]
    assert subnet["reservations-in-subnet"] is True
    assert subnet["reservations-out-of-pool"] is False
    assert [r["ip-address"] for r in subnet["reservations"]] == ["192.168.10.110", "192.168.10.10"]


def test_dns_no_wildcard_or_implicit_recursion():
    output = generate_unbound(scenario("empty"))
    assert 'interface: 0.0.0.0' not in output
    assert 'local-zone: "." refuse' in output


def test_domain_only_forward_not_shadowed_by_root_refusal():
    version = ConfigurationVersion(configuration={"dns": {"forwards": [
        {"domain": "corp.example", "upstreams": ["192.0.2.53"]}]}})
    output = generate_unbound(version)
    assert 'local-zone: "." refuse' in output
    assert 'local-zone: "corp.example" transparent' in output
    assert 'forward-addr: 192.0.2.53' in output


def test_recursive_mode_is_explicit():
    output = generate_unbound(ConfigurationVersion(configuration={"dns": {"recursive": True}}))
    assert 'local-zone: "." refuse' not in output
    assert 'forward-zone:' not in output


def test_primary_translation_and_disabled_rules():
    data = scenario("typical").model_dump()
    data["configuration"]["outbound_nat_mode"] = "manual"
    data["configuration"]["outbound_nat"] = [{"name": "primary", "translation": "primary"}]
    data["configuration"]["firewall_rules"][0]["enabled"] = False
    output = generate_nftables(ConfigurationVersion.model_validate(data))
    assert 'counter masquerade comment "primary"' in output
    assert 'comment "lan_allow"' not in output


def test_router_destination_only_in_input():
    data = scenario("typical").model_dump()
    data["configuration"]["firewall_rules"][0]["dst"] = "zone:router"
    output = generate_nftables(ConfigurationVersion.model_validate(data))
    assert 'comment "lan_allow"' in output.split('chain forward')[0]
    assert 'comment "lan_allow"' not in output.split('chain forward')[1]


# --- DNS upstreams: bare-string compatibility and DoT (ADR-0015 D1) ---------

def test_legacy_string_upstreams_render_plain_forward_addr():
    version = ConfigurationVersion(configuration={"dns": {
        "forwards": [{"domain": "corp.example", "upstreams": ["192.0.2.53"]}],
        "upstreams": ["198.51.100.53", {"address": "203.0.113.53", "port": 5353}],
    }})
    output = generate_unbound(version)
    assert 'forward-addr: 192.0.2.53' in output
    assert 'forward-addr: 198.51.100.53' in output
    assert 'forward-addr: 203.0.113.53@5353' in output
    assert 'forward-tls-upstream' not in output


def test_invalid_upstream_address_is_rejected():
    with pytest.raises(ValidationError, match="dns.upstream_invalid"):
        ConfigurationVersion(configuration={"dns": {"upstreams": ["not-an-ip"]}})


def test_tls_upstream_renders_dot_and_sets_flag_once_per_zone():
    version = ConfigurationVersion(configuration={"dns": {
        "forwards": [{"domain": "corp.example", "upstreams": [
            {"address": "1.1.1.1", "port": 853, "mode": "tls", "tls_name": "cloudflare-dns.com"},
            {"address": "9.9.9.9", "port": 853, "mode": "tls", "tls_name": "dns.quad9.net"}]}]}})
    output = generate_unbound(version)
    assert 'forward-addr: 1.1.1.1@853#cloudflare-dns.com' in output
    assert 'forward-addr: 9.9.9.9@853#dns.quad9.net' in output
    assert output.count('forward-tls-upstream: yes') == 1


def test_udp_zone_has_no_tls_flag_next_to_a_tls_zone():
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"address": "1.1.1.1", "mode": "tls", "tls_name": "cloudflare-dns.com"}],
        "forwards": [{"domain": "corp.example", "upstreams": ["192.0.2.53"]}]}})
    output = generate_unbound(version)
    corp = output.split('name: "corp.example"')[1].split("forward-zone:")[0]
    assert "forward-tls-upstream" not in corp
    assert 'forward-addr: 192.0.2.53' in corp


def test_tls_upstream_requires_tls_name():
    with pytest.raises(ValidationError, match="dns.upstream_tls_name_required"):
        ConfigurationVersion(configuration={"dns": {
            "upstreams": [{"address": "1.1.1.1", "port": 853, "mode": "tls"}]}})
