from pathlib import Path
import json
import pytest
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
