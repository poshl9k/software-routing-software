from pathlib import Path
import json
import pytest
from pydantic import ValidationError
from vs_router.generators import (generate_kea, generate_nftables, generate_unbound,
                                  generate_dnscrypt, doh_server_names)
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


def test_firewall_tcp_udp_ports():
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "eth0", "zone": "lan"}],
        "firewall_rules": [{"name": "both", "ingress_zone": "lan", "protocol": "tcp_udp",
                            "destination_ports": "443", "action": "pass"}],
    }})
    lines = [line for line in generate_nftables(version).splitlines() if 'comment "both"' in line]
    assert len(lines) == 4
    assert all("meta l4proto { tcp, udp } th dport 443" in line for line in lines)
    assert all("tcp_udp dport" not in line for line in lines)


def test_firewall_tcp_port_stays_single_protocol():
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "eth0", "zone": "lan"}],
        "firewall_rules": [{"name": "tcp_only", "ingress_zone": "lan", "protocol": "tcp",
                            "destination_ports": "443", "action": "pass"}],
    }})
    lines = [line for line in generate_nftables(version).splitlines() if 'comment "tcp_only"' in line]
    assert len(lines) == 4
    assert all("meta l4proto tcp tcp dport 443" in line for line in lines)
    assert all("meta l4proto { tcp, udp }" not in line for line in lines)


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


# --- DoH upstreams realized by the local dnscrypt-proxy (ADR-0015 D2) -------

def test_https_upstream_forwards_to_local_doh_listener():
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"mode": "https", "doh_server": "cloudflare"}]}})
    output = generate_unbound(version)
    assert "forward-addr: 127.0.0.1@5300" in output
    assert "do-not-query-localhost: no" in output
    assert "forward-tls-upstream" not in output


def test_doh_server_names_sorted_and_deduplicated():
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"mode": "https", "doh_server": "quad9"},
                      {"mode": "https", "doh_server": "cloudflare"},
                      {"mode": "https", "doh_server": "quad9"}],
        "forwards": [{"domain": "corp.example",
                      "upstreams": [{"mode": "https", "doh_server": "cloudflare"}]}]}})
    assert doh_server_names(version.configuration.dns) == ("cloudflare", "quad9")
    config = generate_dnscrypt(version)
    assert "listen_addresses = ['127.0.0.1:5300']" in config
    assert 'server_names = ["cloudflare", "quad9"]' in config


def test_doh_config_without_https_has_empty_server_list():
    version = ConfigurationVersion(configuration={"dns": {"upstreams": ["1.1.1.1"]}})
    assert "server_names = []" in generate_dnscrypt(version)


def test_https_upstream_requires_doh_server():
    with pytest.raises(ValidationError, match="dns.upstream_doh_server_required"):
        ConfigurationVersion(configuration={"dns": {"upstreams": [{"mode": "https"}]}})


def test_doh_server_on_a_plain_upstream_is_rejected():
    with pytest.raises(ValidationError, match="dns.upstream_doh_server_unexpected"):
        ConfigurationVersion(configuration={"dns": {
            "upstreams": [{"address": "1.1.1.1", "doh_server": "cloudflare"}]}})


def _service_version():
    return ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "eth0", "zone": "wan", "addresses": ["203.0.113.2/24"]},
            {"name": "eth1", "zone": "lan", "addresses": ["10.10.20.1/24"]},
            {"name": "vlan1", "type": "vlan", "parent": "eth1", "vlan_id": 201,
             "zone": "lan", "addresses": ["172.20.1.1/24"]},
        ],
        "dhcp_subnets": [{"id": 1, "interface": "vlan1", "subnet": "172.20.1.0/24",
                          "pools": [{"start": "172.20.1.20", "end": "172.20.1.250"}],
                          "routers": ["172.20.1.1"], "dns_servers": ["172.20.1.1"]}],
        "dns": {"interfaces": ["vlan1"], "access_control": ["172.20.1.0/24"]},
    }})


def test_dhcp_server_rule_is_generated_from_subnets():
    text = generate_nftables(_service_version())
    assert 'iifname "vlan1" udp sport 68 udp dport 67 counter accept comment "dhcp_server_vlan1"' in text


def test_dns_resolver_rule_follows_listeners_and_access_control():
    text = generate_nftables(_service_version())
    assert ('iifname { "vlan1" } meta nfproto ipv4 ip saddr { 172.20.1.0/24 } '
            'meta l4proto { tcp, udp } th dport 53 counter accept comment "dns_resolver_auto"') in text
    assert 'comment "dns_resolver_auto"' not in generate_nftables(ConfigurationVersion())


def test_explicit_dns_block_precedes_automatic_accept():
    version = _service_version()
    data = version.model_dump()
    data["configuration"]["firewall_rules"] = [{
        "name": "dns_block", "ingress_zone": "lan", "protocol": "udp",
        "src": "172.20.1.0/24", "dst": "zone:router", "destination_ports": "53",
        "action": "block", "order": 0,
    }]
    text = generate_nftables(ConfigurationVersion.model_validate(data))
    block = text.index('comment "dns_block"')
    auto = text.index('comment "dns_resolver_auto"')
    assert block < auto


def test_exit_snat_is_automatic_without_capture():
    version = _service_version()
    data = version.model_dump()
    data["configuration"]["routing_rules"] = [{
        "name": "wifi_upstream", "subject": {"kind": "interface", "interface": "vlan1"},
        "ip_cidr": ["0.0.0.0/0"], "domain_suffix": [], "domain_exact": [], "rule_sets": [],
        "exit": {"kind": "interface", "interface": "eth0",
                 "source": "203.0.113.2", "gateway": "203.0.113.1"},
    }]
    text = generate_nftables(ConfigurationVersion.model_validate(data))
    assert 'oifname "eth0" ip saddr { 172.20.1.0/24 } counter snat ip to 203.0.113.2 comment "exit_snat"' in text
