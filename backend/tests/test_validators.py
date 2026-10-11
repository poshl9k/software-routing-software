import pytest
from pydantic import ValidationError
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.validators import port_range
from scenarios import scenario


def test_firewall_tcp_udp_port_validation():
    config = Configuration.model_validate({
        "interfaces": [{"name": "eth0", "zone": "lan"}],
        "firewall_rules": [{"name": "both", "ingress_zone": "lan", "protocol": "tcp_udp",
                            "destination_ports": "443", "action": "pass"}],
    })
    assert config.firewall_rules[0].protocol == "tcp_udp"
    assert config.firewall_rules[0].destination_ports == "443"


def test_firewall_tcp_udp_rejects_protocol_specific_port_alias():
    with pytest.raises(ValueError, match="rule.port_protocol"):
        Configuration.model_validate({
            "interfaces": [{"name": "eth0", "zone": "lan"}],
            "aliases": [{"name": "services", "type": "port", "elements": ["tcp/443", "udp/53"]}],
            "firewall_rules": [{"name": "both", "ingress_zone": "lan", "protocol": "tcp_udp",
                                "destination_ports": "@services", "action": "pass"}],
        })


@pytest.mark.parametrize("ports", ["0", "65536", "80-1", "-1", "tcp/80", "1-2-3", "80; accept"])
def test_invalid_ports(ports):
    with pytest.raises(ValueError, match="port.invalid"):
        port_range(ports)


@pytest.mark.parametrize("elements", [["tcp/0"], ["udp/65536"], ["80"], ["icmp/80"]])
def test_invalid_port_alias(elements):
    with pytest.raises(ValidationError):
        Configuration(aliases=[{"name": "ports", "type": "port", "elements": elements}])


def test_cycles():
    with pytest.raises(ValidationError, match="alias.cycle"):
        Configuration(aliases=[{"name": "a", "type": "address", "includes": ["b"]},
                               {"name": "b", "type": "address", "includes": ["a"]}])


def test_incompatible_aliases():
    with pytest.raises(ValidationError, match="alias.incompatible_type"):
        Configuration(aliases=[{"name": "a", "type": "address", "includes": ["b"]},
                               {"name": "b", "type": "port"}])


@pytest.mark.parametrize("change", [
    {"pools": [{"start": "192.168.10.100", "end": "192.168.10.150"}, {"start": "192.168.10.150", "end": "192.168.10.200"}]},
    {"pools": [{"start": "192.168.10.200", "end": "192.168.10.100"}]},
    {"pools": [{"start": "192.168.10.1", "end": "192.168.10.100"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.10"}, {"hw_address": "AA:BB:CC:DD:EE:01", "ip_address": "192.168.10.11"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.10"}, {"hw_address": "aa:bb:cc:dd:ee:02", "ip_address": "192.168.10.10"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.11.10"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.255"}]},
])
def test_invalid_dhcp(change):
    data = scenario("typical").model_dump()
    data["configuration"]["dhcp_subnets"][0].update(change)
    with pytest.raises(ValidationError):
        ConfigurationVersion.model_validate(data)


def test_alias_overlap_allowed():
    Configuration(aliases=[{"name": "overlap", "type": "address", "elements": ["10.0.0.0/24", "10.0.0.1"]}])


def test_router_not_assignable():
    with pytest.raises(ValidationError, match="router_zone_reserved"):
        Configuration(interfaces=[{"name": "eth0", "zone": "router"}])


def test_config_injection_rejected():
    with pytest.raises(ValidationError):
        Configuration(interfaces=[{"name": 'eth0" accept'}])


def test_legacy_configuration_has_disabled_tproxy_and_roundtrips():
    configuration = Configuration.model_validate({})
    payload = configuration.model_dump(mode="json")
    assert payload["tproxy"] == {
        "enabled": False,
        "ingress_interfaces": [],
        "rules": [],
        "bypass": [],
        "dns": {"servers": [], "rules": []},
        "final": "direct",
        "final_outbound": None,
        "update_schedule": {"mode": "interval", "interval_hours": 6, "window_start": "00:00", "window_end": "05:00"},
        "sniff": False,
        "udp_timeout_seconds": None,
        "clash_api_port": 9099,
    }
    assert Configuration.model_validate(payload).model_dump(mode="json") == payload


@pytest.mark.parametrize("tproxy", [
    {"enabled": True},
    {"enabled": True, "ingress_interfaces": ["lan0"]},
    {"enabled": True, "rules": [
        {"name": "blocked", "domain_suffix": ["example.org"], "action": "block"},
    ]},
])
def test_tproxy_enabled_requires_ingress_and_rules(tproxy):
    with pytest.raises(ValidationError, match="tproxy.enabled_incomplete"):
        Configuration.model_validate({"interfaces": [{"name": "lan0", "zone": "lan"}],
                                      "tproxy": tproxy})


def test_tproxy_complete_enabled_policy_validates_and_roundtrips():
    payload = {"interfaces": [{"name": "lan0", "zone": "lan"}], "tproxy": {
        "enabled": True, "ingress_interfaces": ["lan0"], "rules": [
            {"name": "blocked", "domain_suffix": ["example.org"], "action": "block"},
        ],
    }}
    config = Configuration.model_validate(payload)
    assert config.tproxy.enabled is True
    assert Configuration.model_validate(config.model_dump(mode="json")) == config


@pytest.mark.parametrize(("changes", "error"), [
    ({"ingress_interfaces": ["wan0"]}, "tproxy.ingress_interface"),
    ({"ingress_interfaces": ["lan0", "lan0"]}, "tproxy.ingress_interface"),
    ({"rules": [
        {"name": "same", "domain_suffix": ["example.org"]},
        {"name": "same", "ip_cidr": ["198.18.0.0/15"]},
    ]}, "tproxy.duplicate_rule"),
    ({"rules": [{"name": "r", "domain_suffix": ["example.org"],
                 "action": "route", "outbound": "missing"}]}, "tproxy.outbound_unavailable"),
    ({"rules": [{"name": "r", "rule_sets": ["missing"]}]},
     "tproxy.ruleset_unavailable"),
    ({"final": "route"}, "tproxy.final_outbound_required"),
    ({"final": "route", "final_outbound": "missing"},
     "tproxy.final_outbound_unavailable"),
    ({"final": "block", "final_outbound": "missing"},
     "tproxy.final_outbound_unexpected"),
])
def test_invalid_enabled_tproxy_has_specific_error(changes, error):
    policy = {"enabled": True, "ingress_interfaces": ["lan0"], "rules": [
        {"name": "blocked", "domain_suffix": ["example.org"], "action": "block"},
    ]}
    policy.update(changes)
    with pytest.raises(ValidationError, match=error):
        Configuration.model_validate({"interfaces": [
            {"name": "lan0", "zone": "lan"}, {"name": "wan0", "zone": "wan"},
        ], "tproxy": policy})


def test_tproxy_ingress_must_be_assigned_non_wan_interface():
    interfaces = [{"name": "eth0", "zone": "wan"},
                  {"name": "eth1", "zone": "lan"}, {"name": "eth2"}]
    for ingress in ("missing", "eth0", "eth2"):
        with pytest.raises(ValidationError, match="tproxy.ingress_interface"):
            Configuration.model_validate({"interfaces": interfaces, "tproxy": {"ingress_interfaces": [ingress]}})
    Configuration.model_validate({"interfaces": interfaces, "tproxy": {"ingress_interfaces": ["eth1"]}})


@pytest.mark.parametrize("schedule", [
    {"mode": "window", "window_start": "25:00"},
    {"mode": "window", "window_start": "05:00", "window_end": "00:00"},
    {"mode": "window", "window_start": "00:00", "window_end": "00:00"},
    {"mode": "interval", "interval_hours": 0},
])
def test_tproxy_invalid_update_schedule_rejected(schedule):
    with pytest.raises(ValidationError):
        Configuration.model_validate({"tproxy": {"update_schedule": schedule}})


def test_tproxy_daily_window_schedule_roundtrips():
    config = Configuration.model_validate({"tproxy": {"update_schedule": {
        "mode": "window", "window_start": "01:30", "window_end": "04:00",
    }}})
    assert config.tproxy.update_schedule.mode == "window"
    assert config.tproxy.update_schedule.window_start == "01:30"


def test_tproxy_rule_requires_matcher_and_unique_name():
    with pytest.raises(ValidationError, match="tproxy.rule_matcher_required"):
        Configuration.model_validate({"tproxy": {"rules": [{"name": "empty", "action": "direct"}]}})
    with pytest.raises(ValidationError, match="tproxy.duplicate_rule"):
        Configuration.model_validate({"tproxy": {"rules": [
            {"name": "service", "domain_suffix": ["example.org"], "action": "direct"},
            {"name": "service", "ip_cidr": ["203.0.113.0/24"], "action": "block"},
        ]}})


def test_tproxy_rule_rejects_bad_domain_and_network():
    for rule in ({"name": "bad", "domain_suffix": ["example.org; accept"], "action": "direct"},
                 {"name": "bad", "ip_cidr": ["not-ip"], "action": "direct"}):
        with pytest.raises(ValidationError):
            Configuration.model_validate({"tproxy": {"rules": [rule]}})
