"""Pure sing-box configuration preview; TProxy remains guarded off for live apply."""
from vs_router.schema import ConfigurationVersion
from vs_router.generators.singbox import generate_singbox
from vs_router.generators import generate_nftables, generate_networkd, generate_unbound
from vs_router.generators import nftables
import pytest


def test_singbox_rule_order_and_address_union():
    version = ConfigurationVersion.model_validate({"configuration": {"tproxy": {"rules": [
        {"name": "second", "ip_cidr": ["203.0.113.0/24"], "action": "block", "order": 20},
        {"name": "first", "domain_suffix": ["example.org"], "ip_cidr": ["198.51.100.0/24"],
         "action": "direct", "order": 10},
    ]}}})
    generated = generate_singbox(version)
    assert generated["inbounds"] == [
        {"type": "tproxy", "tag": "tproxy-udp", "listen": "127.0.0.1", "listen_port": 51271, "network": "udp"},
        {"type": "tproxy", "tag": "tproxy-tcp", "listen": "127.0.0.1", "listen_port": 51272,
         "network": "tcp"},
    ]
    assert generated["route"]["rules"] == [
        {"action": "sniff"},
        {"type": "logical", "mode": "or", "rules": [
            {"domain_suffix": ["example.org"]}, {"ip_cidr": ["198.51.100.0/24"]},
        ], "action": "route", "outbound": "direct"},
        {"ip_cidr": ["203.0.113.0/24"], "action": "reject"},
    ]
    assert generated["route"]["final"] == "direct"
    assert generate_singbox(version) == generated


def test_singbox_empty_config_does_not_enable_interception():
    generated = generate_singbox(ConfigurationVersion())
    assert generated["route"]["rules"] == []
    assert not any(k in generated for k in ("nftables", "ip_rules", "ip_routes"))


def test_saved_disabled_policy_cannot_change_live_network_generators():
    base = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "lan0", "zone": "lan", "addresses": ["192.0.2.1/24"]}],
    }})
    configured = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "lan0", "zone": "lan", "addresses": ["192.0.2.1/24"]}],
        "tproxy": {"ingress_interfaces": ["lan0"], "rules": [
            {"name": "blocked", "domain_suffix": ["example.org"], "action": "block"},
        ]},
    }})
    for generator in (generate_nftables, generate_networkd, generate_unbound):
        assert generator(configured) == generator(base)


def test_offline_containment_precedes_conntrack_and_covers_both_families():
    generator = nftables.generate_tproxy_containment
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "lan0", "zone": "lan"}],
        "tproxy": {"ingress_interfaces": ["lan0"]},
    }})
    # Offline fixture only; public validation must keep rejecting live enablement.
    policy = version.configuration.tproxy.model_copy(update={"enabled": True})
    config = version.configuration.model_copy(update={"tproxy": policy})
    version = version.model_copy(update={"configuration": config})
    rendered = generator(version)
    assert 'table inet vs_router_tproxy_guard {' in rendered
    assert 'type filter hook forward priority -10; policy accept;' in rendered
    assert 'iifname { "lan0" } counter drop' in rendered
    assert 'ct state' not in rendered
    assert 'meta nfproto' not in rendered
    assert 'hook input' not in rendered
    assert 'hook output' not in rendered
    assert 'destroy table inet vs_router\n' not in rendered
    assert generator(version) == rendered


@pytest.mark.parametrize("sources", [[], ["wan0"], ["missing"], ["spare0"]])
def test_offline_containment_rejects_unsafe_ingress(sources):
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "lan0", "zone": "lan"},
                       {"name": "wan0", "zone": "wan"}, {"name": "spare0"}],
    }})
    policy = version.configuration.tproxy.model_copy(update={"enabled": True, "ingress_interfaces": tuple(sources)})
    config = version.configuration.model_copy(update={"tproxy": policy})
    version = version.model_copy(update={"configuration": config})
    with pytest.raises(ValueError, match="tproxy.containment_invalid_ingress"):
        nftables.generate_tproxy_containment(version)


def test_offline_containment_off_removes_only_its_own_table():
    assert nftables.generate_tproxy_containment(ConfigurationVersion()) == (
        "destroy table inet vs_router_tproxy_guard\n"
    )
