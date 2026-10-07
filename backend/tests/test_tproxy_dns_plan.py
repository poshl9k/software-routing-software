"""Offline checks for the composed TProxy DNS contour planner."""
import pytest

from vs_router.schema import ConfigurationVersion
from vs_router.generators import marks
from vs_router.generators import tproxy_dns
from vs_router.generators.tproxy_dns import plan_tproxy_dns
from vs_router.generators.unbound import (generate_tproxy_unbound_split,
                                          tproxy_unbound_listener_addresses)
from vs_router.generators.nftables import (generate_tproxy_dns_ingress_guard,
                                           generate_tproxy_dns_listener_guard,
                                           generate_tproxy_dns_output_guard)


def version(dns=None, ingress=("lan0",)):
    base = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "lan1", "zone": "lan", "addresses": ["10.212.3.1/24"]},
        ],
        "dns": dns or {
            "interfaces": ["lan0", "lan1"],
            "access_control": ["10.212.0.0/16"],
            "records": [{"name": "router.test.", "value": "192.0.2.77"}],
            "forwards": [{"domain": "corp.test.", "upstreams": ["198.18.0.2"]}],
            "upstreams": ["198.18.0.3"],
        },
        "tproxy": {"ingress_interfaces": list(ingress)},
    }})
    tproxy = base.configuration.tproxy.model_copy(update={"enabled": True})
    return base.model_copy(update={"configuration": base.configuration.model_copy(
        update={"tproxy": tproxy})})


def disabled(v=None):
    v = v or version()
    return v.model_copy(update={"configuration": v.configuration.model_copy(
        update={"tproxy": v.configuration.tproxy.model_copy(update={"enabled": False})})})


def test_enabled_plan_composes_existing_generators_and_orders_hooks():
    v = version()
    plan = plan_tproxy_dns(v, 29092)
    assert plan.enabled is True
    assert plan.selected_uid == 29092
    # Order is one explicit contract: ingress -> listener -> output.
    assert [g.role for g in plan.nft_guards] == ["ingress", "listener", "output"]
    assert [g.table for g in plan.nft_guards] == [
        tproxy_dns.INGRESS_TABLE, tproxy_dns.LISTENER_TABLE, tproxy_dns.OUTPUT_TABLE]
    assert [(g.hook, g.priority) for g in plan.nft_guards] == [
        ("prerouting", -110), ("input", -10), ("output", -20)]
    # Content is byte-for-byte the existing generators' output, nothing new.
    assert plan.nft_guards[0].content == generate_tproxy_dns_ingress_guard(v)
    assert plan.nft_guards[1].content == generate_tproxy_dns_listener_guard(v)
    assert plan.nft_guards[2].content == generate_tproxy_dns_output_guard(v, 29092)
    assert plan.selected_unbound == generate_tproxy_unbound_split(v)["selected"]
    assert plan.ordinary_unbound == generate_tproxy_unbound_split(v)["ordinary"]
    assert plan.warnings == tproxy_dns.WARNINGS
    assert plan_tproxy_dns(v, 29092) == plan  # deterministic


def test_guard_metadata_matches_shared_marks_registry():
    registered = {(h.table, h.chain): (h.hook, h.priority) for h in marks.HOOKS}
    for guard in plan_tproxy_dns(version(), 29092).nft_guards:
        assert registered[(guard.table, guard.chain)] == (guard.hook, guard.priority)


def test_listener_addresses_agree_between_configs_and_guards():
    v = version()
    plan = plan_tproxy_dns(v, 29092)
    assert plan.listener_addresses == tproxy_unbound_listener_addresses(v)
    assert plan.listener_addresses["selected"] == ("10.212.1.1",)
    assert plan.listener_addresses["ordinary"] == ("10.212.3.1",)
    assert plan.selected_unbound is not None and plan.ordinary_unbound is not None
    # Selected config binds only selected addresses; ordinary only the others.
    assert "interface: 10.212.1.1\n" in plan.selected_unbound
    assert "interface: 10.212.3.1\n" not in plan.selected_unbound
    assert "interface: 10.212.3.1\n" in plan.ordinary_unbound
    assert "interface: 10.212.1.1\n" not in plan.ordinary_unbound
    # Guards reference the same selected address / ingress interface.
    assert 'iifname != { "lan0" } return' in plan.nft_guards[0].content
    assert 'iifname { "lan0" } ip daddr != { 10.212.1.1 } counter drop' in plan.nft_guards[1].content
    assert 'iifname != { "lan0" } ip daddr { 10.212.1.1 } counter drop' in plan.nft_guards[1].content
    assert 'meta skuid 29092 oifname "lan0" ip saddr 10.212.1.1' in plan.nft_guards[2].content


def test_local_records_and_explicit_forwards_keep_priority():
    plan = plan_tproxy_dns(version(), 29092)
    assert plan.selected_unbound is not None and plan.ordinary_unbound is not None
    for content in (plan.selected_unbound, plan.ordinary_unbound):
        assert 'local-data: "router.test. 300 IN A 192.0.2.77"' in content
        assert 'name: "corp.test."\n    forward-addr: 198.18.0.2' in content
    # Selected unmatched goes to the loopback stub; the global upstream cannot
    # become an OUTPUT exception for the selected resolver.
    assert 'name: "."\n    forward-addr: 127.0.0.1@15353' in plan.selected_unbound
    assert 'forward-addr: 198.18.0.3' not in plan.selected_unbound
    output = plan.nft_guards[2].content
    assert 'th dport 53 counter return comment "tproxy_dns_explicit_forward"' in output
    assert output.index("tproxy_dns_explicit_forward") < output.index("tproxy_dns_output_denied")
    assert "198.18.0.3" not in output


def test_disabled_plan_removes_only_its_own_tables():
    plan = plan_tproxy_dns(disabled(), None)
    assert plan.enabled is False
    assert plan.selected_uid is None
    assert plan.selected_unbound is None and plan.ordinary_unbound is None
    assert plan.listener_addresses == {}
    assert [g.content for g in plan.nft_guards] == [
        f"destroy table {tproxy_dns.INGRESS_TABLE}\n",
        f"destroy table {tproxy_dns.LISTENER_TABLE}\n",
        f"destroy table {tproxy_dns.OUTPUT_TABLE}\n",
    ]
    # No service/contour activation snuck into the off-plan.
    assert all("hook" not in g.content and "table " not in g.content.replace("destroy table", "")
               for g in plan.nft_guards)


@pytest.mark.parametrize("uid", [0, -1, 65536, True, None])
def test_enabled_plan_rejects_invalid_or_missing_uid(uid):
    with pytest.raises(ValueError, match="tproxy.dns_output_invalid_uid"):
        plan_tproxy_dns(version(), uid)


@pytest.mark.parametrize("uid", [0, -1, 65536, True])
def test_disabled_plan_still_rejects_provided_invalid_uid(uid):
    with pytest.raises(ValueError, match="tproxy.dns_output_invalid_uid"):
        plan_tproxy_dns(disabled(), uid)


def test_public_gate_stays_closed_and_plan_offs_validated_model():
    v = version()
    with pytest.raises(ValueError, match="tproxy.not_available"):
        ConfigurationVersion.model_validate(v.model_dump())
    # A validated (necessarily disabled) model only ever yields the off-plan.
    plain = ConfigurationVersion.model_validate({"configuration": {}})
    assert plan_tproxy_dns(plain, None).enabled is False


def test_plan_fails_closed_on_missing_selected_listener():
    with pytest.raises(ValueError, match="tproxy.dns_split_missing_listener"):
        plan_tproxy_dns(version(dns={"interfaces": ["lan1"]}), 29092)
