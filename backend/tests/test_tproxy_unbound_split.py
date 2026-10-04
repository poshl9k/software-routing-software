"""Offline resolver layout only; never activates a TProxy DNS service."""
import pytest
from vs_router.schema import ConfigurationVersion
from vs_router.generators.unbound import (generate_unbound, generate_tproxy_unbound_split,
                                          tproxy_unbound_listener_addresses)
from vs_router.generators.nftables import (generate_tproxy_dns_listener_guard,
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


def test_split_is_offline_with_distinct_listeners_and_identical_local_exceptions():
    v = version()
    selected, ordinary = (generate_tproxy_unbound_split(v)[key]
                          for key in ("selected", "ordinary"))
    assert "interface: 10.212.1.1\n" in selected
    assert "interface: 10.212.3.1\n" not in selected
    assert "interface: 10.212.3.1\n" in ordinary
    assert "interface: 10.212.1.1\n" not in ordinary
    for content in (selected, ordinary):
        assert 'local-data: "router.test. 300 IN A 192.0.2.77"' in content
        assert 'name: "corp.test."\n    forward-addr: 198.18.0.2' in content
    assert 'name: "."\n    forward-addr: 127.0.0.1@15353' in selected
    assert 'do-not-query-localhost: no' in selected
    assert 'do-not-query-localhost: no' not in ordinary
    assert 'forward-addr: 198.18.0.3' not in selected
    assert 'name: "."\n    forward-addr: 198.18.0.3' in ordinary
    assert '127.0.0.1@15353' not in ordinary
    assert generate_tproxy_unbound_split(v)["selected"] == selected
    with pytest.raises(ValueError, match="tproxy.not_available"):
        ConfigurationVersion.model_validate(v.model_dump())
    # The live generator is byte-for-byte independent of disabled draft intent.
    off = version().model_copy(update={"configuration": v.configuration.model_copy(
        update={"tproxy": v.configuration.tproxy.model_copy(update={"enabled": False})})})
    assert generate_unbound(off) == generate_unbound(ConfigurationVersion.model_validate(off.model_dump()))
    assert '127.0.0.1@15353' not in generate_unbound(off)


def test_selected_resolver_disables_cache_without_changing_ordinary():
    split = generate_tproxy_unbound_split(version())
    selected, ordinary = split['selected'], split['ordinary']
    assert 'cache-max-ttl: 0' in selected
    assert 'cache-max-negative-ttl: 0' in selected
    assert 'serve-expired: no' in selected
    assert 'cache-max-ttl: 0' not in ordinary
    assert 'cache-max-negative-ttl: 0' not in ordinary


def test_listener_guard_rejects_cross_interface_dns_before_established_accept():
    v = version()
    assert tproxy_unbound_listener_addresses(v) == {
        "selected": ("10.212.1.1",), "ordinary": ("10.212.3.1",)}
    guard = generate_tproxy_dns_listener_guard(v)
    assert 'type filter hook input priority -10; policy accept;' in guard
    assert 'iifname != "lo" ip daddr 127.0.0.1 th dport 15353 counter drop' in guard
    assert guard.index('tproxy_dns_stub_external') < guard.index('th dport != 53 return')
    assert 'iifname { "lan0" } ip daddr != { 10.212.1.1 } counter drop' in guard
    assert 'iifname != { "lan0" } ip daddr { 10.212.1.1 } counter drop' in guard
    assert guard.index('th dport != 53 return') < guard.index('tproxy_dns_selected_wrong_listener')
    assert 'ct state established' not in guard
    off = v.model_copy(update={"configuration": v.configuration.model_copy(update={
        "tproxy": v.configuration.tproxy.model_copy(update={"enabled": False})})})
    assert generate_tproxy_dns_listener_guard(off) == (
        'destroy table inet vs_router_tproxy_dns_listener\n')
    with pytest.raises(ValueError, match="tproxy.dns_split_missing_listener"):
        generate_tproxy_dns_listener_guard(version(dns={"interfaces": ["lan1"]}))


def test_output_guard_allows_only_stub_and_explicit_forward_for_selected_uid():
    v = version()
    text = generate_tproxy_dns_output_guard(v, 29092)
    assert 'hook output priority -20; policy accept;' in text
    assert 'meta skuid 29092 oifname "lan0" ip saddr 10.212.1.1' in text
    assert 'th sport 53 counter return comment "tproxy_dns_client_reply"' in text
    assert 'meta skuid 29092 ip daddr 127.0.0.1' in text
    assert 'th dport 15353 counter return comment "tproxy_dns_stub"' in text
    assert 'meta skuid 29092 ip daddr { 198.18.0.2 }' in text
    assert 'th dport 53 counter return comment "tproxy_dns_explicit_forward"' in text
    assert text.index('tproxy_dns_explicit_forward') < text.index('tproxy_dns_output_denied')
    assert '198.18.0.3' not in text  # Global upstream cannot become an exception.
    assert text.endswith('meta skuid 29092 counter drop comment "tproxy_dns_output_denied"\n    }\n}\n')
    off = v.model_copy(update={"configuration": v.configuration.model_copy(update={
        "tproxy": v.configuration.tproxy.model_copy(update={"enabled": False})})})
    assert generate_tproxy_dns_output_guard(off, 29092) == (
        'destroy table inet vs_router_tproxy_dns_output\n')
    for uid in (0, -1, 65536, True):
        with pytest.raises(ValueError, match='tproxy.dns_output_invalid_uid'):
            generate_tproxy_dns_output_guard(v, uid)
    no_forwards = version(dns={"interfaces": ["lan0", "lan1"],
                               "upstreams": ["198.18.0.3"]})
    assert 'tproxy_dns_explicit_forward' not in generate_tproxy_dns_output_guard(no_forwards, 29092)
    ipv6_forward = version(dns={"interfaces": ["lan0", "lan1"],
                                "forwards": [{"domain": "corp.test.",
                                              "upstreams": ["2001:db8::53"]}]})
    with pytest.raises(ValueError, match='tproxy.dns_output_ipv4_required'):
        generate_tproxy_dns_output_guard(ipv6_forward, 29092)


def test_selected_only_preserves_router_loopback_for_ordinary_service():
    v = version(dns={"interfaces": ["lan0"], "access_control": ["10.212.1.0/24"]})
    split = generate_tproxy_unbound_split(v)
    assert 'interface: 10.212.1.1' in split["selected"]
    assert 'interface: 127.0.0.1' in split["ordinary"]
    assert 'interface: 127.0.0.1' not in split["selected"]


@pytest.mark.parametrize("dns,error", [
    ({"interfaces": ["lan1"]}, "tproxy.dns_split_missing_listener"),
    ({"interfaces": ["lan0", "lan1"], "recursive": True}, "tproxy.dns_split_root_unsupported"),
    ({"interfaces": ["lan0", "lan1"], "forwards": [
        {"domain": ".", "upstreams": ["198.18.0.2"]}]}, "tproxy.dns_split_root_unsupported"),
    ({"interfaces": ["lan0", "lan0"]}, "tproxy.dns_split_address_unsupported"),
])
def test_unsupported_split_is_rejected(dns, error):
    with pytest.raises(ValueError, match=error):
        generate_tproxy_unbound_split(version(dns=dns))


def test_unassigned_source_and_invalid_model_copy_fail_closed():
    with pytest.raises(ValueError, match="tproxy.dns_split_invalid_sources"):
        generate_tproxy_unbound_split(version(ingress=()))
    v = version()
    broken = v.configuration.model_copy(update={"panel_port": 22})
    with pytest.raises(ValueError, match="ssh.port_reserved"):
        generate_tproxy_unbound_split(v.model_copy(update={"configuration": broken}))


def test_split_rejects_ipv6_listener_and_shared_ip_even_on_non_dns_interface():
    v = version(dns={"interfaces": ["lan0"]})
    first, second = v.configuration.interfaces
    for interfaces in ((first.model_copy(update={"addresses": ("10.212.1.1/24", "2001:db8::1/64")}),
                        second),
                       (first, second.model_copy(update={"addresses": ("10.212.1.1/24",)}))):
        changed = v.configuration.model_copy(update={"interfaces": interfaces})
        with pytest.raises(ValueError, match="tproxy.dns_split_address_unsupported"):
            generate_tproxy_unbound_split(v.model_copy(update={"configuration": changed}))
