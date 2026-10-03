"""Offline text/compiler tests; no kernel or packet-path validation."""
from pathlib import Path

import pytest
from vs_router.schema import ConfigurationVersion
from vs_router.generators.nftables import generate_nftables, generate_tproxy_preauthorization
from scenarios import scenario


def enabled(base=None, ingress=("eth1",)):
    base = base or scenario("typical")
    c = base.configuration
    return base.model_copy(update={"configuration": c.model_copy(update={
        "tproxy": c.tproxy.model_copy(update={"enabled": True, "ingress_interfaces": ingress})})})


def rules_version(rules):
    data = scenario("typical").model_dump()
    data["configuration"]["firewall_rules"] = rules
    return enabled(ConfigurationVersion.model_validate(data))


def test_default_deny_and_exemption_precedence():
    output = generate_tproxy_preauthorization(rules_version([]))
    assert 'type filter hook prerouting priority -90; policy accept;' in output
    ordered = ['iifname != { "eth1" } return', 'fib daddr type local return',
               'ct status dnat return', 'meta nfproto != ipv4 drop',
               'meta l4proto != { tcp, udp } drop', 'ct state invalid drop',
               'fib daddr . mark oifname { "eth0", "eth1" } goto transit',
               'counter drop']
    positions = [output.index(s) for s in ordered]
    assert positions == sorted(positions)
    assert 'chain transit {\n        counter drop\n' in output
    assert 'established' not in output and 'related' not in output
    assert 'mark set' not in output and 'ct mark' not in output
    assert ' accept ' not in output


def test_first_match_disabled_ties_and_verdicts():
    output = generate_tproxy_preauthorization(rules_version([
        dict(name='z_pass', ingress_zone='lan', action='pass', order=1),
        dict(name='a_block', ingress_zone='lan', action='block', order=1, log=True),
        dict(name='disabled', ingress_zone='lan', action='pass', order=0, enabled=False),
        dict(name='reject_rest', ingress_zone='lan', action='reject', order=2),
    ]))
    assert output.index('comment "a_block"') < output.index('comment "z_pass"') < output.index('comment "reject_rest"')
    assert 'counter log prefix "vs-router " drop comment "a_block"' in output
    assert 'counter return comment "z_pass"' in output
    assert 'counter drop comment "reject_rest"' in output
    assert 'disabled' not in output


@pytest.mark.parametrize('dst', ['zone:wan', 'any', '198.51.100.0/24'])
def test_destination_uses_route_and_all_passes_require_assigned_egress(dst):
    output = generate_tproxy_preauthorization(rules_version([
        dict(name='allow', ingress_zone='lan', src='zone:lan', dst=dst, action='pass')]))
    assert output.index('oifname { "eth0", "eth1" } goto transit') < output.index('comment "allow"')
    assert 'iifname { "eth1" } meta nfproto ipv4 iifname { "eth1" }' in output
    if dst == 'zone:wan':
        assert 'fib daddr . mark oifname { "eth0" } counter return' in output
        assert '203.0.113' not in output
    assert '\n        oifname ' not in output
    # Kernel NFTA_FIB_F_IIF constrains the result to ingress, not routed egress.
    assert 'fib daddr . mark . iif' not in output


def test_nested_mixed_aliases_and_protocol_ports():
    base = scenario('edge')
    c = base.configuration
    tcp = c.firewall_rules[1]
    udp = tcp.model_copy(update={'name': 'udp_allow', 'protocol': 'udp', 'dst': '@hosts'})
    v6 = tcp.model_copy(update={'name': 'v6_only', 'src': '2001:db8::/64'})
    router = tcp.model_copy(update={'name': 'router_only', 'dst': 'zone:router'})
    base = base.model_copy(update={'configuration': c.model_copy(update={
        'firewall_rules': (*c.firewall_rules, udp, v6, router)})})
    output = generate_tproxy_preauthorization(enabled(base))
    assert '192.168.10.10-192.168.10.20' in output
    assert 'ip saddr @a_clients_4' in output
    assert 'ip daddr @a_hosts_4' in output
    assert 'tcp dport { 443, 8000-8080 }' in output
    assert 'udp dport { 53 }' in output
    assert 'tcp dport { 53 }' not in output
    assert 'comment "v6_only"' not in output
    assert 'comment "router_only"' not in output


@pytest.mark.parametrize('ingress', [(), ('missing',), ('eth0',), ('eth2',), ('eth1', 'eth1')])
def test_invalid_ingress(ingress):
    with pytest.raises(ValueError):
        generate_tproxy_preauthorization(enabled(ingress=ingress))


def test_off_only_destroys_own_table_and_public_enable_is_forbidden():
    assert generate_tproxy_preauthorization(scenario('typical')) == 'destroy table inet vs_router_tproxy_preauth\n'
    with pytest.raises(ValueError, match='tproxy.not_available'):
        ConfigurationVersion.model_validate(enabled().model_dump())


@pytest.mark.parametrize('name', ['empty', 'typical', 'edge'])
def test_live_firewall_golden_stability_and_purity(name):
    base = scenario(name)
    assert generate_nftables(base) == (Path(__file__).parent / 'golden' / f'{name}.nft').read_text()
    if name != 'empty':
        version = enabled(base)
        before = version.model_dump_json()
        output = generate_tproxy_preauthorization(version)
        assert generate_tproxy_preauthorization(version) == output
        assert version.model_dump_json() == before
        assert generate_nftables(version) == generate_nftables(base)


@pytest.mark.parametrize('update', [
    {'dst': 'zone:missing'}, {'src': '@missing'}, {'protocol': 'sctp'},
    {'action': 'unknown'}, {'protocol': 'any', 'destination_ports': '443'},
])
def test_unvalidated_unknown_rule_semantics_fail_closed(update):
    base = scenario('typical')
    c = base.configuration
    rule = c.firewall_rules[0].model_copy(update=update)
    base = base.model_copy(update={'configuration': c.model_copy(update={'firewall_rules': (rule,)})})
    with pytest.raises(ValueError):
        generate_tproxy_preauthorization(enabled(base))


def test_port_alias_without_matching_protocol_cannot_grant_pass():
    data = scenario('edge').model_dump()
    data['configuration']['aliases'][0]['elements'] = ['udp/53']
    output = generate_tproxy_preauthorization(enabled(ConfigurationVersion.model_validate(data)))
    assert 'comment "web_allow"' not in output
    assert 'comment "blocked"' in output
    assert 'comment "reject_rest"' in output
