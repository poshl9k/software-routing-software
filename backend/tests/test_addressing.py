"""Explicit addressing: DHCP is a per-interface mode, not a zone/type heuristic."""
import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from vs_router.api import configuration as api_configuration
from vs_router.generators.nftables import generate_nftables
from vs_router.schema import ConfigurationVersion

ROOT = Path(__file__).resolve().parents[1]


def codes(value):
    """All guard codes surfaced by the offline validator, including details."""
    result = api_configuration.validate(value)
    out = []
    for error in result['errors']:
        out.append(error['message'])
        out.extend(detail.get('message', '') for detail in error.get('details', []))
    return result, out


@pytest.mark.parametrize('interfaces,code', [
    ([{'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp', 'addresses': ['203.0.113.2/24']}],
     'interface.dhcp_with_addresses'),
    ([{'name': 'eth0', 'addressing': 'dhcp'}], 'interface.dhcp_unassigned'),
    ([{'name': 'br0', 'type': 'bridge', 'zone': 'lan', 'members': ['eth0']},
      {'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp'}], 'interface.dhcp_on_member'),
    ([{'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp'},
      {'name': 'eth0.10', 'type': 'vlan', 'parent': 'eth0', 'vlan_id': 10, 'zone': 'lan'}],
     'interface.dhcp_on_trunk'),
])
def test_dhcp_structural_guards(interfaces, code):
    result, found = codes({'interfaces': interfaces})
    assert result['valid'] is False
    assert code in found


def test_kea_server_interface_cannot_be_a_dhcp_client():
    result, found = codes({
        'interfaces': [{'name': 'eth1', 'zone': 'lan', 'addressing': 'dhcp'}],
        'dhcp_subnets': [{'id': 1, 'interface': 'eth1', 'subnet': '192.168.10.0/24'}],
    })
    assert result['valid'] is False
    assert 'dhcp.client_conflict' in found


def test_dhcp_on_a_vlan_wan_is_valid():
    """The multi-provider case: WAN delivered on a VLAN with DHCP (parent is a
    trunk, so it must NOT be a DHCP client itself)."""
    result = api_configuration.validate({'interfaces': [
        {'name': 'eth0', 'zone': 'wan'},
        {'name': 'eth0.20', 'type': 'vlan', 'parent': 'eth0', 'vlan_id': 20,
         'zone': 'wan', 'addressing': 'dhcp'},
        {'name': 'eth1', 'zone': 'lan', 'addresses': ['192.168.10.1/24']},
    ]})
    assert result['valid'] is True, result['errors']


def test_firewall_allows_dhcp_replies_on_client_interfaces():
    version = ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth0', 'zone': 'wan'},
        {'name': 'eth0.20', 'type': 'vlan', 'parent': 'eth0', 'vlan_id': 20,
         'zone': 'wan', 'addressing': 'dhcp'},
        {'name': 'eth1', 'zone': 'lan', 'addresses': ['192.168.10.1/24']},
    ]})
    table = generate_nftables(version)
    rule = 'udp sport 67 udp dport 68 counter accept comment "dhcp_client"'
    assert rule in table
    # DHCP replies must be accepted before conntrack can drop them as invalid.
    assert table.index(rule) < table.index('ct state invalid drop')
    assert 'iifname { "eth0.20" }' in table


def test_firewall_has_no_dhcp_rule_without_a_client():
    version = ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth0', 'zone': 'wan', 'addresses': ['203.0.113.2/24']}]})
    assert 'dhcp_client' not in generate_nftables(version)


@pytest.mark.parametrize('previous,code', [
    ({'interfaces': [{'name': 'eth0', 'type': 'physical', 'zone': 'wan', 'addresses': []}]},
     'management.dhcp_forbidden'),
])
def test_management_forbids_dhcp_on_the_pinned_lan(previous, code):
    from test_agent_apply import FakeFS, FakeExecutor
    from test_management import STATE
    from vs_router.agent.apply import ApplyEngine, ApplyError
    fs = FakeFS()
    engine = ApplyEngine(filesystem=fs, executor=FakeExecutor(),
                         management_provider=lambda: STATE)
    config = {'interfaces': [
        {'name': 'eth0', 'zone': 'wan'},
        {'name': 'eth1', 'zone': 'lan', 'addressing': 'dhcp'}]}
    with pytest.raises(ApplyError, match=code):
        engine.apply_version({'id': 1, 'status': 'draft', 'configuration': config})
    assert not fs.files


def test_migration_marks_legacy_addressless_wan_as_dhcp(tmp_path):
    url = f"sqlite:///{tmp_path / 'legacy.db'}"
    config = Config(str(ROOT / 'alembic.ini'))
    config.set_main_option('sqlalchemy.url', url)
    command.upgrade(config, '0002')
    engine = sa.create_engine(url)
    legacy = {'schema_version': 1, 'interfaces': [
        {'name': 'eth0', 'type': 'physical', 'zone': 'wan', 'addresses': []},
        {'name': 'eth1', 'type': 'physical', 'zone': 'lan', 'addresses': ['192.168.10.1/24']}]}
    with engine.begin() as conn:
        conn.execute(sa.text("insert into configuration_versions "
                             "(id, status, configuration, created_at) "
                             "values (1, 'draft', :c, '2026-01-01 00:00:00')"),
                     {'c': json.dumps(legacy)})
    command.upgrade(config, '0003')
    with engine.connect() as conn:
        stored = conn.execute(sa.text(
            "select configuration from configuration_versions where id = 1")).scalar()
    interfaces = {i['name']: i for i in json.loads(stored)['interfaces']}
    assert interfaces['eth0'].get('addressing') == 'dhcp'
    # An interface with a static address is untouched.
    assert 'addressing' not in interfaces['eth1']
