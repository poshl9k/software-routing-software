"""A tunnel exit must actually send traffic into its tunnel.

The exit is a sing-box outbound bound to the tunnel's own address, so the kernel
has to route that source into the tunnel. The main table cannot hold a second
default (it would compete with the WAN for the whole host), so each tunnel exit
gets a table selected by the tunnel address — the same shape an interface exit
uses for its WAN source.

Without it the engine logged `dial tcp 10.66.66.10:0->1.1.1.1:443: i/o timeout`
and a segment configured for the tunnel quietly used whatever the main table said.
"""
from __future__ import annotations

from types import SimpleNamespace

from vs_router.agent import tunnel_policy
from vs_router.generators import marks
from vs_router.schema import Configuration


class Executor:
    def __init__(self, rules=''):
        self.calls = []
        self.rules = rules

    def run(self, argv, timeout=None):
        self.calls.append(list(argv))
        if argv[:4] == ['ip', '-4', 'rule', 'show']:
            return SimpleNamespace(returncode=0, stdout=self.rules, stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')


class FS:
    def __init__(self, content=None):
        self.content = content
        self.written = {}

    def read(self, path):
        if self.content is None:
            raise FileNotFoundError(path)
        return self.content

    def write(self, path, content):
        self.written[str(path)] = content


def configuration(**overrides):
    body = {
        'interfaces': [
            {'name': 'ens224', 'zone': 'wan', 'addresses': ['192.0.2.10/24']},
            {'name': 'awg0', 'type': 'physical', 'addresses': ['10.66.66.10/32']},
            {'name': 'vlan10', 'type': 'vlan', 'parent': 'ens224', 'vlan_id': 10,
             'zone': 'lan', 'addresses': ['10.10.10.1/24']},
        ],
        'tunnels': [
            {'name': 'rg3', 'interface': 'awg0', 'role': 'client', 'protocol': 'awg',
             'private_key': {'encrypted': True, 'ciphertext': 'gAAAA' + 'A' * 20},
             'endpoint': '203.0.113.1:51820', 'server_public_key': 'pk',
             'allowed_ips': ['0.0.0.0/0'], 'default_route': False,
             'header_protection_key': {'encrypted': True, 'ciphertext': 'gAAAA' + 'B' * 20},
             'random_trailers': True, 'disable_cookies': True,
             'obfuscation': {'Jc': 10, 'Jmin': 30, 'Jmax': 89,
                             'S1': 28, 'S2': 28, 'S3': 28, 'S4': 28,
                             'H1': 1054942449, 'H2': 586746522, 'H3': 770735274,
                             'H4': 276117209, 'I1': '<b 0x9c0b645045a3>',
                             'I2': '<rd 8>', 'I3': '<r 6>', 'I4': '<b 0x3f>', 'I5': '<rc 6>',
                             'RekeyAfterTime': '111-142', 'RekeyTimeout': '5-9',
                             'RejectAfterTime': '189-222', 'KeepaliveTimeout': '5-16',
                             'MaxHandshakeAttempts': '16-25'}},
        ],
        'routing_rules': [
            {'name': 'seg_tunnel',
             'subject': {'kind': 'interface', 'interface': 'vlan10'},
             'ip_cidr': ['1.1.1.1/32'],
             'exit': {'kind': 'tunnel', 'name': 'rg3', 'source': '10.66.66.10'}},
            {'name': 'seg_direct',
             'subject': {'kind': 'interface', 'interface': 'vlan10'},
             'ip_cidr': ['0.0.0.0/0'],
             'exit': {'kind': 'direct'}},
        ],
    }
    body.update(overrides)
    return Configuration.model_validate(body)


def test_a_tunnel_exit_gets_its_own_table_and_selector():
    entries = tunnel_policy.plan(configuration())
    assert entries == [{'source': '10.66.66.10', 'interface': 'awg0',
                        'table': marks.TUNNEL_POLICY_TABLE_BASE,
                        'priority': tunnel_policy.RULE_PRIORITY_BASE}]


def test_the_tunnel_table_does_not_collide_with_interface_exits():
    assert marks.TUNNEL_POLICY_TABLE_BASE > marks.POLICY_TABLE_BASE
    assert marks.TUNNEL_POLICY_TABLE_BASE >= marks.POLICY_TABLE_BASE + 100 or \
        marks.POLICY_TABLE_BASE + marks.POLICY_TABLE_LIMIT <= marks.TUNNEL_POLICY_TABLE_BASE


def test_a_configuration_without_a_tunnel_exit_needs_no_table():
    """A direct-only policy must not leave a table selector behind."""
    base = configuration()
    direct = base.routing_rules[1].model_dump(mode='json')
    assert tunnel_policy.plan(configuration(routing_rules=[direct])) == []


def test_sync_installs_the_route_and_the_rule_once():
    executor, filesystem = Executor(), FS()
    entries = tunnel_policy.plan(configuration())
    tunnel_policy.sync(executor, filesystem, entries)
    assert ['ip', '-4', 'route', 'replace', 'default', 'dev', 'awg0',
            'table', str(marks.TUNNEL_POLICY_TABLE_BASE)] in executor.calls
    assert any(call[:4] == ['ip', '-4', 'rule', 'add'] for call in executor.calls)

    # Second run with the rule already live: no duplicate rule is added.
    live = (f'33000:\tfrom 10.66.66.10 lookup {marks.TUNNEL_POLICY_TABLE_BASE}\n')
    executor2 = Executor(rules=live)
    tunnel_policy.sync(executor2, FS(filesystem.written[tunnel_policy.STATE_PATH]), entries)
    assert not any(call[:4] == ['ip', '-4', 'rule', 'add'] for call in executor2.calls)


def test_a_configuration_without_tunnels_retires_previous_tables():
    executor = Executor()
    previous = '[{"source": "10.66.66.10", "interface": "awg0", ' \
               f'"table": {marks.TUNNEL_POLICY_TABLE_BASE}, "priority": 33000}}]'
    changes = tunnel_policy.teardown(executor, FS(previous))
    assert any('removed' in change for change in changes)
    assert ['ip', '-4', 'rule', 'del', 'from', '10.66.66.10', 'lookup',
            str(marks.TUNNEL_POLICY_TABLE_BASE), 'priority', '33000'] in executor.calls
    assert ['ip', '-4', 'route', 'flush', 'table', str(marks.TUNNEL_POLICY_TABLE_BASE)] in executor.calls
