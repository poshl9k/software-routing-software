import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vs_router.agent.apply import ApplyEngine, APPLIED_DIR, ApplyError
from vs_router.agent.services import NetworkdReloader
from vs_router.api import configuration as api_configuration
from vs_router.generators import generate_networkd, serialize_networkd
from vs_router.generators.networkd import deserialize_networkd
from vs_router.schema import ConfigurationVersion
from test_agent_apply import FakeFS, FakeExecutor


def scenario(name):
    interfaces = {
        'empty': [],
        'typical': [
            {'name': 'eth0', 'zone': 'wan', 'addressing': 'dhcp'},
            {'name': 'eth1', 'zone': 'lan'},
            {'name': 'eth2', 'zone': 'lan'},
            {'name': 'br0', 'type': 'bridge', 'zone': 'lan',
             'members': ['eth2', 'eth1'], 'addresses': ['192.168.10.1/24']},
            {'name': 'br0.20', 'type': 'vlan', 'parent': 'br0', 'vlan_id': 20,
             'zone': 'guest', 'addresses': ['192.168.20.1/24']},
            {'name': 'eth3', 'zone': 'lan', 'addresses': ['192.168.30.1/24']},
            {'name': 'eth3.40', 'type': 'vlan', 'parent': 'eth3', 'vlan_id': 40,
             'zone': 'iot', 'addresses': ['192.168.40.1/24']},
        ],
        'edge': [
            {'name': 'eth0', 'zone': 'wan', 'addresses': [
                '203.0.113.2/24', '203.0.113.3/24', '203.0.113.4/32', '2001:db8::2/64']},
            {'name': 'eth1', 'addresses': ['192.168.1.1/24']},
            {'name': 'br0', 'type': 'bridge', 'zone': 'lan', 'members': ['eth1']},
            {'name': 'eth0.10', 'type': 'vlan', 'parent': 'eth0', 'vlan_id': 10},
        ],
    }[name]
    return ConfigurationVersion(configuration={'interfaces': interfaces})


@pytest.mark.parametrize('name', ['empty', 'typical', 'edge'])
def test_networkd_golden(name):
    version = scenario(name)
    before = version.model_dump_json()
    files = generate_networkd(version)
    result = serialize_networkd(files)
    assert result == (Path(__file__).parent / 'golden' / f'{name}.networkd').read_text()
    assert generate_networkd(version) == files
    assert version.model_dump_json() == before
    assert deserialize_networkd(result) == files
    reversed_version = version.model_copy(update={
        'configuration': version.configuration.model_copy(update={
            'interfaces': tuple(reversed(version.configuration.interfaces))})})
    assert serialize_networkd(generate_networkd(reversed_version)) == result


def test_vlan_attachment_and_bridge_addresses():
    files = generate_networkd(scenario('typical'))
    assert 'VLAN=br0.20' in files['10-vs-router-br0.network']
    assert 'VLAN=eth3.40' in files['10-vs-router-eth3.network']
    for name in ('eth1', 'eth2'):
        assert 'Bridge=br0' in files[f'10-vs-router-{name}.network']
        assert 'VLAN=' not in files[f'10-vs-router-{name}.network']
        assert 'Address=' not in files[f'10-vs-router-{name}.network']
    assert 'Address=192.168.10.1/24' in files['10-vs-router-br0.network']
    assert '[VLAN]\nId=20' in files['10-vs-router-br0.20.netdev']


@pytest.mark.parametrize('addressing,zone,iface_type,addresses,dhcp', [
    ('dhcp', 'wan', 'physical', [], True),
    ('dhcp', 'lan', 'vlan', [], True),
    ('dhcp', 'wan', 'bridge', [], True),
    ('static', 'wan', 'physical', [], False),
    ('static', 'wan', 'physical', ['203.0.113.2/24'], False),
    ('static', 'lan', 'physical', ['192.168.10.1/24'], False),
])
def test_dhcp_is_explicit(addressing, zone, iface_type, addresses, dhcp):
    """DHCP is driven by the addressing field, not by zone/type heuristics."""
    iface = {'name': 'eth0', 'zone': zone, 'addressing': addressing,
             'type': iface_type, 'addresses': addresses}
    if iface_type == 'vlan':
        iface.update(parent='eth9', vlan_id=10)
    version = ConfigurationVersion(configuration={
        'interfaces': ([{'name': 'eth9', 'zone': 'wan'}] if iface_type == 'vlan' else [])
        + [iface]})
    output = generate_networkd(version)['10-vs-router-eth0.network']
    assert ('DHCP=ipv4' in output) == dhcp
    if dhcp:
        assert 'UseRoutes=yes' in output and 'UseGateway=yes' in output
        assert 'UseDNS=no' in output


@pytest.mark.parametrize('bundle', [
    'garbage', '### FILE: ../../evil.network\n[Network]\n',
    '### FILE: other.network\n',
    '### FILE: 10-vs-router-eth0.network\n### FILE: 10-vs-router-eth0.network\n'])
def test_invalid_bundles(bundle):
    with pytest.raises(ValueError, match='invalid_bundle'):
        deserialize_networkd(bundle)


def test_validation_reports_networkd_failure(monkeypatch):
    def fail(version):
        raise ValueError('invalid topology')
    monkeypatch.setattr(api_configuration, 'generate_networkd', fail)
    result = api_configuration.validate({})
    assert not result['valid']
    assert result['errors'][0]['details'] == [{'generator': 'networkd'}]


def test_install_cleanup_and_rollback():
    fs, executor = FakeFS(), FakeExecutor()
    adapter = NetworkdReloader(executor, fs)
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         reload_commands={'networkd': adapter})
    foreign = Path('/etc/systemd/network/99-local.network')
    fs.write(foreign, 'untouched')
    assert engine.apply_version(scenario('typical').model_dump()).status == 'confirmed'
    original = generate_networkd(scenario('typical'))
    assert fs.read(APPLIED_DIR / 'networkd.conf') == serialize_networkd(original)
    assert engine.apply_version(scenario('empty').model_dump(), True).status == 'pending'
    assert all(adapter.network_dir / name not in fs.files for name in original)
    assert engine.rollback('timeout').status == 'rolled_back'
    assert all(fs.read(adapter.network_dir / name) == content for name, content in original.items())
    assert fs.read(foreign) == 'untouched'
    assert sum(argv == ['networkctl', 'reload'] for argv, _ in executor.calls) == 3


def test_reload_failure_restores_files():
    fs, executor = FakeFS(), FakeExecutor()
    adapter = NetworkdReloader(executor, fs)
    engine = ApplyEngine(filesystem=fs, executor=executor,
                         reload_commands={'networkd': adapter})
    engine.apply_version(scenario('empty').model_dump())
    run = executor.run
    failed = []
    def fail_once(argv, timeout):
        if argv == ['networkctl', 'reload'] and not failed:
            failed.append(True)
            return SimpleNamespace(returncode=1)
        return run(argv, timeout)
    executor.run = fail_once
    assert engine.apply_version(scenario('typical').model_dump(), True).status == 'rolled_back'
    assert not any(path.parent == adapter.network_dir for path in fs.files)
    assert fs.read(adapter.manifest_path) == ''


def test_reloader_waits_for_new_virtual_links_before_returning():
    fs, executor = FakeFS(), FakeExecutor()
    path = APPLIED_DIR / 'networkd.conf'
    fs.write(path, serialize_networkd({
        '10-vs-router-eth0.network': '[Match]\nName=eth0\n\n[Network]\nVLAN=vlan1\n',
        '10-vs-router-vlan1.netdev': '[NetDev]\nName=vlan1\nKind=vlan\n\n[VLAN]\nId=1\n',
        '10-vs-router-vlan1.network': '[Match]\nName=vlan1\n\n[Network]\nAddress=10.0.0.1/24\n',
    }))
    probes = iter((1, 1, 0))
    sleeps = []

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv == ['ip', 'link', 'show', 'dev', 'vlan1']:
            return SimpleNamespace(returncode=next(probes))
        return SimpleNamespace(returncode=0)

    executor.run = run
    NetworkdReloader(executor, fs, attempts=3, sleep=sleeps.append)(path)

    assert sleeps == [0.1, 0.1]
    assert [argv for argv, _ in executor.calls].count(
        ['ip', 'link', 'show', 'dev', 'vlan1']) == 3


def _vlan_bundle(vlan_id=201, parent='eth0'):
    return serialize_networkd({
        '10-vs-router-eth0.network': f'[Match]\nName={parent}\n\n[Network]\nVLAN=vlan1\n',
        '10-vs-router-vlan1.netdev': f'[NetDev]\nName=vlan1\nKind=vlan\n\n[VLAN]\nId={vlan_id}\n',
        '10-vs-router-vlan1.network': '[Match]\nName=vlan1\n\n[Network]\nAddress=172.20.1.1/24\n',
    })


def _vlan_link(vlan_id, parent='eth0'):
    return json.dumps([{'ifname': 'vlan1', 'link': parent,
                        'linkinfo': {'info_kind': 'vlan',
                                     'info_data': {'id': vlan_id}}}])


def test_reloader_replaces_stale_vlan_with_wrong_id():
    """A netdev left from an earlier config must not survive under the same name."""
    fs, executor = FakeFS(), FakeExecutor()
    path = APPLIED_DIR / 'networkd.conf'
    fs.write(path, _vlan_bundle())
    states = iter((_vlan_link(1), _vlan_link(201)))

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv == ['ip', '-j', '-d', 'link', 'show', 'dev', 'vlan1']:
            return SimpleNamespace(returncode=0, stdout=next(states, _vlan_link(201)))
        return SimpleNamespace(returncode=0, stdout='')

    executor.run = run
    NetworkdReloader(executor, fs)(path)

    assert ['ip', 'link', 'del', 'vlan1'] in [argv for argv, _ in executor.calls]


def _link_probe(executor, name, states):
    values = iter(states)

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv == ['ip', '-j', '-d', 'link', 'show', 'dev', name]:
            return SimpleNamespace(returncode=0, stdout=next(values))
        return SimpleNamespace(returncode=0, stdout='')

    executor.run = run


def test_reloader_keeps_vlan_that_matches():
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', _vlan_bundle())
    _link_probe(executor, 'vlan1', [_vlan_link(201), _vlan_link(201)])

    NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')

    assert not any(argv[:3] == ['ip', 'link', 'del'] for argv, _ in executor.calls)


def test_reloader_replaces_vlan_on_wrong_parent():
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', _vlan_bundle())
    _link_probe(executor, 'vlan1', [_vlan_link(201, 'eth9'), _vlan_link(201)])

    NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')

    assert ['ip', 'link', 'del', 'vlan1'] in [argv for argv, _ in executor.calls]


def test_reloader_accepts_repeated_address_lines_on_vlan_parent():
    """Multiple WAN addresses are legal in .network; configparser must not choke."""
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', serialize_networkd({
        '10-vs-router-eth0.network': (
            '[Match]\nName=eth0\n\n[Network]\n'
            'Address=192.168.107.2/24\nAddress=192.168.116.253/32\nVLAN=vlan1\n'),
        '10-vs-router-vlan1.netdev': (
            '[NetDev]\nName=vlan1\nKind=vlan\n\n[VLAN]\nId=201\n'),
        '10-vs-router-vlan1.network': (
            '[Match]\nName=vlan1\n\n[Network]\nAddress=172.20.1.1/24\n'),
    }))
    _link_probe(executor, 'vlan1', [_vlan_link(201), _vlan_link(201)])

    NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')

    assert not any(argv[:3] == ['ip', 'link', 'del'] for argv, _ in executor.calls)


def test_reloader_replaces_netdev_of_foreign_kind():
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', serialize_networkd({
        '10-vs-router-br0.netdev': '[NetDev]\nName=br0\nKind=bridge\n',
        '10-vs-router-br0.network': '[Match]\nName=br0\n\n[Network]\nAddress=10.0.0.1/24\n',
    }))
    foreign = json.dumps([{'ifname': 'br0',
                           'linkinfo': {'info_kind': 'vlan', 'info_data': {'id': 1}}}])
    recreated = json.dumps([{'ifname': 'br0', 'linkinfo': {'info_kind': 'bridge'}}])
    _link_probe(executor, 'br0', [foreign, recreated])

    NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')

    assert ['ip', 'link', 'del', 'br0'] in [argv for argv, _ in executor.calls]


def test_reloader_fails_if_stale_netdev_survives():
    """Do not confirm an apply that left the wrong VID on the wire."""
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', _vlan_bundle())
    _link_probe(executor, 'vlan1', [_vlan_link(1), _vlan_link(1)])

    with pytest.raises(ApplyError, match='agent.reload_failed'):
        NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')


def test_interface_description_is_metadata_not_configuration():
    """description is operator-facing only: it round-trips but never reaches
    generated networkd/nftables output, and it is length-limited."""
    from vs_router.generators.nftables import generate_nftables
    version = ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth1', 'zone': 'lan', 'addresses': ['192.168.10.1/24'],
         'description': 'оптика провайдера'}]})
    assert version.configuration.interfaces[0].description == 'оптика провайдера'
    assert 'оптика' not in serialize_networkd(generate_networkd(version))
    assert 'оптика' not in generate_nftables(version)
    with pytest.raises(ValueError):
        ConfigurationVersion(configuration={'interfaces': [
            {'name': 'eth1', 'zone': 'lan', 'description': 'x' * 65}]})


def test_reloader_rejects_unsafe_bundle_before_writes():
    fs, executor = FakeFS(), FakeExecutor()
    path = APPLIED_DIR / 'networkd.conf'
    fs.write(path, '### FILE: ../../evil.network\n')
    with pytest.raises(ApplyError):
        NetworkdReloader(executor, fs)(path)
    assert list(fs.files) == [path]
    assert executor.calls == []


def test_ipvlan_l2_generation_attaches_to_the_parent():
    files = generate_networkd(ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth0', 'zone': 'wan', 'addresses': []},
        {'name': 'vip0', 'type': 'virtualip', 'parent': 'eth0', 'zone': 'wan',
         'addresses': ['192.0.2.2/24', '192.0.2.3/32']},
    ]}))
    netdev = files['10-vs-router-vip0.netdev']
    assert '[NetDev]\nName=vip0\nKind=ipvlan\n' in netdev
    assert '[IPVLAN]\nMode=L2\n' in netdev
    parent = files['10-vs-router-eth0.network']
    assert 'IPvLAN=vip0' in parent
    child = files['10-vs-router-vip0.network']
    assert 'Address=192.0.2.2/24' in child
    assert 'Address=192.0.2.3/32' in child


def test_reloader_finds_ipvlan_parent_in_a_bundle(monkeypatch):
    monkeypatch.setattr('vs_router.agent.services.host_supports_ipvlan', lambda: True)
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', serialize_networkd({
        '10-vs-router-eth0.network': '[Match]\nName=eth0\n\n[Network]\nIPvLAN=vip0\n',
        '10-vs-router-vip0.netdev': '[NetDev]\nName=vip0\nKind=ipvlan\n\n[IPVLAN]\nMode=L2\n',
        '10-vs-router-vip0.network': '[Match]\nName=vip0\n\n[Network]\nAddress=192.0.2.2/24\n',
    }))
    values = iter((json.dumps([{'ifname': 'vip0', 'link': 'eth0',
                                'linkinfo': {'info_kind': 'ipvlan'}}]),
                   json.dumps([{'ifname': 'vip0', 'link': 'eth0',
                                'linkinfo': {'info_kind': 'ipvlan'}}])))
    executor.run = lambda argv, timeout: SimpleNamespace(
        returncode=0, stdout=next(values) if argv == ['ip', '-j', '-d', 'link', 'show', 'dev', 'vip0'] else '')

    NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')

    assert not any(argv[:3] == ['ip', 'link', 'del'] for argv, _ in executor.calls)


def test_macvlan_bridge_generation_attaches_to_the_parent():
    files = generate_networkd(ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth0', 'zone': 'wan', 'addresses': []},
        {'name': 'vip0', 'type': 'virtualmac', 'parent': 'eth0', 'zone': 'wan',
         'addresses': ['192.0.2.2/24']},
    ]}))
    netdev = files['10-vs-router-vip0.netdev']
    assert 'Kind=macvlan' in netdev
    assert '[MACVLAN]\nMode=bridge' in netdev
    assert 'MACVLAN=vip0' in files['10-vs-router-eth0.network']


def test_reloader_refuses_ipvlan_on_a_host_without_support(monkeypatch):
    monkeypatch.setattr('vs_router.agent.services.host_supports_ipvlan', lambda: False)
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(APPLIED_DIR / 'networkd.conf', serialize_networkd({
        '10-vs-router-eth0.network': '[Match]\nName=eth0\n\n[Network]\nIPvLAN=vip0\n',
        '10-vs-router-vip0.netdev': '[NetDev]\nName=vip0\nKind=ipvlan\n\n[IPVLAN]\nMode=L2\n',
        '10-vs-router-vip0.network': '[Match]\nName=vip0\n\n[Network]\nAddress=192.0.2.2/24\n',
    }))
    with pytest.raises(ApplyError, match='agent.ipvlan_unsupported'):
        NetworkdReloader(executor, fs)(APPLIED_DIR / 'networkd.conf')
