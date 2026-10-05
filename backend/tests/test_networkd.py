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
            {'name': 'eth0', 'zone': 'wan'},
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


@pytest.mark.parametrize('zone,addresses,dhcp', [
    ('wan', [], True), ('wan', ['203.0.113.2/24'], False),
    ('lan', [], False), (None, [], False)])
def test_dhcp_convention(zone, addresses, dhcp):
    version = ConfigurationVersion(configuration={'interfaces': [
        {'name': 'eth0', 'zone': zone, 'addresses': addresses}]})
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


def test_reloader_rejects_unsafe_bundle_before_writes():
    fs, executor = FakeFS(), FakeExecutor()
    path = APPLIED_DIR / 'networkd.conf'
    fs.write(path, '### FILE: ../../evil.network\n')
    with pytest.raises(ApplyError):
        NetworkdReloader(executor, fs)(path)
    assert list(fs.files) == [path]
    assert executor.calls == []
