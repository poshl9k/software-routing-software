"""Who owns a link, and what the panel must therefore leave alone (ADR-0027).

The panel writes no networkd configuration for the host's own uplink — but only
when something else already configures that link, because writing nothing for a
link whose only configuration is ours loses its address. These tests pin both
halves, and they read no filesystem: the ownership decision is pure, and the
reader is exercised against temporary directories.
"""
from types import SimpleNamespace

from vs_router.agent.network_ownership import foreign_owner, host_config_candidates
from vs_router.management import unmanaged_host_interfaces
from vs_router.generators import generate_networkd
from vs_router.schema import ConfigurationVersion


def test_our_own_file_is_never_an_owner():
    """Otherwise the panel could never stop managing a link it already manages."""
    candidates = [('/etc/systemd/network/10-vs-router-eth0.network',
                   '[Match]\nName=eth0\n')]
    assert foreign_owner('eth0', candidates) is False


def test_a_netplan_source_that_names_the_link_owns_it():
    candidates = [('/etc/netplan/50-cloud-init.yaml',
                   'network:\n  ethernets:\n    eth0:\n      dhcp4: true\n')]
    assert foreign_owner('eth0', candidates) is True
    # A name that merely contains the interface name is not a match.
    assert foreign_owner('eth0', [('/etc/netplan/x.yaml', 'eth01:\n  dhcp4: true\n')]) is False


def test_a_foreign_network_file_that_matches_by_name_owns_the_link():
    candidates = [('/run/systemd/network/10-netplan-eth0.network',
                   '[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n')]
    assert foreign_owner('eth0', candidates) is True


def test_a_wildcard_match_counts_because_it_would_take_the_link_over():
    candidates = [('/etc/systemd/network/20-all.network',
                   '[Match]\nName=en*\n\n[Network]\nDHCP=yes\n')]
    assert foreign_owner('enp1s0', candidates) is True


def test_a_file_that_matches_something_else_is_not_an_owner():
    candidates = [('/etc/systemd/network/30-lab.network',
                   '[Match]\nName=lab0\n\n[Network]\nDHCP=no\n')]
    assert foreign_owner('eth0', candidates) is False


def test_the_reader_returns_only_config_files(tmp_path):
    netplan = tmp_path / 'netplan'
    network = tmp_path / 'network'
    netplan.mkdir(), network.mkdir()
    (netplan / '50-cloud-init.yaml').write_text('ethernets:\n  eth0:\n')
    (netplan / 'README').write_text('not a config\n')
    (network / '10-netplan-eth0.network').write_text('[Match]\nName=eth0\n')
    (network / 'subdir').mkdir()
    found = dict(host_config_candidates(netplan, (network,)))
    assert set(found) == {str(netplan / '50-cloud-init.yaml'),
                          str(network / '10-netplan-eth0.network')}
    assert foreign_owner('eth0', found.items()) is True


def test_a_missing_directory_is_not_a_reason_to_claim_ownership(tmp_path):
    assert list(host_config_candidates(tmp_path / 'absent', (tmp_path / 'also-absent',))) == []


RECORD = SimpleNamespace(interface='eth0')


def test_only_a_panel_leaves_the_uplink_alone():
    owner = lambda interface: True
    assert unmanaged_host_interfaces('router', RECORD, foreign_owner=owner) == frozenset()
    assert unmanaged_host_interfaces('panel', RECORD, foreign_owner=owner) == frozenset({'eth0'})


def test_the_panel_keeps_managing_a_link_nobody_else_configures():
    """The safety half: excluding such a link loses the host's address."""
    nothing = lambda interface: False
    assert unmanaged_host_interfaces('panel', RECORD, foreign_owner=nothing) == frozenset()


def test_a_host_without_a_record_has_no_uplink_to_exclude():
    assert unmanaged_host_interfaces('panel', None, foreign_owner=lambda i: True) == frozenset()
    assert unmanaged_host_interfaces('panel', SimpleNamespace(interface=None),
                                     foreign_owner=lambda i: True) == frozenset()


def test_the_generator_drops_an_excluded_interface_and_its_netdev():
    version = ConfigurationVersion.model_validate({'configuration': {
        'interfaces': [
            {'name': 'eth0', 'type': 'physical', 'zone': 'wan', 'addressing': 'dhcp'},
            {'name': 'tun1', 'type': 'physical', 'zone': 'lan', 'addressing': 'static',
             'addresses': ['10.66.66.1/24']},
            {'name': 'br0', 'type': 'bridge', 'zone': 'lan', 'addressing': 'static',
             'addresses': ['192.168.10.1/24'], 'members': []},
        ],
    }})
    files = generate_networkd(version, exclude={'eth0'})
    assert '10-vs-router-eth0.network' not in files
    assert '10-vs-router-tun1.network' in files
    assert '10-vs-router-br0.network' in files and '10-vs-router-br0.netdev' in files
    # Without the exclusion nothing is dropped: the default is the router's.
    assert '10-vs-router-eth0.network' in generate_networkd(version)
