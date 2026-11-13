"""The management path must survive every apply.

The panel rewrites nftables and networkd as a whole, so a document that is wrong
about its own management interface — or an apply that dies half way and restores
an older ruleset — can leave the host with no address, no SSH and no ICMP. The
lab stand hit exactly that three times and each time needed hands on the ESXi
console.

Two defences are covered here: the guard service that re-asserts the host-owned
management record every 30 seconds, and the apply-time invariant that refuses to
call a configuration confirmed when its own management address is gone.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from vs_router.agent.apply import ApplyEngine, ApplyError

PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'


def _guard():
    spec = importlib.util.spec_from_file_location(
        'vs_router_access_guard', PACKAGING / 'vs-router-access-guard.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _guard()


def test_the_guard_ships_with_the_installer():
    for name in ('vs-router-access-guard.py', 'vs-router-access-guard.service',
                 'vs-router-access-guard.timer'):
        assert (PACKAGING / name).is_file(), name
    install = (PACKAGING / 'install.sh').read_text(encoding='utf-8')
    assert 'vs-router-access-guard.py' in install
    assert 'systemctl enable vs-router-access-guard.timer' in install
    # A structural unit that only reconfigures one pinned link.
    unit = (PACKAGING / 'vs-router-access-guard.service').read_text(encoding='utf-8')
    assert 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW' in unit
    assert 'NoNewPrivileges=yes' in unit
    timer = (PACKAGING / 'vs-router-access-guard.timer').read_text(encoding='utf-8')
    assert 'OnUnitActiveSec=30s' in timer


def test_the_address_check_compares_hosts_not_prefix_lengths():
    assert guard.address_missing('inet 192.168.22.64/16 brd x', '192.168.22.64/24') is False
    assert guard.address_missing('inet 192.168.22.65/16 brd x', '192.168.22.64/16') is True
    assert guard.address_missing('', '192.168.22.64/16') is True


def test_missing_rules_are_only_the_absent_ones():
    empty = guard.missing_rules('', 'ens192')
    assert len(empty) == 2
    assert any('tcp dport 22' in rule for rule in empty)
    assert any('icmp type echo-request' in rule for rule in empty)
    assert all(guard.COMMENT in rule for rule in empty)

    present = (
        'iifname "ens192" tcp dport 22 counter accept comment "vs-router_access_guard"\n'
        'iifname "ens192" icmp type echo-request counter accept comment "vs-router_access_guard"\n'
    )
    assert guard.missing_rules(present, 'ens192') == []
    # A rule for another interface is not a rule for this one.
    assert len(guard.missing_rules(present, 'ens224')) == 2


def test_no_management_record_means_nothing_to_guard(tmp_path):
    assert guard.read_state(tmp_path / 'missing.json') is None
    assert guard.main(['--dry-run']) in (0, None)


def test_a_host_without_the_address_is_never_reported_as_confirmed():
    """The apply-time half of the same invariant."""
    class Executor:
        def run(self, argv, timeout=None):
            # `ip -4 addr show dev ens192` without the pinned address: exactly
            # what the networkd phase left behind when the stand went dark.
            return SimpleNamespace(returncode=0, stdout='    inet 192.168.22.65/16 brd x\n',
                                   stderr='')

    engine = ApplyEngine(executor=Executor())
    management = SimpleNamespace(interface='ens192', address='192.168.22.64/16',
                                 mode='separate-lan')
    with pytest.raises(ApplyError) as caught:
        engine._verify_management_access(management)
    assert 'management.access_lost' in str(caught.value)

    class Present(Executor):
        def run(self, argv, timeout=None):
            return SimpleNamespace(returncode=0, stdout='    inet 192.168.22.64/16 brd x\n',
                                   stderr='')

    ApplyEngine(executor=Present())._verify_management_access(management)


def test_a_dhcp_lease_may_move_without_failing_the_apply():
    """single-uplink (VPS) keeps a lease; a moved lease is not a lockout."""
    engine = ApplyEngine(executor=SimpleNamespace(
        run=lambda argv, timeout=None: SimpleNamespace(
            returncode=0, stdout='    inet 10.0.0.99/24 brd x\n', stderr='')))
    engine._verify_management_access(
        SimpleNamespace(interface='ens3', address='10.0.0.5/24', mode='single-uplink'))


def test_the_installer_lets_kea_read_the_staged_configuration():
    """Debian's kea AppArmor profile only reads /etc/kea.

    Without the local override every DHCP apply dies in validation — the failure
    the router stand hit, on a configuration `kea-dhcp4 -t` accepts by hand.
    """
    # The override lives with the rest of the Kea provisioning, so a host where
    # Kea appears after the panel gets it too.
    setup = (PACKAGING / 'kea-setup.sh').read_text(encoding='utf-8')
    assert 'local/usr.sbin.kea-dhcp4' in setup
    assert '/run/vs-router/pending/* r,' in setup
    install = (PACKAGING / 'install.sh').read_text(encoding='utf-8')
    assert 'kea-setup.sh' in install
