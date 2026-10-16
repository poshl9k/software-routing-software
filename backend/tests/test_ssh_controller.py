"""Host-free checks for SSH fail-closed lifecycle and restore order."""
import json
from types import SimpleNamespace

import pytest

from vs_router.agent.apply import APPLIED_DIR, CONFIRMED_DIR, ApplyError
from vs_router.agent.ssh import SSHController, READY
from test_agent_apply import FakeExecutor, FakeFS


def test_close_attempts_all_containment_even_after_nft_failure():
    fs = FakeFS()
    fs.write(READY, 'protected\n')
    class FailNft(FakeExecutor):
        def run(self, argv, timeout):
            result = super().run(argv, timeout)
            if argv[0] == 'nft':
                return SimpleNamespace(returncode=1)
            return result
    executor = FailNft()
    with pytest.raises(ApplyError, match='ssh.close_failed'):
        SSHController(executor, fs).close()
    assert READY not in fs.files
    assert ['systemctl', 'stop', 'ssh.socket', 'ssh.service'] in [call for call, _ in executor.calls]


def test_restore_requires_identical_confirmed_snapshot():
    fs, executor = FakeFS(), FakeExecutor()
    controller = SSHController(executor, fs)
    version = {'id': 1, 'status': 'confirmed', 'configuration': {'ssh': {'interfaces': ['eth1']}}}
    fs.write(CONFIRMED_DIR / 'snapshot.json', json.dumps({'version_snapshot': version}))
    fs.write(APPLIED_DIR / 'snapshot.json', json.dumps({**version, 'id': 2}))
    with pytest.raises(ApplyError, match='ssh.snapshot_mismatch'):
        controller.restore(SimpleNamespace(status=lambda: None))
    assert ['systemctl', 'unmask', 'ssh.service'] not in [call for call, _ in executor.calls]


def test_restore_does_not_open_ssh_after_interrupted_apply():
    fs, executor = FakeFS(), FakeExecutor()
    SSHController(executor, fs).restore(SimpleNamespace(status=lambda: {'status': 'pending'}))
    assert ['systemctl', 'unmask', 'ssh.service'] not in [call for call, _ in executor.calls]


def test_restore_queues_ssh_only_after_guard_ready():
    fs, executor = FakeFS(), FakeExecutor()
    controller = SSHController(executor, fs, sleep=lambda _: None)
    version = {'id': 1, 'status': 'confirmed', 'configuration': {
        'interfaces': [{'name': 'eth1', 'zone': 'lan'}], 'ssh': {'interfaces': ['eth1']}}}
    fs.write(CONFIRMED_DIR / 'snapshot.json', json.dumps({'version_snapshot': version}))
    fs.write(APPLIED_DIR / 'snapshot.json', json.dumps(version))
    controller.restore(SimpleNamespace(status=lambda: {'status': 'confirmed'}))
    calls = [call for call, _ in executor.calls]
    assert READY in fs.files
    assert calls.index(['systemctl', 'start', 'vs-router-ssh-guard.service']) < calls.index(
        ['systemctl', '--no-block', 'start', 'ssh.service'])
    assert ['systemctl', 'restart', 'ssh.service'] not in calls


def test_single_uplink_leaves_ssh_and_port_22_untouched(monkeypatch):
    """ADR-0017: a one-NIC box has no console, so the panel must not fail closed."""
    from vs_router.management import Management

    fs, executor = FakeFS(), FakeExecutor()
    fs.write(READY, 'protected\n')
    state = Management(interface='eth0', mac='02:00:00:00:00:01',
                       address='92.51.36.131/24', mode='single-uplink')
    monkeypatch.setattr('vs_router.agent.ssh.read_management', lambda path: state)
    controller = SSHController(executor, fs)

    controller.close()
    controller.activate({'interfaces': ['eth0']})
    controller.restore(SimpleNamespace(status=lambda: {'status': 'confirmed'}))

    assert executor.calls == []
    assert READY in fs.files
    assert not any(str(name).endswith('.nft') for name in fs.files)


def test_online_install_marker_disables_the_fail_closed_lifecycle(tmp_path, monkeypatch):
    """The marker exists before the management record, so it must stand alone."""
    marker = tmp_path / 'online-install'
    marker.write_text('')
    monkeypatch.setattr('vs_router.agent.ssh.ONLINE_MARKER', marker)
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(READY, 'protected\n')

    SSHController(executor, fs).close()

    assert executor.calls == []
    assert READY in fs.files
