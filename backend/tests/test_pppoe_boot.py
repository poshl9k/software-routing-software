"""Post-network-online PPPoE startup uses only confirmed interface names."""
import json
import subprocess

from vs_router.agent import boot_restore
from vs_router.agent import apply


class Executor:
    def __init__(self, failing=()):
        self.calls = []
        self.failing = failing

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv[2] in self.failing:
            raise subprocess.TimeoutExpired(argv, timeout, output=b'secret')
        return subprocess.CompletedProcess(argv, 0)


def setup(monkeypatch, tmp_path, interfaces, applied=None):
    confirmed_dir = tmp_path / 'confirmed'
    confirmed_dir.mkdir()
    applied_dir = tmp_path / 'applied'
    applied_dir.mkdir()
    peers = tmp_path / 'peers'
    peers.mkdir()
    snapshot = {'configuration': {'interfaces': interfaces}}
    (confirmed_dir / 'snapshot.json').write_text(json.dumps({'version_snapshot': snapshot}))
    (applied_dir / 'snapshot.json').write_text(json.dumps(applied or snapshot))
    monkeypatch.setattr(apply, 'CONFIRMED_DIR', confirmed_dir)
    monkeypatch.setattr(boot_restore, 'APPLIED', str(applied_dir))
    monkeypatch.setattr(boot_restore, 'PPPOE_PEERS_DIR', str(peers))
    return peers


def test_starts_only_confirmed_pppoe_with_injected_executor(monkeypatch, tmp_path):
    peers = setup(monkeypatch, tmp_path, [
        {'name': 'eth2', 'addressing': 'pppoe', 'pppoe_password': 'secret'},
        {'name': 'eth1', 'addressing': 'dhcp'},
    ])
    (peers / 'vs-router-eth2').write_text('secret')
    executor = Executor()
    assert boot_restore.post_boot_pppoe(executor) == 0
    assert executor.calls == [(['systemctl', 'start', 'vs-router-pppoe@eth2.service'], 30)]


def test_failure_isolated_and_secret_not_logged(monkeypatch, tmp_path, capsys):
    peers = setup(monkeypatch, tmp_path, [
        {'name': 'eth0', 'addressing': 'pppoe', 'pppoe_password': 'secret'},
        {'name': 'eth2', 'addressing': 'pppoe'},
    ])
    for name in ('eth0', 'eth2'):
        (peers / f'vs-router-{name}').write_text('secret')
    executor = Executor({'vs-router-pppoe@eth0.service'})
    assert boot_restore.post_boot_pppoe(executor) == 1
    assert len(executor.calls) == 2
    assert 'secret' not in capsys.readouterr().err


def test_unconfirmed_snapshot_and_unsafe_name_withheld(monkeypatch, tmp_path):
    interfaces = [{'name': 'eth0', 'addressing': 'pppoe'}]
    setup(monkeypatch, tmp_path, interfaces, {'configuration': {'interfaces': []}})
    executor = Executor()
    assert boot_restore.post_boot_pppoe(executor) == 1
    assert executor.calls == []
