import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.fernet import Fernet

from vs_router.agent.apply import ApplyEngine, APPLIED_DIR, CONFIRMED_DIR
from vs_router.agent.services import PPPoEReloader, NetworkdReloader
from vs_router.secrets import encrypt_secret
from vs_router.schema import ConfigurationVersion


class FS:
    def __init__(self):
        self.files = {}

    def write(self, path, content):
        self.files[Path(path)] = content

    def read(self, path):
        try:
            return self.files[Path(path)]
        except KeyError:
            raise FileNotFoundError(path) from None

    def remove(self, path):
        self.files.pop(Path(path), None)

    def atomic_move(self, source, destination):
        self.write(destination, self.read(source))
        self.remove(source)


class Exec:
    def __init__(self):
        self.calls = []
        self.fail: list[str] | None = None

    def run(self, argv, timeout):
        self.calls.append(argv)
        return SimpleNamespace(returncode=int(self.fail == argv))


def version(number, password=None, mode='pppoe'):
    iface = {'name': 'eth0', 'zone': 'wan', 'addressing': mode}
    if mode == 'pppoe':
        iface.update(pppoe_username='alice', pppoe_password=password)
    return ConfigurationVersion.model_validate(
        {'id': number, 'status': 'draft', 'configuration': {'interfaces': [iface]}}
    ).model_dump(mode='json')


def setup(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    fs, executor = FS(), Exec()
    reloads = {'networkd': NetworkdReloader(executor, fs),
               'pppoe': PPPoEReloader(executor, fs)}
    engine = ApplyEngine(filesystem=fs, executor=executor, reload_commands=reloads)
    return engine, fs, executor, encrypt_secret('secret', key)


def test_validation_precedes_live_mutation(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    executor.fail = ['/usr/sbin/pppd', '--version']
    result = engine.apply_version(version(1, password))
    assert result.status == 'failed'
    assert APPLIED_DIR / 'pppoe.json' not in fs.files
    assert not any(str(path).startswith('/etc/ppp/') for path in fs.files)
    assert not any(call[0] == 'systemctl' and call[1] == 'start' for call in executor.calls)


def test_service_failure_restores_confirmed_and_stops_peer(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, mode='dhcp')).status == 'confirmed'
    old_network = fs.read(APPLIED_DIR / 'networkd.conf')
    executor.fail = ['systemctl', 'start', 'vs-router-pppoe@eth0.service']
    result = engine.apply_version(version(2, password), safe_mode=True)
    assert result.status == 'rolled_back'
    assert fs.read(APPLIED_DIR / 'networkd.conf') == old_network
    assert Path('/etc/ppp/peers/vs-router-eth0') not in fs.files
    assert ['systemctl', 'stop', 'vs-router-pppoe@eth0.service'] in executor.calls


def test_switch_and_safe_confirmation_backup(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, mode='dhcp')).status == 'confirmed'
    assert engine.apply_version(version(2, password), safe_mode=True).status == 'pending'
    assert Path('/etc/systemd/network/10-vs-router-eth0.network') not in fs.files
    assert engine.confirm_version(2)['status'] == 'confirmed'
    backup = json.loads(fs.read(CONFIRMED_DIR / 'snapshot.json'))
    assert 'pppoe' in backup['files']
    assert engine.apply_version(version(3, mode='dhcp')).status == 'confirmed'
    assert Path('/etc/systemd/network/10-vs-router-eth0.network') in fs.files
    assert Path('/etc/ppp/peers/vs-router-eth0') not in fs.files
    assert Path('/etc/ppp/chap-secrets') not in fs.files
    assert Path('/etc/ppp/pap-secrets') not in fs.files
    assert CONFIRMED_DIR / 'pppoe.json' not in fs.files
    assert ['systemctl', 'stop', 'vs-router-pppoe@eth0.service'] in executor.calls


def test_switch_away_stop_failure_rolls_back_to_pppoe(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, password)).status == 'confirmed'
    peer = fs.read(Path('/etc/ppp/peers/vs-router-eth0'))
    executor.fail = ['systemctl', 'stop', 'vs-router-pppoe@eth0.service']
    result = engine.apply_version(version(2, mode='dhcp'))
    assert result.status == 'rolled_back'
    assert result.reason == 'agent.reload_failed'
    assert fs.read(Path('/etc/ppp/peers/vs-router-eth0')) == peer
    assert Path('/etc/systemd/network/10-vs-router-eth0.network') not in fs.files


def test_first_apply_start_failure_cleans_credentials(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    executor.fail = ['systemctl', 'start', 'vs-router-pppoe@eth0.service']
    result = engine.apply_version(version(1, password))
    assert result.status == 'failed'
    for name in ('peers/vs-router-eth0', 'chap-secrets', 'pap-secrets'):
        assert Path('/etc/ppp') / name not in fs.files
    assert APPLIED_DIR / 'pppoe.json' not in fs.files


def test_ordinary_artifact_map_and_validator_are_unchanged(monkeypatch):
    from vs_router.agent.apply import FILES, VALIDATORS
    engine, fs, executor, _ = setup(monkeypatch)
    result = engine.apply_version(version(1, mode='dhcp'))
    assert result.status == 'confirmed'
    assert set(result.phases) == set(FILES)
    assert set(json.loads(fs.read(CONFIRMED_DIR / 'snapshot.json'))['files']) == set(FILES)
    assert not any('pppd' in argv or 'vs-router-pppoe@eth0.service' in argv
                   for argv in executor.calls)
    assert 'pppoe' not in VALIDATORS
