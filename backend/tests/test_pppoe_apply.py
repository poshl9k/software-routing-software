import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.fernet import Fernet

from vs_router.agent.apply import ApplyEngine, ApplyError, APPLIED_DIR, CONFIRMED_DIR
from vs_router.agent import pppoe_apply
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
        self.link_ready = True
        self.route_ready = True

    def run(self, argv, timeout):
        self.calls.append(argv)
        links = ([{'ifname': 'ppp0', 'flags': ['LOWER_UP'], 'addr_info': [
            {'family': 'inet', 'local': '10.41.0.2', 'address': '10.41.0.1'}]}]
            if self.link_ready else [])
        stdout = ([{'dst': 'default', 'dev': 'ppp0'}] if self.route_ready else []) if argv[:4] == ['ip', '-j', '-4', 'route'] else links
        return SimpleNamespace(returncode=int(self.fail == argv), stdout=json.dumps(stdout).encode())


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


def test_readiness_timeout_rolls_back_bad_credentials(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, mode='dhcp')).status == 'confirmed'
    executor.link_ready = False
    ticks = [0]
    def clock():
        return ticks[0]
    def sleep(seconds):
        ticks[0] += seconds
    real_wait = pppoe_apply.wait_ready
    monkeypatch.setattr(pppoe_apply, 'wait_ready',
                        lambda executor, names: real_wait(executor, names, timeout=3,
                                                          clock=clock, sleep=sleep))
    result = engine.apply_version(version(2, password))
    assert result.status == 'rolled_back'
    assert result.reason == 'pppoe.not_ready'
    assert result.reason_service == 'pppoe'
    assert ticks[0] == 3
    assert CONFIRMED_DIR / 'pppoe.json' not in fs.files
    assert Path('/etc/ppp/peers/vs-router-eth0') not in fs.files


def test_pppoe_requires_ipcp_route_and_carrier(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, mode='dhcp')).status == 'confirmed'
    executor.route_ready = False
    assert not pppoe_apply.ready(executor, ['eth0'])
    executor.route_ready = True
    assert pppoe_apply.ready(executor, ['eth0'])
    assert ['ip', '-j', '-4', 'route', 'show'] in executor.calls


def test_pending_peer_loss_rolls_back_on_confirmation(monkeypatch):
    engine, fs, executor, password = setup(monkeypatch)
    assert engine.apply_version(version(1, mode='dhcp')).status == 'confirmed'
    assert engine.apply_version(version(2, password), safe_mode=True).status == 'pending'
    executor.link_ready = False
    try:
        engine.confirm_version(2)
    except ApplyError as exc:
        assert exc.code == 'pppoe.not_ready'
    else:
        assert False, 'confirmation should reject a lost PPP link'
    assert engine.status()['status'] == 'rolled_back'
    assert CONFIRMED_DIR / 'pppoe.json' not in fs.files
