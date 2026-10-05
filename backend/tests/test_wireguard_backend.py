import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor
from vs_router.agent.services import WireGuardReloader


class WgExecutor(FakeExecutor):
    """FakeExecutor that answers the kernel probe and link presence."""

    def __init__(self, kernel=('wg', 'awg'), present=()):
        super().__init__()
        self.kernel = set(kernel)
        self.present = set(present)

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv[:2] == ['ip', 'link'] and argv[2] == 'add':
            kind = argv[-1]
            protocol = 'wg' if kind == 'wireguard' else 'awg'
            return SimpleNamespace(returncode=0 if protocol in self.kernel else 1)
        if argv[:2] == ['ip', 'link'] and argv[2] == 'show':
            return SimpleNamespace(returncode=0 if argv[4] in self.present else 1)
        return SimpleNamespace(returncode=0)


def bundle(protocol):
    """Serialize through the real bundle format the agent deserializes."""
    from vs_router.generators.wireguard import serialize_wireguard
    files = {
        'manifest.json': json.dumps({'wg0': {'file': 'vpn.conf', 'protocol': protocol,
                                             'addresses': ['10.66.66.1/24'],
                                             'routes': ['10.10.0.0/16']}}),
        'vpn.conf': '[Interface]\nPrivateKey = x\n',
    }
    return serialize_wireguard(files)


@pytest.mark.parametrize('protocol,kind', [('wg', 'wireguard'), ('awg', 'amneziawg')])
def test_kernel_backend_selects_link_type_without_daemon(protocol, kind):
    fs = FakeFS()
    executor = WgExecutor()
    reloader = WireGuardReloader(executor=executor, filesystem=fs,
                                 config_dir=Path('/wg'), sleep=lambda _: None)
    fs.write(Path('/bundle'), bundle(protocol))
    reloader(Path('/bundle'))
    commands = [tuple(argv) for argv, _ in executor.calls]
    assert ('ip', 'link', 'add', 'dev', 'wg0', 'type', kind) in commands
    assert not any('systemctl' in argv and f'{protocol}@wg0.service' in argv for argv in commands)
    assert (protocol, 'setconf', 'wg0', '/wg/vpn.conf') in commands
    assert ('ip', 'addr', 'replace', '10.66.66.1/24', 'dev', 'wg0') in commands


def test_awg_falls_back_to_userspace_without_its_module():
    """A kernel with WireGuard but no AmneziaWG module must use the daemon."""
    fs = FakeFS()
    executor = WgExecutor(kernel={'wg'})
    reloader = WireGuardReloader(executor=executor, filesystem=fs,
                                 config_dir=Path('/wg'), sleep=lambda _: None)
    fs.write(Path('/bundle'), bundle('awg'))
    reloader(Path('/bundle'))
    commands = [tuple(argv) for argv, _ in executor.calls]
    assert ('systemctl', 'enable', 'vs-router-awg@wg0.service') in commands
    assert ('ip', 'link', 'add', 'dev', 'wg0', 'type', 'amneziawg') not in commands
    assert ('awg', 'setconf', 'wg0', '/wg/vpn.conf') in commands


def test_userspace_fallback_when_kernel_lacks_wireguard():
    fs = FakeFS()
    executor = WgExecutor(kernel=set())
    reloader = WireGuardReloader(executor=executor, filesystem=fs,
                                 config_dir=Path('/wg'), sleep=lambda _: None)
    fs.write(Path('/bundle'), bundle('wg'))
    reloader(Path('/bundle'))
    commands = [tuple(argv) for argv, _ in executor.calls]
    assert ('systemctl', 'enable', 'vs-router-wg@wg0.service') in commands
    assert ('ip', 'link', 'add', 'wg0', 'type', 'wireguard') not in commands


def test_existing_kernel_link_is_not_recreated():
    fs = FakeFS()
    executor = WgExecutor(present={'wg0'})
    reloader = WireGuardReloader(executor=executor, filesystem=fs,
                                 config_dir=Path('/wg'), sleep=lambda _: None)
    fs.write(Path('/bundle'), bundle('wg'))
    reloader(Path('/bundle'))
    commands = [tuple(argv) for argv, _ in executor.calls]
    assert ('ip', 'link', 'add', 'dev', 'wg0', 'type', 'wireguard') not in commands


def test_probe_leaves_no_interface_behind():
    executor = WgExecutor()
    assert WireGuardReloader.probe_kernel_wireguard(executor) is True
    commands = [tuple(argv) for argv, _ in executor.calls]
    assert commands[0] == ('ip', 'link', 'del', 'vsrwprobe0')
    assert commands[-1] == ('ip', 'link', 'del', 'vsrwprobe0')
    assert ('ip', 'link', 'add', 'vsrwprobe0', 'type', 'wireguard') in commands


def test_probe_reports_false_without_kernel_support():
    assert WireGuardReloader.probe_kernel_wireguard(WgExecutor(kernel=set())) is False


def test_probe_uses_the_protocol_link_type():
    executor = WgExecutor()
    assert WireGuardReloader.probe_kernel_wireguard(executor, 'awg') is True
    assert ('ip', 'link', 'add', 'vsrwprobe0', 'type', 'amneziawg') in [
        tuple(argv) for argv, _ in executor.calls]
