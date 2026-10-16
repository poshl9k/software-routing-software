"""Peers of a running tunnel are programmed without a full apply."""
import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from vs_router.agent.apply import ApplyError
from vs_router.agent.rpc import PARAMS, RPCRequest, TunnelPeersSyncParams
from vs_router.agent.services import MANIFEST, TunnelPeers

from test_agent_apply import FakeFS, FakeExecutor

KEY_A = base64.b64encode(b'a' * 32).decode()
KEY_B = base64.b64encode(b'b' * 32).decode()
KEY_C = base64.b64encode(b'c' * 32).decode()
PSK = base64.b64encode(b'p' * 32).decode()


def applied(fs, interfaces={'wg0': 'wg'}):
    fs.write(MANIFEST, json.dumps({name: {'protocol': protocol, 'file': f'{name}.conf'}
                                   for name, protocol in interfaces.items()}))


def dump(peers):
    """`wg show <iface> dump`: the interface line first, then one line per peer."""
    header = f'{KEY_A}\t{KEY_B}\t51820\toff\n'
    return (header + ''.join(f'{key}\t(none)\t(none)\t10.66.66.9/32\t0\t0\t0\toff\n'
                             for key in peers)).encode()


def executor_for(executor, peers):
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if len(argv) > 2 and argv[1] == 'show':
            return SimpleNamespace(returncode=0, stdout=dump(peers))
        return SimpleNamespace(returncode=0)
    return run


def test_sync_sets_the_desired_peers_and_removes_the_rest():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [KEY_B])
    result = TunnelPeers(executor, fs).sync('wg0', [
        {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': None}])
    calls = [argv for argv, _ in executor.calls]
    assert ['wg', 'set', 'wg0', 'peer', KEY_A, 'allowed-ips', '10.66.66.2/32'] in calls
    assert ['wg', 'set', 'wg0', 'peer', KEY_B, 'remove'] in calls
    assert result == {'added': [KEY_A], 'removed': [KEY_B], 'unchanged': []}


def test_sync_reports_a_peer_that_was_already_present():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [KEY_A])
    result = TunnelPeers(executor, fs).sync('wg0', [
        {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': None}])
    assert result == {'added': [], 'removed': [], 'unchanged': [KEY_A]}
    assert not any('remove' in argv for argv, _ in executor.calls)


def test_sync_uses_the_amneziawg_tool_for_an_awg_tunnel():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs, {'awg0': 'awg'})
    executor.run = executor_for(executor, [])
    TunnelPeers(executor, fs).sync('awg0', [
        {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': None}])
    assert any(argv[:2] == ['awg', 'set'] for argv, _ in executor.calls)
    assert not any(argv[:2] == ['wg', 'set'] for argv, _ in executor.calls)


def test_sync_never_puts_the_preshared_key_in_the_command_line():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [])
    config_dir = Path('/etc/vs-router/wireguard')
    TunnelPeers(executor, fs, config_dir=config_dir).sync('wg0', [
        {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': PSK}])
    calls = [argv for argv, _ in executor.calls]
    secret_path = str(config_dir / 'peer-preshared-key.tmp')
    assert ['wg', 'set', 'wg0', 'peer', KEY_A, 'allowed-ips', '10.66.66.2/32',
            'preshared-key', secret_path] in calls
    assert not any(PSK in argv for argv, _ in executor.calls)
    # The key file is consumed and removed: nothing keeps the secret on disk.
    assert config_dir / 'peer-preshared-key.tmp' not in fs.files


def test_sync_touches_only_interfaces_the_panel_applied():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs, {'wg0': 'wg'})
    executor.run = executor_for(executor, [])
    with pytest.raises(ApplyError) as failure:
        TunnelPeers(executor, fs).sync('eth0', [])
    assert failure.value.code == 'tunnel.not_applied'
    assert executor.calls == []


def test_sync_refuses_a_peer_without_allowed_ips():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [])
    with pytest.raises(ApplyError) as failure:
        TunnelPeers(executor, fs).sync('wg0', [
            {'public_key': KEY_A, 'allowed_ips': [], 'preshared_key': None}])
    assert failure.value.code == 'tunnel.peer_allowed_ips_required'


def test_sync_refuses_a_malformed_allowed_ip():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [])
    with pytest.raises(ApplyError) as failure:
        TunnelPeers(executor, fs).sync('wg0', [
            {'public_key': KEY_A, 'allowed_ips': ['not-a-network'], 'preshared_key': None}])
    assert failure.value.code == 'tunnel.peer_allowed_ips_invalid'


def test_sync_fails_closed_when_the_device_cannot_be_read():
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.fail = True
    with pytest.raises(ApplyError) as failure:
        TunnelPeers(executor, fs).sync('wg0', [])
    assert failure.value.code == 'tunnel.peer_failed'


def test_sync_request_is_typed_and_rejects_a_bad_key():
    assert PARAMS['tunnel_peers_sync'] is TunnelPeersSyncParams
    request = {'id': 1, 'method': 'tunnel_peers_sync',
               'params': {'interface': 'wg0', 'peers': [
                   {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32']}]}}
    assert RPCRequest.model_validate(request).method == 'tunnel_peers_sync'
    for params in ({'interface': 'wg0; rm -rf /', 'peers': []},
                   {'interface': 'wg0', 'peers': [{'public_key': 'nope',
                                                   'allowed_ips': ['10.66.66.2/32']}]},
                   {'interface': 'wg0', 'peers': [{'public_key': KEY_A, 'allowed_ips': []}]},
                   {'interface': 'wg0', 'peers': [{'public_key': KEY_A}]}):
        with pytest.raises(ValidationError):
            RPCRequest.model_validate({**request, 'params': params})


def test_sync_keeps_only_the_requested_peers():
    """Two peers in, one out of the stored set: the missing one is removed."""
    fs, executor = FakeFS(), FakeExecutor()
    applied(fs)
    executor.run = executor_for(executor, [KEY_A, KEY_C])
    result = TunnelPeers(executor, fs).sync('wg0', [
        {'public_key': KEY_A, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': None},
        {'public_key': KEY_B, 'allowed_ips': ['10.66.66.3/32'], 'preshared_key': None}])
    calls = [argv for argv, _ in executor.calls]
    assert result == {'added': [KEY_B], 'removed': [KEY_C], 'unchanged': [KEY_A]}
    assert calls.count(['wg', 'set', 'wg0', 'peer', KEY_C, 'remove']) == 1
