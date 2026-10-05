import base64
import io
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent.apply import APPLIED_DIR, FILES, ApplyEngine, ApplyError
from vs_router.agent.services import NftApply, UnboundReloader, KeaReloader
from vs_router.generators import generate_nftables, generate_kea
from vs_router.schema import ConfigurationVersion


def test_nft_transaction():
    executor = FakeExecutor()
    text = generate_nftables(ConfigurationVersion())
    assert text.startswith('destroy table inet vs_router\ntable inet vs_router {')
    assert 'flush ruleset' not in text
    NftApply(executor)(APPLIED_DIR / 'nftables.conf')
    assert executor.calls == [(['nft', '-f', str(APPLIED_DIR / 'nftables.conf')], 15)]
    executor.fail = True
    with pytest.raises(ApplyError):
        NftApply(executor)(APPLIED_DIR / 'nftables.conf')


@pytest.mark.parametrize('failure', [None, 'check', 'reload', 'hup'])
def test_unbound_full_check_and_fallback(failure):
    fs, executor = FakeFS(), FakeExecutor()
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        failed = ((failure == 'check' and argv[0] == 'unbound-checkconf')
                  or (failure in ('reload', 'hup') and argv[:2] == ['systemctl', 'reload'])
                  or (failure == 'hup' and argv[:2] == ['systemctl', 'kill']))
        return SimpleNamespace(returncode=int(failed))
    executor.run = run
    adapter = UnboundReloader(executor, fs)
    if failure in ('check', 'hup'):
        with pytest.raises(ApplyError):
            adapter(APPLIED_DIR / 'unbound.conf')
    else:
        adapter(APPLIED_DIR / 'unbound.conf')
    assert fs.read(adapter.include_path) == f'include: "{APPLIED_DIR}/unbound.conf"\n'
    assert executor.calls[1][0] == ['unbound-checkconf', '/etc/unbound/unbound.conf']
    if failure == 'check':
        assert len(executor.calls) == 2
    if failure in ('reload', 'hup'):
        assert executor.calls[-1][0] == ['systemctl', 'kill', '--kill-whom=main', '-s', 'HUP', 'unbound']


@pytest.mark.parametrize('start_succeeds', [True, False])
def test_unbound_starts_when_initial_include_was_missing(start_succeeds):
    fs, executor = FakeFS(), FakeExecutor()
    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv == ['systemctl', 'is-active', '--quiet', 'unbound']:
            return SimpleNamespace(returncode=3)
        if argv == ['systemctl', 'start', 'unbound']:
            assert fs.read(Path('/etc/unbound/unbound.conf.d/vs-router.conf')) == (
                f'include: "{APPLIED_DIR}/unbound.conf"\n')
            return SimpleNamespace(returncode=0 if start_succeeds else 1)
        return SimpleNamespace(returncode=0)
    executor.run = run
    adapter = UnboundReloader(executor, fs)
    if start_succeeds:
        adapter(APPLIED_DIR / 'unbound.conf')
    else:
        with pytest.raises(ApplyError, match='agent.reload_failed'):
            adapter(APPLIED_DIR / 'unbound.conf')
    assert (['systemctl', 'start', 'unbound'], 15) in executor.calls
    assert (['systemctl', 'reload', 'unbound'], 15) not in executor.calls


@pytest.mark.parametrize('reply,status,ok', [('[{"result":0}]', 200, True),
    ('[{"result":1}]', 200, False), ('[]', 200, False), ('{}', 200, False),
    ('not json', 200, False), ('[{"result":false}]', 200, False),
    ('[{"result":0}]', 401, False), ('[{}]', 200, False)])
def test_kea_reload(reply, status, ok):
    fs, executor = FakeFS(), FakeExecutor()
    source = APPLIED_DIR / 'kea.json'
    fs.write(source, generate_kea(ConfigurationVersion()))
    fs.write(Path('/etc/kea/kea-api-password'), 'secret\n')
    def http(request, timeout):
        assert timeout == 15
        assert request.full_url == 'http://127.0.0.1:8000/'
        assert request.get_method() == 'POST'
        assert request.get_header('Authorization') == 'Basic ' + base64.b64encode(b'kea-api:secret').decode()
        assert json.loads(request.data) == {'command': 'config-reload', 'service': ['dhcp4']}
        assert fs.read(Path('/etc/kea/kea-dhcp4.conf')) == fs.read(source)
        response = io.BytesIO(reply.encode())
        response.status = status
        return response
    adapter = KeaReloader(executor, fs, http)
    if ok:
        adapter(source)
    else:
        with pytest.raises(ApplyError, match='reload_failed'):
            adapter(source)
    assert json.loads(fs.read(source))['Dhcp4']['control-socket']['socket-name'] == '/run/kea/kea4-ctrl-socket'


@pytest.mark.parametrize('password', [None, '', 'secret'])
def test_kea_transport_and_password_failure(password):
    fs = FakeFS()
    if password is not None:
        fs.write(Path('/etc/kea/kea-api-password'), password)
    fs.write(APPLIED_DIR / 'kea.json', '{}')
    def http(*args, **kwargs):
        raise URLError('offline')
    with pytest.raises((ApplyError, FileNotFoundError)):
        KeaReloader(FakeExecutor(), fs, http)(APPLIED_DIR / 'kea.json')


def test_live_adapters_apply_and_rollback():
    fs, executor = FakeFS(), FakeExecutor()
    fs.write(Path('/etc/kea/kea-api-password'), 'secret')
    payloads = []
    def http(request, timeout):
        payloads.append(fs.read(Path('/etc/kea/kea-dhcp4.conf')))
        response = io.BytesIO(b'[{"result":0}]')
        response.status = 200
        return response
    engine = ApplyEngine(filesystem=fs, executor=executor, reload_commands={
        'nftables': NftApply(executor), 'unbound': UnboundReloader(executor, fs),
        'kea': KeaReloader(executor, fs, http)})
    assert engine.apply_version(snapshot()).status == 'confirmed'
    originals = {name: fs.read(APPLIED_DIR / file) for name, file in FILES.items()}
    assert engine.apply_version(dict(snapshot(2), configuration={'panel_port': 8443}), True).status == 'pending'
    assert engine.status()['phases'] == dict.fromkeys(FILES, 'applied')
    assert engine.rollback('timeout').status == 'rolled_back'
    assert engine.status()['phases'] == dict(dict.fromkeys(FILES, 'applied'), rollback='rolled_back')
    assert all(fs.read(APPLIED_DIR / FILES[name]) == value for name, value in originals.items())
    assert len(payloads) == 3
    assert payloads[-1] == originals['kea']
    assert sum(argv[:2] == ['nft', '-f'] for argv, _ in executor.calls) == 3
    assert sum(argv == ['systemctl', 'reload', 'unbound'] for argv, _ in executor.calls) == 3


def test_callable_failure_retries_confirmed_and_marks_failed_rollback():
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    engine.apply_version(snapshot())
    calls = []
    def fail(path):
        calls.append(fs.read(path))
        raise ApplyError('agent.reload_failed')
    engine.reload_commands = {'nftables': fail}
    with pytest.raises(ApplyError, match='rollback_failed'):
        engine.apply_version(dict(snapshot(2), configuration={'panel_port': 8443}), True)
    assert len(calls) == 2
    assert engine.status()['status'] == 'rollback_failed'
    assert engine.status()['phases']['nftables'] == 'validated'


def test_phase_is_recorded_only_after_callable_reload_and_failure_recovers():
    fs, executor = FakeFS(), FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    engine.apply_version(snapshot())
    original = fs.read(APPLIED_DIR / 'nftables.conf')
    seen = []
    def reload(path):
        assert engine.status()['phases']['nftables'] == 'validated'
        seen.append(fs.read(path))
        if len(seen) == 1:
            raise ApplyError('agent.reload_failed')
    engine.reload_commands = {'nftables': reload}
    result = engine.apply_version(dict(snapshot(2), configuration={'panel_port': 8443}), True)
    assert result.status == 'rolled_back'
    assert len(seen) == 2
    assert seen[-1] == original
    assert engine.status()['reason'] == 'agent.reload_failed'
