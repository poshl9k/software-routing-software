"""Host-free checks of VM probe fixtures; never execute the packet probes."""
import json
from pathlib import Path
import runpy

import pytest


def cases(protocol):
    source = Path(__file__).parent / 'lab' / 'generate_tproxy_preauth_cases.py'
    return runpy.run_path(str(source))['generate_cases'](protocol)


@pytest.mark.parametrize('protocol', ['udp', 'tcp'])
def test_vm_cases_use_selected_protocol_and_keep_off_scoped(protocol):
    outputs = cases(protocol)
    for name in ('allow', 'deny_first', 'default_deny', 'allow_first'):
        assert 'type filter hook prerouting priority -90' in outputs[name]
        assert 'type filter hook forward priority -10' in outputs[name + '_guard']
        assert 'chain forward' in outputs[name + '_firewall']
        if name != 'default_deny':
            assert f'{protocol} dport 19090' in outputs[name]
        preview = json.loads(outputs[name + '_singbox'])
        assert any(i['network'] == protocol and i['type'] == 'tproxy' for i in preview['inbounds'])
    assert outputs['off'] == 'destroy table inet vs_router_tproxy_preauth\n'
    assert outputs['off_guard'] == 'destroy table inet vs_router_tproxy_guard\n'
    assert '__combined__' not in outputs  # Mode selection is explicit at CLI boundary.


@pytest.mark.parametrize('protocol', ['udp', 'tcp'])
def test_vm_cases_keep_first_match_order(protocol):
    outputs = cases(protocol)
    assert outputs['deny_first'].index('comment "deny"') < outputs['deny_first'].index('comment "allow"')
    assert outputs['allow_first'].index('comment "allow"') < outputs['allow_first'].index('comment "deny"')


def test_tcp_proof_fixture_is_explicit_and_preserves_baseline():
    source = Path(__file__).parent / 'lab' / 'generate_tproxy_preauth_cases.py'
    generate = runpy.run_path(str(source))['generate_cases']
    baseline = generate('tcp')
    proof = generate('tcp', input_proof=True)
    assert proof.pop('__input_proof__') is True
    assert proof == baseline
    assert '__input_proof__' not in baseline


def test_udp_fixture_rejects_tcp_only_proof_mode():
    source = Path(__file__).parent / 'lab' / 'generate_tproxy_preauth_cases.py'
    generate = runpy.run_path(str(source))['generate_cases']
    with pytest.raises(ValueError, match='TCP-only'):
        generate('udp', input_proof=True)


def lab_module(name):
    return runpy.run_path(str(Path(__file__).parent / 'lab' / name))


def test_collision_fixture_and_cli(tmp_path):
    module = lab_module('generate_tproxy_preauth_cases.py')
    generate = module['generate_cases']
    with pytest.raises(ValueError, match='TCP-only'):
        generate('udp', mark_collision=True)
    collision = generate('tcp', mark_collision=True)
    assert collision.pop('__mark_collision__') is True
    assert collision.pop('__input_proof__') is True
    assert collision == generate('tcp')
    target = tmp_path / 'cases.json'
    for flags in ([], ['--combined'], ['--tcp-proof']):
        with pytest.raises(SystemExit) as exc:
            module['main']([str(target), *flags, '--tcp-mark-collision'])
        assert exc.value.code == 2
        assert not target.exists()
    module['main']([str(target), '--tcp', '--tcp-mark-collision'])
    assert json.loads(target.read_text()) == generate('tcp', mark_collision=True)


def test_collision_requires_literal_proof(tmp_path):
    lab = lab_module('tproxy_tcp_probe.py')['Lab']
    for proof in (None, False, 1, 'true'):
        with pytest.raises(AssertionError, match='requires __input_proof__'):
            lab({'__mark_collision__': True, '__input_proof__': proof}, tmp_path)
    assert not lab({}, tmp_path).mark_collision_mode


@pytest.mark.parametrize('priority', [-86, -84])
@pytest.mark.parametrize('delivered', [False, True])
def test_collision_observes_outcomes_and_stops_before_restore(
        tmp_path, monkeypatch, capsys, priority, delivered):
    module = lab_module('tproxy_tcp_probe.py')
    injector = module['collision_injector'](26001, priority)
    assert f'priority {priority}' in injector
    assert 'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport 26001 tcp dport 19090' in injector
    assert 'meta mark set meta mark | 0x200 counter' in injector
    assert '0x100' not in injector and 'hook input' not in injector
    assert 'counter accept' not in injector
    lab = module['Lab']({'__mark_collision__': True, '__input_proof__': True}, tmp_path)
    calls = []

    class Endpoint:
        def stop(self, abort=False):
            calls.append(('stop', self, abort))

    client, proxy = Endpoint(), Endpoint()
    lab.proxy = proxy
    lab.ingress, lab.origin_wire, lab.receiver = object(), object(), object()
    lab.positive = lambda case, **kw: (calls.append(('positive', case)) or (client, 26001))
    lab.nft = lambda text: calls.append(('nft', text))
    lab.settle = lambda: None
    lab.start_proxy = lambda: calls.append(('start',))
    monkeypatch.setattr(module['time'], 'sleep', lambda _: None)
    values = iter([dict(established=0, output=0), dict(established=2, output=int(delivered))])
    lab.counters = lambda: next(values)
    counts = iter([1, 0, 0, 2, 0 if delivered else 2])
    lab.counter = lambda *args: next(counts)
    tokens = []

    def exchange(endpoint, case):
        assert endpoint is client
        token = case + '\n'
        tokens.append(token)
        return token, dict(sent=len(token), reply=token if len(tokens) == 1 or delivered else '')

    lab.exchange = exchange
    ingress = dict(src='10.212.1.2', dst='198.18.0.2', sport=26001, dport=19090)
    lab.frames = lambda capture, token: [dict(ingress, payload=token)] if (
        capture is lab.ingress or delivered) else []
    lab.mark_collision(priority)
    record = json.loads(capsys.readouterr().out)
    assert record['delivered'] is delivered
    assert record['echoed'] is delivered
    assert record['token'] == tokens[1] != tokens[0]
    assert record['injector_delta'] == 2
    assert record['input_proof_drop_delta'] == (0 if delivered else 2)
    assert record['counters']['output'] == int(delivered)
    assert record['established_control_packets'] == 1
    assert lab.violations == []
    abort = calls.index(('stop', client, True))
    stop = calls.index(('stop', proxy, False))
    restore = calls.index(('nft', lab.intercept))
    remove = calls.index(('nft', 'destroy table inet vsr_tcp_mark_collision\n'))
    assert abort < stop < remove < restore
    assert calls.index(('nft', 'destroy table inet vsr_tcp_intercept\n')) < calls.index(('nft', injector))
    assert not any(c[0] == 'nft' and 'hook input' in c[1] for c in calls)
