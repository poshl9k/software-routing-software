"""Host-free structural checks; never start namespace or packet probes."""
import importlib.util
from pathlib import Path
import runpy

import pytest


LAB = Path(__file__).parent / 'lab'


def load():
    spec = importlib.util.spec_from_file_location('output_probe_test', LAB / 'tproxy_tcp_output_probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixtures():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))['generate_cases']


def test_fixture_selection_is_opt_in_and_does_not_change_generated_cases():
    module = load()
    generate = fixtures()
    baseline = generate('tcp')
    with pytest.raises(AssertionError, match='opt-in'):
        module.validate_fixture(baseline)
    for selected in (generate('tcp', input_proof=True), generate('tcp', mark_collision=True)):
        module.validate_fixture(selected)
        assert {k: v for k, v in selected.items() if not k.startswith('__')} == baseline
    with pytest.raises(AssertionError, match='opt-in'):
        module.validate_fixture(generate('udp'))


def test_output_rule_scope_and_order():
    module = load()
    guard = module.OUTPUT_GUARD
    revoke = module.OUTPUT_REVOKE
    assert 'type filter hook output priority -20; policy accept' in guard
    assert 'type filter hook output priority -20; policy accept' not in module.base.OBSERVE
    for text in (guard, revoke):
        assert 'ip daddr 198.18.0.2 oifname "wan0" tcp dport 19090' in text
        assert 'ct state established' not in text
        assert 'meta mark' not in text
    assert 'counter drop comment "revoked_output"' in revoke
    assert 'ct state established' not in module.OUTPUT_GUARD
    assert 'type filter hook input priority -15; policy accept' in module.INPUT_OBSERVE
    assert 'counter comment "accepted_input_path"' in module.INPUT_OBSERVE
    assert 'counter accept' not in module.INPUT_OBSERVE


def test_runtime_revocation_and_cleanup_order_are_independent():
    module = load()
    code = (LAB / 'tproxy_tcp_output_probe.py').read_text()
    trial = code.split('    def output_trial(self):', 1)[1].split('    def settle_without_receiver', 1)[0]
    assert trial.index('self.revoke()') < trial.index('self.exchange(client, \'output-revoked\')')
    assert trial.index('client.stop(abort=True)') < trial.index('self.receiver.stop()')
    assert trial.index('self.receiver.stop()') < trial.index('self.proxy.stop()')
    assert trial.index('self.proxy.stop()') < trial.index('self.restore()')
    assert 'self.frames(self.ingress, token)' in trial
    assert 'self.frames(self.origin_wire, token)' in trial
    assert 'self.frames(self.receiver, token)' in trial
    assert 'self.positive(\'output-recovered\')' in trial
    assert 'self.positive(\'off-ordinary-forward\', proxied=False)' in code
    assert 'self.negative_syn(\'off-default-deny\')' in code
    assert module.base.SENDER == runpy.run_path(str(LAB / 'tproxy_tcp_probe.py'))['SENDER']
