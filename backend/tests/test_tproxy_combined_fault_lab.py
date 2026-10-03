"""Host-free checks for the VM-only combined TCP fault experiment."""
import importlib.util
from pathlib import Path
import runpy

import pytest

LAB = Path(__file__).parent / 'lab'
SOURCE = LAB / 'tproxy_tcp_combined_fault_probe.py'


def load():
    spec = importlib.util.spec_from_file_location('combined_probe_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))['generate_cases'](
        'tcp', input_proof=True)


def test_inherits_uid_namespace_lab_and_rejects_unsafe_fixtures(monkeypatch):
    combined = load()
    assert combined.CombinedLab.__mro__[1] is combined.uid.UidLab
    cases = fixture()
    combined.uid.validate_fixture(cases)
    with pytest.raises(AssertionError, match='opt-in'):
        combined.uid.validate_fixture({**cases, '__input_proof__': False})
    with pytest.raises(AssertionError, match='secret-free'):
        combined.uid.validate_fixture({**cases, 'allow_singbox':
                                       cases['allow_singbox'].replace(
                                           '"direct"}', '"direct", "password": "secret"}')})
    monkeypatch.setattr(combined.sys, 'argv', ['probe', '/unused'])
    monkeypatch.setattr(combined.Path, 'read_text', lambda self: '{}')
    with pytest.raises(AssertionError, match='opt-in'):
        combined.main()


def test_fault_order_and_bounded_evidence():
    code = SOURCE.read_text()
    a = code.split('    def collision_trial(self):', 1)[1].split('    def combined_trial(self):', 1)[0]
    b = code.split('    def combined_trial(self):', 1)[1].split('    def execute(self):', 1)[0]
    observe = code.split('    def observe_fault(self,', 1)[1].split('    def stop_old(self,', 1)[0]
    assert a.index('self.established_client(') < a.index('destroy table inet vsr_tcp_intercept')
    assert 'self.revoke()' not in a
    assert a.index('self.stop_old(client)') < a.index('self.nft(self.intercept)')
    assert b.index('self.established_client(') < b.index('self.revoke()')
    assert b.index('self.revoke()') < b.index('destroy table inet vsr_tcp_intercept')
    assert b.index('self.stop_old(client)') < b.index('other_token =')
    assert b.index('other_token =') < b.index('self.receiver.stop()')
    assert b.index('self.receiver.stop()') < b.index('self.restore()')
    assert b.index('self.restore()') < b.index('self.start_proxy()')
    assert 'base.collision_injector(port, -84)' in a + b
    assert "self.frames(self.ingress, token)" in observe
    assert "self.frames(self.origin_wire, token)" in observe
    assert "self.frames(self.receiver, token)" in observe
    assert "evidence['input_proof_drop_delta'] == 0" in observe
    assert "evidence['uid_counters']['input'] > 0" in observe
    assert "evidence['forward_guard_delta'] == 0" in observe
    assert "evidence['uid_counters']['drop'] > 0" in b
    assert "evidence['other_uid']['proxy_drop_delta'] == 0" in b
    assert "self.positive('combined-recovered')" in b
    assert "self.positive('off-ordinary-forward', proxied=False)" in code
    assert "self.negative_syn('off-default-deny')" in code
    assert 'finally:\n            lab.cleanup()' in code
