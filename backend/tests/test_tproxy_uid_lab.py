"""Host-free checks for the opt-in VM UID experiment."""
import importlib.util
from pathlib import Path
import runpy

import pytest


LAB = Path(__file__).parent / 'lab'
SOURCE = LAB / 'tproxy_tcp_uid_probe.py'


def load():
    spec = importlib.util.spec_from_file_location('uid_probe_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))['generate_cases']


def test_fixture_is_opt_in_and_secret_free():
    uid = load()
    cases = generate()
    with pytest.raises(AssertionError, match='opt-in'):
        uid.validate_fixture(cases('tcp'))
    selected = cases('tcp', input_proof=True)
    uid.validate_fixture(selected)
    with pytest.raises(AssertionError, match='secret-free'):
        uid.validate_fixture({**selected, 'allow_singbox':
                              selected['allow_singbox'].replace('"direct"}',
                                                              '"direct", "password": "secret"}')})


def test_same_tuple_uid_rule_and_independent_observers():
    uid = load()
    guard = uid.UID_GUARD
    revoke = uid.UID_REVOKE
    assert 'type filter hook output priority -20; policy accept' in guard
    assert guard.count(uid.SCOPE) == 2
    assert uid.SCOPE in revoke
    assert f'meta skuid {uid.PROXY_UID}' in guard and f'meta skuid {uid.PROXY_UID}' in revoke
    assert f'meta skuid {uid.OTHER_UID}' in guard
    assert f'meta skuid {uid.OTHER_UID}' not in revoke
    assert 'counter comment "proxy_uid"' in guard
    assert 'counter comment "other_uid"' in guard
    assert 'counter drop comment "proxy_uid_drop"' in revoke
    assert 'ct state established' not in guard + revoke
    assert 'meta mark' not in guard + revoke


def test_uid_start_has_no_root_fallback_and_cleanup_precedes_restore():
    uid = load()
    code = SOURCE.read_text()
    start = code.split('    def start_proxy(self):', 1)[1].split('    def setup(self):', 1)[0]
    trial = code.split('    def uid_trial(self):', 1)[1].split('    def execute(self):', 1)[0]
    execute = code.split('    def execute(self):', 1)[1].split('\ndef main():', 1)[0]
    setup = code.split('    def setup(self):', 1)[1].split('    def uid_counts(self):', 1)[0]
    assert 'base.Lab.setup(self)' in setup
    assert 'super().setup()' not in setup
    assert '--reuid=29090' in start and '--regid=29090' in start
    assert '--inh-caps=+net_raw' in start and '--ambient-caps=+net_raw' in start
    assert '--bounding-set=-all,+net_raw' in start
    assert "fields['Uid']" in start and "fields['CapEff']" in start
    assert "fields['CapAmb']" in start and "'ss', '-H', '-ltnp'" in start
    assert "os.chmod(self.folder, 0o700)" in start
    assert "os.chmod(config, 0o600)" in start
    assert 'except Exception' not in start and 'base.BINARY, \'run\'' in start
    assert trial.index("self.positive('uid-healthy', retain=True)") < trial.index('self.revoke()')
    assert trial.index("ct state established counter") < trial.index('self.revoke()')
    assert trial.index('self.revoke()') < trial.index("self.exchange(client, 'uid-revoked')")
    assert "self.frames(self.ingress, token)" in trial
    assert "self.frames(self.origin_wire, token)" in trial
    assert "self.frames(self.receiver, token)" in trial
    assert '--reuid=29091' in trial and 'other_after[\'drop\'] == other_before[\'drop\']' in trial
    assert trial.index('client.stop(abort=True)') < trial.index('self.receiver.stop()')
    assert trial.index('self.receiver.stop()') < trial.index('self.proxy.stop()')
    assert trial.index('self.proxy.stop()') < trial.index('self.restore()')
    assert "self.positive('uid-recovered')" in trial
    assert "self.positive('off-ordinary-forward', proxied=False)" in execute
    assert "self.negative_syn('off-default-deny')" in execute
    assert 'finally:\n            lab.cleanup()' in code
    assert uid.UidLab.__mro__[1] is uid.output.OutputLab
