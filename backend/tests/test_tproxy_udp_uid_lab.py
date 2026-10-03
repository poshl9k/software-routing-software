"""Host-free structure and fixture checks for the VM-only UDP UID probe."""
import importlib.util
from pathlib import Path
import runpy

import pytest


LAB = Path(__file__).parent / 'lab'
SOURCE = LAB / 'tproxy_udp_uid_probe.py'


def load():
    spec = importlib.util.spec_from_file_location('udp_uid_probe_test', SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))['generate_cases']


def test_fixture_requires_combined_udp_and_exact_direct_config():
    probe = load()
    cases = generate()
    with pytest.raises(AssertionError, match='opt-in'):
        probe.validate_fixture(cases())
    selected = {**cases(), '__combined__': 'udp'}
    probe.validate_fixture(selected)
    with pytest.raises(AssertionError, match='secret-free'):
        probe.validate_fixture({**selected, 'allow_singbox':
                                selected['allow_singbox'].replace('"direct"}',
                                                                  '"direct", "password": "secret"}')})
    with pytest.raises(AssertionError, match='preauthorization'):
        probe.validate_fixture({**selected, 'allow': ''})


def test_same_destination_uid_guard_and_independent_observers():
    probe = load()
    assert 'type filter hook output priority -20; policy accept' in probe.UID_GUARD
    assert probe.UID_GUARD.count(probe.SCOPE) == 2
    assert probe.SCOPE in probe.UID_REVOKE
    assert f'meta skuid {probe.PROXY_UID}' in probe.UID_GUARD + probe.UID_REVOKE
    assert f'meta skuid {probe.OTHER_UID}' in probe.UID_GUARD
    assert f'meta skuid {probe.OTHER_UID}' not in probe.UID_REVOKE
    assert 'counter drop comment "proxy_uid_drop"' in probe.UID_REVOKE
    assert 'ct state established' not in probe.UID_GUARD + probe.UID_REVOKE
    assert 'meta mark' not in probe.UID_GUARD + probe.UID_REVOKE
    assert 'hook prerouting priority -150' in probe.OBSERVE
    assert 'udp sport 25000 udp dport 19090 ct state established counter' in probe.OBSERVE
    assert 'hook input priority -10' in probe.OBSERVE
    assert 'udp dport 19090 counter comment "input_observer"' in probe.OBSERVE
    assert 'tproxy ip to 127.0.0.1:51271' in probe.INTERCEPT


def test_resources_fault_recovery_and_off_are_explicit():
    code = SOURCE.read_text()
    setup = code.split('    def setup(self):', 1)[1].split('    def start_proxy(self):', 1)[0]
    start = code.split('    def start_proxy(self):', 1)[1].split('    def sender(self, port):', 1)[0]
    trial = code.split('    def trial(self):', 1)[1].split('    def off_exchange(', 1)[0]
    assert 'tproxy_preauth_probe' not in code
    assert "base.ns(ROUTER, 'ip', 'link', 'add'" in setup
    assert "base.run('ip', 'link', 'add'" not in setup
    assert "self.policies['allow_firewall'], self.policies['allow']" in setup
    assert "self.policies['allow_guard'], INTERCEPT, OBSERVE, UID_GUARD" in setup
    assert "base.BINARY, 'check'" in setup
    assert 'os.chown(config, PROXY_UID, PROXY_UID)' in setup
    assert 'os.chmod(config, 0o600)' in setup
    assert '--reuid=29090' in start and '--regid=29090' in start
    assert '--bounding-set=-all,+net_raw' in start
    assert '--inh-caps=+net_raw' in start and '--ambient-caps=+net_raw' in start
    assert "fields['Uid']" in start and "fields['CapEff']" in start
    assert "fields['CapAmb']" in start and "'ss', '-H', '-lunp'" in start
    assert 'except Exception' not in start
    assert trial.index("self.sender(25000)") < trial.index("'established-control'")
    assert trial.index("'established-control'") < trial.index('self.nft(UID_REVOKE')
    assert trial.index('self.nft(UID_REVOKE') < trial.index("'revoked'")
    assert "blocked['counters']['established'] > 0" in trial
    assert "blocked['counters']['input'] > 0" in trial
    assert "blocked['counters']['drop'] > 0" in trial
    assert "'--reuid=29091'" in trial and "'--regid=29091'" in trial
    assert "after['other'] > before['other']" in trial
    assert "after['drop'] == before['drop']" in trial
    assert trial.index('old.stop(abort=True)') < trial.index('self.proxy.stop()')
    assert trial.index('self.proxy.stop()') < trial.index("self.nft('flush chain")
    assert trial.index("self.nft('flush chain") < trial.index("'recovered'")
    assert "self.records(self.origin_wire, self.blocked_token)" in trial
    assert "self.policies['off'] + self.policies['off_guard']" in trial
    assert "'off-ordinary-allow'" in trial and "'off-fresh-default-deny'" in trial
    assert 'finally:\n            lab.cleanup()' in code


def test_negative_evidence_requires_ingress_and_origin_checks():
    code = SOURCE.read_text()
    exchange = code.split('    def exchange(', 1)[1].split('    def trial(self):', 1)[0]
    off = code.split('    def off_exchange(', 1)[1].split('    def cleanup(self):', 1)[0]
    assert "self.records(self.ingress, token)" in exchange
    assert "self.records(self.origin_wire, token)" in exchange
    assert "self.records(self.receiver, token)" in exchange
    assert "base.require(ingress" in exchange
    assert "result['reply'] is None and not received and not origin_wire" in exchange
    assert "result['reply'] is None and not wire and not echo" in off
    assert 'stale.append' in code
