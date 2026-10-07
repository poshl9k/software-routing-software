"""Host-free checks for the combined TCP preauth probe; never run packet probes.

These verify fixture opt-in, rule narrowness, hook ordering and off-table removal
without touching the kernel, namespaces or any network state.
"""
import json
from pathlib import Path
import runpy

import pytest


LAB = Path(__file__).parent / 'lab'


def generator():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))


def probe():
    return runpy.run_path(str(LAB / 'tproxy_tcp_preauth_combined_probe.py'))


def test_combined_mode_is_opt_in_and_preserves_proof_baseline(tmp_path):
    module = generator()
    generate = module['generate_cases']
    proof = generate('tcp', input_proof=True)
    target = tmp_path / 'cases.json'
    module['main']([str(target), '--tcp-preauth-combined'])
    output = json.loads(target.read_text())
    assert output.pop('__tcp_preauth_combined__') == 'tcp'
    # Reuses the exact TCP INPUT-proof fixture; no generated text differs.
    assert output == proof


@pytest.mark.parametrize('flags', [[], ['--combined'], ['--tcp'], ['--tcp-proof']])
def test_other_modes_never_emit_combined_marker(tmp_path, flags):
    module = generator()
    target = tmp_path / 'cases.json'
    module['main']([str(target), *flags])
    assert '__tcp_preauth_combined__' not in json.loads(target.read_text())


def test_combined_flag_is_mutually_exclusive(tmp_path):
    module = generator()
    target = tmp_path / 'cases.json'
    with pytest.raises(SystemExit) as exc:
        module['main']([str(target), '--tcp-preauth-combined', '--tcp'])
    assert exc.value.code == 2
    assert not target.exists()


def test_combined_fixture_rules_are_narrow():
    output = generator()['generate_cases']('tcp', input_proof=True)
    preauth = output['allow']
    assert 'type filter hook prerouting priority -90; policy accept;' in preauth
    assert 'iifname != ' in preauth              # non-selected ingress returned
    assert 'counter drop' in preauth            # default deny
    assert ' accept ' not in preauth            # preauth grants no accept/marker
    assert 'mark set' not in preauth            # never authorizes interception
    guard = output['allow_guard']
    assert 'type filter hook forward priority -10; policy accept;' in guard
    assert guard.count('drop') == 1             # one containment drop rule
    assert 'iifname { "lan0" } counter drop comment "tproxy_containment"' in guard
    config = json.loads(output['allow_singbox'])
    assert config['outbounds'] == [{'type': 'direct', 'tag': 'direct'}]
    assert all(i['type'] == 'tproxy' for i in config['inbounds'])


def test_hook_ordering_and_off_removes_only_own_tables():
    output = generator()['generate_cases']('tcp', input_proof=True)
    # preauth runs before the lab TProxy interception (prerouting -80) and before
    # the lab INPUT proof (input -20); containment is an independent FORWARD hook.
    assert '-90' in output['allow'] and 'priority -10' in output['allow_guard']
    assert output['off'] == 'destroy table inet vs_router_tproxy_preauth\n'
    assert output['off_guard'] == 'destroy table inet vs_router_tproxy_guard\n'


def test_probe_requires_combined_opt_in_fixture():
    validate = probe()['validate_fixture']
    with pytest.raises(AssertionError, match='tcp-preauth-combined'):
        validate({})
    proof_only = generator()['generate_cases']('tcp', input_proof=True)
    with pytest.raises(AssertionError, match='tcp-preauth-combined'):
        validate(proof_only)


def test_probe_accepts_generated_combined_fixture():
    fixture = generator()['generate_cases']('tcp', input_proof=True)
    fixture['__tcp_preauth_combined__'] = 'tcp'
    # Must not raise: marker present and proof mode carried.
    probe()['validate_fixture'](fixture)


def test_probe_uid_output_guard_is_scoped():
    module = probe()
    guard = module['UID_GUARD']
    assert 'meta skuid 29090' in guard and 'meta skuid 29091' in guard
    assert 'oifname "wan0"' in guard and 'tcp dport 19090' in guard
    assert 'hook output priority -20' in guard
    assert module['UID_REVOKE'].startswith('insert rule')
    assert module['UID_REVOKE'].count(' counter drop ') == 1
    assert '0x100' not in guard and 'hook input' not in guard
