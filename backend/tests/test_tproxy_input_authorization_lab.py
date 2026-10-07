"""Host-free checks for the conntrack-mark INPUT authorization lab experiment.

These never touch nftables, namespaces or any network state. They only verify
fixture opt-in, rule narrowness, hook ordering and the exact injection scopes
that separate the lab-09 packet-mark forge from the residual conntrack-mark one.
"""
import json
from pathlib import Path
import runpy

import pytest

from vs_router.generators import marks

LAB = Path(__file__).parent / 'lab'


def generator():
    return runpy.run_path(str(LAB / 'generate_tproxy_preauth_cases.py'))


def probe():
    return runpy.run_path(str(LAB / 'tproxy_tcp_ct_proof_probe.py'))


# --------------------------------------------------------------------------
# fixture opt-in
# --------------------------------------------------------------------------

def test_ct_proof_fixture_is_explicit_and_preserves_baseline():
    generate = generator()['generate_cases']
    baseline = generate('tcp')
    ct = generate('tcp', ct_proof=True)
    assert ct.pop('__ct_proof__') is True
    assert '__input_proof__' not in ct and '__mark_collision__' not in ct
    assert ct == baseline


def test_ct_proof_is_tcp_only_and_standalone():
    generate = generator()['generate_cases']
    with pytest.raises(ValueError, match='TCP-only'):
        generate('udp', ct_proof=True)
    with pytest.raises(ValueError, match='standalone'):
        generate('tcp', input_proof=True, ct_proof=True)
    with pytest.raises(ValueError, match='standalone'):
        generate('tcp', mark_collision=True, ct_proof=True)


def test_ct_proof_cli_is_exclusive(tmp_path):
    module = generator()
    target = tmp_path / 'cases.json'
    for flags in (['--tcp-ct-proof', '--tcp'], ['--tcp-ct-proof', '--tcp-proof'],
                  ['--tcp-ct-proof', '--combined'], ['--tcp-ct-proof', '--tcp-preauth-combined']):
        with pytest.raises(SystemExit) as exc:
            module['main']([str(target), *flags])
        assert exc.value.code == 2
        assert not target.exists()
    module['main']([str(target), '--tcp-ct-proof'])
    assert json.loads(target.read_text()) == module['generate_cases']('tcp', ct_proof=True)


def test_other_modes_never_emit_ct_marker(tmp_path):
    module = generator()
    target = tmp_path / 'cases.json'
    for flags in ([], ['--tcp'], ['--tcp-proof'], ['--tcp-preauth-combined'],
                  ['--tcp', '--tcp-mark-collision']):
        module['main']([str(target), *flags])
        assert '__ct_proof__' not in json.loads(target.read_text())


# --------------------------------------------------------------------------
# probe fixture validation
# --------------------------------------------------------------------------

def test_probe_requires_ct_opt_in_and_rejects_packet_proof():
    validate = probe()['validate_fixture']
    with pytest.raises(AssertionError, match='tcp-ct-proof'):
        validate({})
    packet_proof = generator()['generate_cases']('tcp', input_proof=True)
    with pytest.raises(AssertionError, match='tcp-ct-proof'):
        validate(packet_proof)
    collision = generator()['generate_cases']('tcp', mark_collision=True)
    with pytest.raises(AssertionError, match='tcp-ct-proof'):
        validate(collision)


def test_probe_accepts_generated_ct_fixture():
    fixture = generator()['generate_cases']('tcp', ct_proof=True)
    probe()['validate_fixture'](fixture)  # must not raise


def test_ct_lab_rejects_packet_proof_mode(tmp_path):
    module = probe()
    packet_proof = generator()['generate_cases']('tcp', input_proof=True)
    with pytest.raises(AssertionError, match='standalone'):
        module['CtProofLab'](packet_proof, tmp_path)


# --------------------------------------------------------------------------
# rule narrowness and hook ordering
# --------------------------------------------------------------------------

def test_interception_uses_conntrack_mark_not_packet_proof():
    text = probe()['INTERCEPT_CT']
    assert 'type filter hook prerouting priority -80' in text
    assert 'meta nfproto ipv4 meta l4proto tcp' in text
    assert 'meta mark set 0x100' in text           # routing mark for policy route
    assert 'ct mark set ct mark | 0x200' in text   # authorization token lives in ct
    assert 'meta mark set meta mark | 0x200' not in text  # never the forgeable bit
    assert 'ct status dnat return' in text
    assert 'tproxy ip to 127.0.0.1:51272' in text


def test_reset_and_guard_operate_on_conntrack_mark():
    text = probe()['CT_GUARD']
    reset, guard = text.split('table inet vsr_tcp_ct_input_proof')
    assert 'type filter hook prerouting priority -85' in reset
    assert 'ct mark set ct mark & 0xfffffdff' in reset
    assert 'type filter hook input priority -20' in guard
    assert 'ct mark & 0x200 == 0 counter drop' in guard
    # The guard never authorizes on the forgeable packet mark.
    assert 'meta mark' not in guard
    assert guard.count('drop') == 1
    assert 'ct state' not in guard
    assert 'accept' not in guard.replace('policy accept', '')


def test_hook_order_reset_before_interception_before_guard():
    assert -85 < -80 < -20
    text = probe()['CT_GUARD'] + probe()['INTERCEPT_CT']
    assert 'priority -85' in text and 'priority -80' in text and 'priority -20' in text


# --------------------------------------------------------------------------
# injection scopes
# --------------------------------------------------------------------------

@pytest.mark.parametrize('priority', [-86, -84])
def test_packet_forge_injector_touches_only_packet_mark(priority):
    text = probe()['packet_forge_injector'](26001, priority)
    assert f'priority {priority}' in text
    assert 'ip saddr 10.212.1.2 ip daddr 198.18.0.2 tcp sport 26001 tcp dport 19090' in text
    assert 'meta mark set meta mark | 0x200 counter' in text
    assert 'ct mark' not in text
    assert '0x100' not in text and 'hook input' not in text
    assert 'tproxy' not in text and 'counter accept' not in text


@pytest.mark.parametrize('priority', [-86, -84])
def test_ct_forge_injector_is_the_documented_residual(priority):
    text = probe()['ct_forge_injector'](26001, priority)
    assert f'priority {priority}' in text
    assert 'ct mark set ct mark | 0x200 counter' in text
    assert 'meta mark' not in text
    assert 'tproxy' not in text and 'hook input' not in text


def test_injectors_reject_bad_arguments():
    for fn in (probe()['packet_forge_injector'], probe()['ct_forge_injector']):
        with pytest.raises(AssertionError):
            fn(26001, -80)
        with pytest.raises(AssertionError):
            fn(0, -84)


# --------------------------------------------------------------------------
# registry documents the conntrack namespace without mixing it into packet marks
# --------------------------------------------------------------------------

def test_ct_mark_constants_are_separate_namespace():
    assert marks.MARK_TPROXY_CT_PROOF_VALUE == marks.MARK_TPROXY_PROOF_VALUE == 0x200
    assert marks.MARK_TPROXY_CT_PROOF_MASK == 0x200
    assert (marks.MARK_TPROXY_CT_PROOF_VALUE & marks.MARK_TPROXY_CT_PROOF_CLEAR_MASK) == 0
    names = {entry.name for entry in marks.REGISTRY}
    assert 'tproxy_ct_proof_bit' not in names  # conntrack space is documented, not a packet mark
