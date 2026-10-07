"""Host-free invariant tests for the lab-31 preauth<->capture coupling.

F4 in ``docs/lab-30-tproxy-e2e-matrix.md`` was a residual: with the preauth
table gone, a denied selected flow was still captured into LOCAL_IN and reached
origin, because capture is routing and did not depend on preauth. The fix makes
**capture depend on a live preauth**: ``generate_tproxy_preauthorization``
stamps a reserved packet mark on authorized selected transit and
``generate_tproxy_interception`` capture fires only when that mark is present.
Losing preauth removes the mark, capture returns, the flow stays on FORWARD and
the independent containment (``-10``) / default-deny hold it.

These tests never touch a host: they pin the coupling, the single ownership of
the mark, the "no mark leaks onto disabled/denied paths" property and the
fail-closed direction (capture requires preauth, never the reverse).
"""
import pytest

from vs_router.generators import marks
from vs_router.generators.nftables import (generate_tproxy_interception,
                                           generate_tproxy_preauthorization)
from vs_router.schema import ConfigurationVersion


def _version(rules=(), enabled=True):
    version = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": ["10.212.2.1/24"]},
        ],
        "firewall_rules": list(rules),
        "tproxy": {"ingress_interfaces": ["lan0"]},
    }})
    if not enabled:
        return version
    tproxy = version.configuration.tproxy.model_copy(update={"enabled": True})
    return version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": tproxy})})


ALLOW = {"name": "allow", "ingress_zone": "lan", "dst": "zone:wan",
         "protocol": "tcp", "destination_ports": "19090", "action": "pass", "order": 10}
BLOCK = {"name": "block", "ingress_zone": "lan", "dst": "zone:wan",
         "protocol": "tcp", "destination_ports": "19090", "action": "block", "order": 0}
REJECT = dict(BLOCK, name="reject", action="reject")

STAMP = f"meta mark set meta mark | {marks.MARK_TPROXY_AUTH_VALUE:#x} "
GATE = f"meta mark & {marks.MARK_TPROXY_AUTH_VALUE:#x} == 0 return"


def test_single_owner_constant_is_registered_and_collision_free():
    assert marks.MARK_TPROXY_AUTH_MASK == marks.MARK_TPROXY_AUTH_VALUE
    marks.assert_no_collisions(marks.MARK_TPROXY_AUTH_VALUE, marks.Owner.TPROXY)
    # Distinct from the routing mark and the (legacy) packet proof bit.
    assert marks.MARK_TPROXY_AUTH_VALUE & marks.MARK_TPROXY_ROUTE_VALUE == 0
    assert marks.MARK_TPROXY_AUTH_VALUE & marks.MARK_TPROXY_PROOF_VALUE == 0
    assert marks.mark_owners(marks.MARK_TPROXY_AUTH_VALUE) == frozenset({marks.Owner.TPROXY})
    # Foreign claim rejected: the product namespace cannot take the bit.
    with pytest.raises(marks.MarkCollisionError):
        marks.assert_no_collisions(marks.MARK_TPROXY_AUTH_VALUE, marks.Owner.PRODUCT)


def test_preauth_stamps_only_the_authorized_pass_path():
    text = generate_tproxy_preauthorization(_version([BLOCK, ALLOW, REJECT]))
    pass_line = next(l for l in text.splitlines() if 'comment "allow"' in l)
    block_line = next(l for l in text.splitlines() if 'comment "block"' in l)
    reject_line = next(l for l in text.splitlines() if 'comment "reject"' in l)
    assert STAMP in pass_line and pass_line.rstrip().endswith('comment "allow"')
    # Denials drop before capture; they must not carry the gate the capture needs.
    assert STAMP not in block_line and STAMP not in reject_line
    assert pass_line.index("tcp dport 19090") < pass_line.index(STAMP)  # after the match/FIB
    assert pass_line.index(STAMP) < pass_line.index("counter")


def test_preauth_off_and_deny_only_paths_carry_no_gate_mark():
    assert generate_tproxy_preauthorization(_version(enabled=False)) == \
        "destroy table inet vs_router_tproxy_preauth\n"
    empty = generate_tproxy_preauthorization(_version([]))
    assert STAMP not in empty
    assert "mark set" not in empty and "ct mark" not in empty


def test_capture_requires_the_preauth_gate_and_preauth_never_requires_capture():
    capture = generate_tproxy_interception(_version())
    assert GATE in capture
    # The gate is a precondition for the tproxy expressions, not a consequence.
    assert capture.index(GATE) < capture.index("tproxy ip to 127.0.0.1:")
    # Preauth output must not reference the capture tables or the ct proof: the
    # dependency is one-directional (capture -> preauth).
    preauth = generate_tproxy_preauthorization(_version([ALLOW]))
    for token in ("vs_router_tproxy_interception", "vs_router_tproxy_input",
                  "tproxy ip to", "ct mark"):
        assert token not in preauth


def test_off_interception_destroys_only_its_own_tables_without_the_gate():
    off = generate_tproxy_interception(_version(enabled=False))
    assert GATE not in off and STAMP not in off
    assert off == ("destroy table inet vs_router_tproxy_ct_reset\n"
                   "destroy table inet vs_router_tproxy_interception\n"
                   "destroy table inet vs_router_tproxy_input\n")


def test_generators_are_deterministic_about_the_gate():
    for build in (generate_tproxy_preauthorization, generate_tproxy_interception):
        assert build(_version([ALLOW])) == build(_version([ALLOW]))
