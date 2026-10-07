"""Contract tests for the provisional mark/table/hook/port registry.

These tests are host-free: they never touch nftables, policy routing or a
network interface. They only check that the registry is internally consistent,
that the TProxy namespace is separate from the product namespace, that the
validation helpers reject foreign ownership, and that the registered constants
still match the real values found in the product/lab sources.
"""
from pathlib import Path

import pytest

from vs_router.generators import marks
from vs_router.generators.marks import (
    DNS_STUB_PORT,
    MARK_TPROXY_PROOF_VALUE,
    MARK_TPROXY_ROUTE_VALUE,
    PRODUCT_RESERVED_BITS,
    TPROXY_RESERVED_BITS,
    TPROXY_TCP_PORT,
    TPROXY_UDP_PORT,
    MarkCollisionError,
    Owner,
)

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"


# --------------------------------------------------------------------------
# registry self-consistency (no collisions among registered values)
# --------------------------------------------------------------------------

def test_registry_is_consistent():
    marks.assert_registry_consistent()


def test_owned_entries_do_not_overlap_across_owners():
    entries = list(marks.REGISTRY)
    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            if a.owner is not b.owner:
                assert a.mask & b.mask == 0, (a.name, b.name)
            if a.mask & b.mask:
                # Same owner may reuse a bit only with an identical value.
                assert (a.value or 0) == (b.value or 0), (a.name, b.name)


def test_no_wired_table_name_is_reused():
    marks.assert_unique_tables()


def test_no_wired_port_collision():
    marks.assert_unique_ports()


# --------------------------------------------------------------------------
# TProxy space is separate from the product space
# --------------------------------------------------------------------------

def test_namespaces_are_disjoint():
    marks.assert_namespaces_disjoint()


def test_tproxy_claims_stay_inside_tproxy_namespace():
    for entry in marks.REGISTRY:
        if entry.owner is Owner.TPROXY:
            assert entry.mask & PRODUCT_RESERVED_BITS == 0
            assert entry.mask & TPROXY_RESERVED_BITS == entry.mask


def test_route_and_proof_are_distinct_bits():
    assert MARK_TPROXY_ROUTE_VALUE != MARK_TPROXY_PROOF_VALUE
    assert MARK_TPROXY_ROUTE_VALUE & MARK_TPROXY_PROOF_VALUE == 0
    assert marks.MARK_TPROXY_INTERCEPT_PROOF == (
        MARK_TPROXY_ROUTE_VALUE | MARK_TPROXY_PROOF_VALUE)


# --------------------------------------------------------------------------
# validation rejects foreign ownership
# --------------------------------------------------------------------------

def test_accepts_own_route_and_combined_marks():
    marks.assert_no_collisions(MARK_TPROXY_ROUTE_VALUE, Owner.TPROXY)
    marks.assert_no_collisions(marks.MARK_TPROXY_INTERCEPT_PROOF, Owner.TPROXY)


def test_rejects_mark_using_foreign_namespace():
    with pytest.raises(MarkCollisionError):
        marks.assert_no_collisions(MARK_TPROXY_ROUTE_VALUE, Owner.PRODUCT)
    with pytest.raises(MarkCollisionError):
        marks.assert_no_collisions(0x00000001, Owner.TPROXY)


def test_rejects_lab_mark_as_tproxy_claim():
    # 0x123 also sets low-byte bits that belong to the product reservation.
    with pytest.raises(MarkCollisionError):
        marks.assert_no_collisions(0x123, Owner.TPROXY)


def test_rejects_invalid_values_and_owner():
    for bad in (-1, 0x1_0000_0000, "0x100", 1.0):
        with pytest.raises(ValueError):
            marks.assert_no_collisions(bad, Owner.TPROXY)
    with pytest.raises(ValueError):
        marks.assert_no_collisions(0x0, "tproxy")


def test_mark_owners_reports_touched_namespaces():
    assert marks.mark_owners(MARK_TPROXY_ROUTE_VALUE) == frozenset({Owner.TPROXY})
    assert Owner.PRODUCT in marks.mark_owners(0x00000001)


# --------------------------------------------------------------------------
# registry matches values really found in the sources
# --------------------------------------------------------------------------

def test_ports_match_singbox_generator():
    text = (BACKEND / "src/vs_router/generators/singbox.py").read_text()
    assert f'"listen_port": {TPROXY_UDP_PORT}' in text
    assert f'"listen_port": {TPROXY_TCP_PORT}' in text


def test_dns_stub_port_matches_unbound_generator():
    text = (BACKEND / "src/vs_router/generators/unbound.py").read_text()
    assert f"127.0.0.1@{DNS_STUB_PORT}" in text


def test_tables_match_nftables_generator():
    text = (BACKEND / "src/vs_router/generators/nftables.py").read_text()
    for entry in marks.TABLES:
        assert entry.name in text, entry.name


def test_hook_priorities_match_nftables_generator():
    text = (BACKEND / "src/vs_router/generators/nftables.py").read_text()
    numeric = [h for h in marks.HOOKS if isinstance(h.priority, int)]
    # The TProxy experiment priorities are rendered by the generator source.
    for hook in numeric:
        assert f"priority {hook.priority};" in text, hook


def test_reserved_marks_match_lab_probes():
    tcp = (BACKEND / "tests/lab/tproxy_tcp_probe.py").read_text()
    assert f"meta mark set {MARK_TPROXY_ROUTE_VALUE:#x}" in tcp
    assert f"meta mark | {MARK_TPROXY_PROOF_VALUE:#x}" in tcp
    preauth = (BACKEND / "tests/lab/tproxy_preauth_probe.py").read_text()
    assert f"meta mark set {MARK_TPROXY_ROUTE_VALUE:#x}" in preauth


def test_policy_route_matches_lab_probes():
    tcp = (BACKEND / "tests/lab/tproxy_tcp_probe.py").read_text()
    for route in marks.POLICY_ROUTES:
        assert f"'priority', '{route.rule_priority}'" in tcp or (
            f"priority {route.rule_priority}" in tcp)
        assert f"'lookup', '{route.table_id}'" in tcp or (
            f"lookup {route.table_id}" in tcp)
