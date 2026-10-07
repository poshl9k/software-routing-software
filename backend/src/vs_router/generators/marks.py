"""Single registry for nftables marks, tables, hooks, policy routes and ports.

Purpose
-------
The product (``inet vs_router``) and the future sing-box TProxy path both need
to talk about integer namespaces that are *global* to the host: packet marks
(``meta mark`` / ``fwmark``), nftables table names, chain hook priorities,
policy-routing table ids and loopback service ports. Today these values live
scattered across generators, offline TProxy experiments and VM-only lab probes;
nothing guarantees that two owners pick the same bit or port.

This module is the *provisional* ownership registry. It is additive: importing
it changes no generator output, no bundle, no apply/boot path.

.. warning::

   This registry is a naming/reservation contract, **not** a security
   mechanism and **not** proof of safe interception. Specifically:

   * It does **not** replace independent INPUT authorization. Reserving a bit
     does not stop a competing privileged nftables writer from setting or
     clearing it. The proven blocker (``docs/lab-09-tproxy-mark-collision.md``)
     shows that a privileged rule running after the proof reset can forge the
     ``0x200`` proof bit and let established TCP through INPUT. The follow-up
     lab-26 experiment moves INPUT authorization from the forgeable packet
     ``meta mark`` to the per-conntrack ``ct mark`` set only by the interception
     chain; the packet-mark forge of lab-09 no longer reproduces the token.
     See ``docs/lab-26-tproxy-input-authorization.md``.
   * It does **not** solve the prototype problem of mark forgery. ``meta mark``
     observed in INPUT is attacker-controllable by any writer that runs earlier
     in the packet path; a bit can only ever be treated as a *hint*, never as
     unforgeable proof. The conntrack-mark design removes the packet-mark forge
     but not a privileged writer of ``ct mark`` (``ct mark set ct mark | 0x200``):
     unforgeability against a competing root nftables writer is impossible in
     principle. The honest trust boundary is a **single writer** of the
     mark/table/hook space (the router's own privileged apply path); ownership of
     that space is the real requirement, not the mark value itself.
   * It is **not** evidence that TProxy is ready. The public gate
     ``tproxy.not_available`` stays closed; the packet-path proof on a
     disposable VM is still outstanding.

Honesty note
------------
Within the *offline* TProxy generators (not wired to any bundle/apply/boot and
unreachable while the public gate stays closed) the capture now really emits the
routing packet mark ``0x100`` and the conntrack proof bit ``0x200``
(``generate_tproxy_interception``, lab-27/lab-29). The product firewall
(``generate_nftables``) still emits no ``meta mark``/``fwmark``/``ip rule``. The
TProxy entries below remain a reservation of a still-unproven path, and the
product namespace is an explicit reservation with no concrete value yet.
Nothing here invents a product mark.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# --------------------------------------------------------------------------
# Integer safety
# --------------------------------------------------------------------------

MARK_MAX = 0xFFFFFFFF
"""Packet marks are 32-bit unsigned on Linux; reject anything else."""


class MarkCollisionError(ValueError):
    """A mark value crosses a namespace owned by a different owner."""


class Owner(str, Enum):
    """Who owns an integer namespace."""

    PRODUCT = "product"   # inet vs_router generator and router services
    TPROXY = "tproxy"     # future sing-box TProxy interception path
    LAB = "lab"           # VM-only experiments; never authoritative


# --------------------------------------------------------------------------
# Mark namespaces and concrete values
# --------------------------------------------------------------------------
#
# Layout of the 32-bit mark (bits are exclusive per owner):
#
#   bits  0..7   (mask 0x000000FF)  reserved for the router / non-TProxy writers
#   bit   8      (mask 0x00000100)  TProxy routing mark        (0x100)
#   bit   9      (mask 0x00000200)  TProxy "proof" bit         (0x200)
#   bits 10..11  (within 0x00000F00) reserved spare for TProxy
#
# No concrete product mark is emitted today; PRODUCT keeps the low byte as a
# pure reservation so a TProxy claim can never silently steal bit 0..7.

#: Whole byte reserved for the TProxy path (bits 8..11).
TPROXY_RESERVED_BITS = 0x00000F00
#: Whole byte reserved for the router / non-TProxy owners (bits 0..7).
PRODUCT_RESERVED_BITS = 0x000000FF

#: Routing mark used by the (VM-only, unproven) TProxy path.
MARK_TPROXY_ROUTE_MASK = 0x00000100
MARK_TPROXY_ROUTE_VALUE = 0x00000100
#: "Proof" bit, set after a successful TProxy expression in the lab probe.
#: Forgeable: a competing privileged writer can set it; see module warning.
MARK_TPROXY_PROOF_MASK = 0x00000200
MARK_TPROXY_PROOF_VALUE = 0x00000200
#: Combined interception+proof mark observed as 0x300 in the lab probe.
MARK_TPROXY_INTERCEPT_PROOF = MARK_TPROXY_ROUTE_VALUE | MARK_TPROXY_PROOF_VALUE

#: Mask that clears exactly the proof bit (lab reset hook, PREROUTING -85).
MARK_TPROXY_PROOF_CLEAR_MASK = ~MARK_TPROXY_PROOF_MASK & MARK_MAX

#: Conntrack-mark proof bit (lab-26). This lives in the *conntrack* mark
#: namespace (``nf_conntrack``'s mark), which is a different 32-bit space from
#: the packet ``meta mark``. The interception chain sets it after a successful
#: TProxy; the per-packet reset clears it; the INPUT guard authorizes only on it.
#: A rule that forges the packet ``meta mark`` (the lab-09 injector) does not
#: touch it. It is deliberately NOT listed in ``REGISTRY`` because that registry
#: describes the packet-mark namespace, and it is NOT unforgeable against a
#: privileged writer of ``ct mark`` -- see the module warning.
MARK_TPROXY_CT_PROOF_MASK = 0x00000200
MARK_TPROXY_CT_PROOF_VALUE = 0x00000200
MARK_TPROXY_CT_PROOF_CLEAR_MASK = ~MARK_TPROXY_CT_PROOF_MASK & MARK_MAX

#: Preauthorization *capture gate* (lab-31). A packet mark set by
#: ``generate_tproxy_preauthorization`` on authorized selected transit and
#: required by ``generate_tproxy_interception`` capture. Coupling capture to a
#: live preauth table makes the loss of preauth fail-closed: without the mark the
#: capture rule returns, the packet stays on the ordinary FORWARD path and the
#: independent containment (``FORWARD -10``) / default-deny hold it, instead of
#: being diverted into LOCAL_IN -> proxy with no policy enforcement.
#:
#: This is a *packet* mark (routing/capture control), kept deliberately separate
#: from the conntrack INPUT-authorization space so lab-26/lab-29 semantics are
#: unchanged. Like every mark it is a single-writer naming contract, not an
#: unforgeable security bit (ADR-0013).
MARK_TPROXY_AUTH_MASK = 0x00000400
MARK_TPROXY_AUTH_VALUE = 0x00000400


@dataclass(frozen=True)
class MarkEntry:
    """One owner claim on a bit range of the 32-bit mark."""

    owner: Owner
    mask: int
    value: int | None
    name: str
    source: str
    note: str = ""


#: Authoritative owned entries. Must stay mutually collision-free across owners.
REGISTRY: tuple[MarkEntry, ...] = (
    MarkEntry(
        owner=Owner.PRODUCT,
        mask=PRODUCT_RESERVED_BITS,
        value=None,  # pure reservation; no product mark is emitted yet
        name="product_reserved_bits_0_7",
        source="design reservation (no product mark emitted today)",
        note="Keeps non-TProxy writers out of the TProxy bit range and vice versa.",
    ),
    MarkEntry(
        owner=Owner.TPROXY,
        mask=MARK_TPROXY_ROUTE_MASK,
        value=MARK_TPROXY_ROUTE_VALUE,
        name="tproxy_route_mark",
        source=(
            "backend/tests/lab/tproxy_tcp_probe.py:162,184; "
            "backend/tests/lab/tproxy_preauth_probe.py:157; "
            "backend/tests/lab/tproxy_udp_uid_probe.py:38"
        ),
        note="No production generator sets this today; reserved for TProxy.",
    ),
    MarkEntry(
        owner=Owner.TPROXY,
        mask=MARK_TPROXY_PROOF_MASK,
        value=MARK_TPROXY_PROOF_VALUE,
        name="tproxy_proof_bit",
        source=(
            "backend/tests/lab/tproxy_tcp_probe.py:184,194,205; "
            "docs/lab-09-tproxy-mark-collision.md"
        ),
        note="FORGEABLE. A competing privileged nft writer can set it; see module warning.",
    ),
    MarkEntry(
        owner=Owner.TPROXY,
        mask=MARK_TPROXY_AUTH_MASK,
        value=MARK_TPROXY_AUTH_VALUE,
        name="tproxy_preauth_capture_gate",
        source=(
            "generators/nftables.py:generate_tproxy_preauthorization/"
            "generate_tproxy_interception; docs/lab-31-tproxy-preauth-independence.md"
        ),
        note=(
            "Set by preauth on authorized selected transit, required by capture: "
            "losing preauth removes the mark, disables capture and fails closed at "
            "the independent containment/default-deny. Single-writer contract, not "
            "an unforgeable bit."
        ),
    ),
)

#: VM-only lab marks that really exist in the tree. NOT owned, NOT product.
#: They are recorded so the registry can flag that a lab value overlaps the
#: reserved TProxy range (0x123 shares bit 8 with the TProxy route mark).
OBSERVED_LAB_MARKS: tuple[MarkEntry, ...] = (
    MarkEntry(
        owner=Owner.LAB,
        mask=0x000000FF,  # low byte; 0x123 also sets bit 8 below
        value=0x00000023,
        name="lab05_fwmark_0x123_low_byte",
        source="docs/lab-05-singbox-tproxy.md:9",
        note="VM-only policy-route fwmark; overlaps the reserved TProxy bit 8.",
    ),
    MarkEntry(
        owner=Owner.LAB,
        mask=MARK_TPROXY_ROUTE_MASK,
        value=MARK_TPROXY_ROUTE_VALUE,
        name="lab05_fwmark_0x123_route_bit",
        source="docs/lab-05-singbox-tproxy.md:9",
        note="The bit-8 part of the lab 0x123 value; collides with TProxy route mark.",
    ),
)


# --------------------------------------------------------------------------
# nftables tables
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NftTable:
    name: str          # canonical "family table" string
    purpose: str
    source: str
    wired: bool        # True if reachable from bundle/apply


PRODUCT_TABLE = "inet vs_router"

TABLES: tuple[NftTable, ...] = (
    NftTable(PRODUCT_TABLE, "product filter/nat", "generators/nftables.py:99", True),
    NftTable("inet vs_router_tproxy_guard", "offline containment",
             "generators/nftables.py:177", False),
    NftTable("inet vs_router_tproxy_ipv6_guard", "offline IPv6 WAN-escape guard",
             "generators/nftables.py:generate_tproxy_ipv6_guard", False),
    NftTable("inet vs_router_tproxy_preauth", "offline pre-authorization",
             "generators/nftables.py:310", False),
    NftTable("inet vs_router_tproxy_interception", "offline TProxy capture",
             "generators/nftables.py:generate_tproxy_interception", False),
    NftTable("inet vs_router_tproxy_ct_reset", "offline TProxy ct-mark reset",
             "generators/nftables.py:generate_tproxy_interception", False),
    NftTable("inet vs_router_tproxy_input", "offline TProxy INPUT guard",
             "generators/nftables.py:generate_tproxy_interception", False),
    NftTable("inet vs_router_tproxy_dns_ingress", "offline DNS ingress guard",
             "generators/nftables.py:202", False),
    NftTable("inet vs_router_tproxy_dns_listener", "offline DNS listener boundary",
             "generators/nftables.py:234", False),
    NftTable("inet vs_router_tproxy_dns_output", "offline DNS OUTPUT boundary",
             "generators/nftables.py:261", False),
)


# --------------------------------------------------------------------------
# hook priorities
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HookPriority:
    table: str
    chain: str
    hook: str
    priority: int | str
    source: str


HOOKS: tuple[HookPriority, ...] = (
    HookPriority(PRODUCT_TABLE, "input", "input", "filter", "generators/nftables.py:103"),
    HookPriority(PRODUCT_TABLE, "forward", "forward", "filter", "generators/nftables.py:103"),
    HookPriority(PRODUCT_TABLE, "prerouting", "prerouting", "dstnat", "generators/nftables.py:148"),
    HookPriority(PRODUCT_TABLE, "postrouting", "postrouting", "srcnat", "generators/nftables.py:153"),
    HookPriority("inet vs_router_tproxy_guard", "forward", "forward", -10,
                 "generators/nftables.py:189"),
    HookPriority("inet vs_router_tproxy_ipv6_guard", "forward", "forward", -11,
                 "generators/nftables.py:generate_tproxy_ipv6_guard"),
    HookPriority("inet vs_router_tproxy_preauth", "prerouting", "prerouting", -90,
                 "generators/nftables.py:330"),
    HookPriority("inet vs_router_tproxy_interception", "prerouting", "prerouting", -80,
                 "generators/nftables.py:generate_tproxy_interception"),
    HookPriority("inet vs_router_tproxy_ct_reset", "prerouting", "prerouting", -85,
                 "generators/nftables.py:generate_tproxy_interception"),
    HookPriority("inet vs_router_tproxy_input", "input", "input", -20,
                 "generators/nftables.py:generate_tproxy_interception"),
    HookPriority("inet vs_router_tproxy_dns_ingress", "prerouting", "prerouting", -110,
                 "generators/nftables.py:218"),
    HookPriority("inet vs_router_tproxy_dns_listener", "input", "input", -10,
                 "generators/nftables.py:243"),
    HookPriority("inet vs_router_tproxy_dns_output", "output", "output", -20,
                 "generators/nftables.py:271"),
)


# --------------------------------------------------------------------------
# policy routing
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyRoute:
    table_id: int
    rule_priority: int
    fwmark: int
    source: str
    wired: bool


POLICY_ROUTES: tuple[PolicyRoute, ...] = (
    PolicyRoute(
        table_id=100,
        rule_priority=100,
        fwmark=MARK_TPROXY_ROUTE_VALUE,
        source=(
            "backend/tests/lab/tproxy_tcp_probe.py:325; "
            "backend/tests/lab/tproxy_preauth_probe.py:169; "
            "backend/tests/lab/tproxy_udp_uid_probe.py:200"
        ),
        wired=False,
    ),
)


# --------------------------------------------------------------------------
# ports
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PortClaim:
    port: int
    proto: str        # "tcp", "udp" or "tcp/udp"
    purpose: str
    source: str
    wired: bool


TPROXY_TCP_PORT = 51272
TPROXY_UDP_PORT = 51271
DNS_STUB_PORT = 15353

PORTS: tuple[PortClaim, ...] = (
    PortClaim(TPROXY_UDP_PORT, "udp", "sing-box TProxy UDP inbound (127.0.0.1)",
              "generators/singbox.py:26", True),
    PortClaim(TPROXY_TCP_PORT, "tcp", "sing-box TProxy TCP inbound (127.0.0.1)",
              "generators/singbox.py:28", True),
    PortClaim(DNS_STUB_PORT, "tcp/udp", "loopback DNS stub (selected Unbound)",
              "generators/unbound.py:86", False),
)


# --------------------------------------------------------------------------
# validation helpers
# --------------------------------------------------------------------------


def _validate_mark(mark: int) -> None:
    if type(mark) is not int or not 0 <= mark <= MARK_MAX:
        raise ValueError("marks.invalid_value")


def mark_owners(mark: int) -> frozenset[Owner]:
    """Return the set of owners whose reserved bits ``mark`` touches."""
    _validate_mark(mark)
    return frozenset(entry.owner for entry in REGISTRY if mark & entry.mask)


def assert_no_collisions(mark: int, owner: Owner) -> None:
    """Fail if ``mark`` crosses an owner's namespace or misuses its own.

    ``owner`` is the caller claiming the mark. Raises ``MarkCollisionError`` if:

    * any set bit falls inside another owner's mask (foreign namespace), or
    * a bit falls inside ``owner``'s mask with a value other than the one the
      registry reserves for it (unregistered value in an owned mask).

    Unclaimed bits (outside every mask) are allowed but should be avoided.
    """
    _validate_mark(mark)
    if not isinstance(owner, Owner):
        raise ValueError("marks.invalid_owner")
    for entry in REGISTRY:
        overlap = mark & entry.mask
        if not overlap:
            continue
        if entry.owner is not owner:
            raise MarkCollisionError(
                f"mark 0x{mark:x} uses {entry.owner.value}-owned bits "
                f"'{entry.name}' (mask 0x{entry.mask:x})"
            )
        if entry.value is not None and overlap != (entry.value & entry.mask):
            raise MarkCollisionError(
                f"mark 0x{mark:x} sets unregistered value in own mask "
                f"'{entry.name}' (expected 0x{entry.value & entry.mask:x})"
            )


def assert_registry_consistent() -> None:
    """Fail if the owned registry is self-inconsistent.

    Checks: each entry fits 32 bits, carries its value inside its mask, and no
    two entries of *different* owners overlap.
    """
    for entry in REGISTRY:
        if not 0 <= entry.mask <= MARK_MAX:
            raise ValueError(f"registry.bad_mask:{entry.name}")
        if entry.value is not None and not 0 <= entry.value <= MARK_MAX:
            raise ValueError(f"registry.bad_value:{entry.name}")
        if entry.value is not None and (entry.value & entry.mask) != entry.value:
            raise ValueError(f"registry.value_outside_mask:{entry.name}")
    entries = list(REGISTRY)
    for i, a in enumerate(entries):
        for b in entries[i + 1:]:
            if a.owner is not b.owner and (a.mask & b.mask):
                raise ValueError(
                    f"registry.owner_overlap:{a.name}/{b.name}"
                )


def assert_namespaces_disjoint() -> None:
    """Fail if the reserved PRODUCT and TPROXY byte namespaces overlap."""
    if PRODUCT_RESERVED_BITS & TPROXY_RESERVED_BITS:
        raise ValueError("registry.namespace_overlap")
    if not (MARK_TPROXY_ROUTE_MASK | MARK_TPROXY_PROOF_MASK) & TPROXY_RESERVED_BITS:
        raise ValueError("registry.tproxy_bits_outside_namespace")


def assert_unique_tables() -> None:
    """Fail if two registered nftables tables share a name."""
    root = [t.name for t in TABLES]
    if len(root) != len(set(root)):
        raise ValueError("registry.duplicate_table")


def assert_unique_ports() -> None:
    """Fail if two wired claims collide on the same port and protocol."""
    seen: set[tuple[int, str]] = set()
    for claim in PORTS:
        if not claim.wired:
            continue
        key = (claim.port, claim.proto)
        if key in seen:
            raise ValueError(f"registry.duplicate_port:{claim.port}/{claim.proto}")
        seen.add(key)


def registry_map() -> dict[str, int | None]:
    """Return a convenience name -> value view of the owned mark registry."""
    return {entry.name: entry.value for entry in REGISTRY}
