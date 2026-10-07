"""Offline TProxy DNS contour planner: composition over existing generators.

This module is *additive orchestration only*. It renders nothing new: every
Unbound text and nftables table it returns comes byte-for-byte from the
existing offline generators in :mod:`.unbound` and :mod:`.nftables`. Its job is
to make the intended contour explicit in one place — which listeners the
selected and ordinary resolvers bind, which nft guard tables exist, their
hook/priority and their install order, the selected resolver UID — and to carry
an explicit list of what is **not** proven.

Warnings
--------
This is a plan, not a proof. Nothing here starts a service, installs a process
or packet-classifies a client. ``tproxy.enabled=True`` is still rejected by the
public gate ``tproxy.not_available`` in :func:`validators.validate_configuration`;
a plan is only reachable from an offline ``model_copy`` snapshot exactly like the
underlying generators. See ``docs/tproxy-dns-policy-plan.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import ConfigurationVersion
from . import marks
from .nftables import (generate_tproxy_dns_ingress_guard,
                       generate_tproxy_dns_listener_guard,
                       generate_tproxy_dns_output_guard)
from .unbound import (generate_tproxy_unbound_split,
                      tproxy_unbound_listener_addresses)

#: Canonical guard table names (must match the generators and marks registry).
INGRESS_TABLE = "inet vs_router_tproxy_dns_ingress"
LISTENER_TABLE = "inet vs_router_tproxy_dns_listener"
OUTPUT_TABLE = "inet vs_router_tproxy_dns_output"

#: Install / evaluation order of the guard tables. A selected client query hits
#: the PREROUTING ingress guard, then the INPUT listener boundary; the resolver's
#: own sockets hit the OUTPUT boundary. Kept as one ordered contract so a
#: consumer cannot silently reorder the contour.
GUARD_ORDER = ("ingress", "listener", "output")

_GUARD_TABLES = {
    "ingress": INGRESS_TABLE,
    "listener": LISTENER_TABLE,
    "output": OUTPUT_TABLE,
}

#: Hook/priority are sourced from the shared :mod:`.marks` registry so the plan
#: and the ownership registry cannot drift apart.
_HOOKS = {(h.table, h.chain): h for h in marks.HOOKS}

#: Deterministic, reserved UID of the *selected* resolver process. The public
#: schema has no field for it yet, so the contour must take it from this single
#: committed value rather than let each consumer invent a literal. It is plan
#: data only: this module creates no user, process or service. ``29092`` is the
#: value the VM probes (lab-18..23) and the OUTPUT guard's own validator
#: (``100..65535``) use.
TPROXY_SELECTED_UID = 29092


def selected_uid_for(version: ConfigurationVersion) -> int | None:
    """Deterministic selected-resolver UID, or ``None`` while the contour is off.

    Listener addresses come from the configuration through
    :func:`tproxy_unbound_listener_addresses`; the UID has no schema field yet,
    so it is the reserved constant above. Both feed :func:`plan_tproxy_dns`, so
    the resolver configs and the guard tables cannot disagree about the contour.
    """
    return TPROXY_SELECTED_UID if version.configuration.tproxy.enabled else None


@dataclass(frozen=True)
class TProxyDnsGuard:
    """One nftables guard table in the contour."""

    role: str          # "ingress" | "listener" | "output"
    table: str
    hook: str          # nft hook name, e.g. "prerouting"
    chain: str         # chain name inside the table
    priority: int      # signed hook priority
    content: str       # rendered table text from the existing generator


@dataclass(frozen=True)
class TProxyDnsPlan:
    """Structured offline plan for the TProxy DNS source-boundary contour.

    ``enabled=False`` means "everything off": the only actionable output is
    removing this contour's own tables; resolver configs are ``None``.
    """

    enabled: bool
    selected_uid: int | None
    selected_unbound: str | None
    ordinary_unbound: str | None
    listener_addresses: dict[str, tuple[str, ...]] = field(default_factory=dict)
    nft_guards: tuple[TProxyDnsGuard, ...] = ()
    warnings: tuple[str, ...] = ()


#: Explicit, non-exhaustive list of what this planner does NOT prove.
WARNINGS: tuple[str, ...] = (
    "plan only: no service, process, UID or nft rule is installed by this module",
    "real sing-box DNS is not generated, resolved or classified by source",
    "Unbound service lifecycle, privileges and crash/restart recovery are absent",
    "explicit forward exception is address-scoped, not QNAME-scoped",
    "cache-max-ttl: 0 covers sequential replays, not parallel in-flight queries",
    "IPv6 listeners and upstreams are unsupported by the split",
    "DoH/DoT and encrypted upstream transports are out of scope",
    "public gate tproxy.not_available stays closed; this is not enablement",
)


def _hook(role: str) -> tuple[str, str, int]:
    table = _GUARD_TABLES[role]
    for chain in ("prerouting", "input", "output"):
        entry = _HOOKS.get((table, chain))
        if entry is not None:
            if not isinstance(entry.priority, int):
                raise ValueError(f"tproxy.dns_plan_nonint_priority:{table}")
            return entry.hook, entry.chain, entry.priority
    raise ValueError(f"tproxy.dns_plan_unregistered_guard:{table}")


def _valid_uid(uid: object) -> bool:
    return type(uid) is int and 100 <= uid <= 65535


def plan_tproxy_dns(version: ConfigurationVersion, selected_uid: int | None) -> TProxyDnsPlan:
    """Compose the offline TProxy DNS contour from the existing generators.

    Reuses :func:`generate_tproxy_unbound_split`,
    :func:`tproxy_unbound_listener_addresses` and the three ``*_dns_*_guard``
    generators. Never re-validates ``tproxy.enabled`` (the public gate already
    rejects it); an enabled plan is only reachable through an offline snapshot.

    Raises ``ValueError('tproxy.dns_output_invalid_uid')`` if an enabled plan is
    requested without a valid selected UID, or if a provided UID is invalid.
    """
    enabled = version.configuration.tproxy.enabled

    if selected_uid is not None and not _valid_uid(selected_uid):
        raise ValueError("tproxy.dns_output_invalid_uid")
    if enabled and not _valid_uid(selected_uid):
        raise ValueError("tproxy.dns_output_invalid_uid")
    # Disabled plan ignores the UID; the disabled generator returns a destroy-only
    # table before it inspects the value, so a placeholder int is safe here.
    out_uid = selected_uid if selected_uid is not None else 0

    guards = (
        TProxyDnsGuard("ingress", INGRESS_TABLE, *_hook("ingress"),
                       generate_tproxy_dns_ingress_guard(version)),
        TProxyDnsGuard("listener", LISTENER_TABLE, *_hook("listener"),
                       generate_tproxy_dns_listener_guard(version)),
        TProxyDnsGuard("output", OUTPUT_TABLE, *_hook("output"),
                       generate_tproxy_dns_output_guard(version, out_uid)),
    )

    if not enabled:
        return TProxyDnsPlan(
            enabled=False,
            selected_uid=None,
            selected_unbound=None,
            ordinary_unbound=None,
            listener_addresses={},
            nft_guards=guards,
            warnings=WARNINGS,
        )

    if not _valid_uid(selected_uid):
        raise ValueError("tproxy.dns_output_invalid_uid")

    listeners = tproxy_unbound_listener_addresses(version)
    split = generate_tproxy_unbound_split(version)
    return TProxyDnsPlan(
        enabled=True,
        selected_uid=selected_uid,
        selected_unbound=split["selected"],
        ordinary_unbound=split["ordinary"],
        listener_addresses=dict(listeners),
        nft_guards=guards,
        warnings=WARNINGS,
    )
