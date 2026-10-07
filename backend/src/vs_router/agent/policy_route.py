"""Typed policy-route adapter for the TProxy capture mark.

The TProxy capture path steers marked packets into a dedicated loopback routing
table (``ip rule ... fwmark ... lookup N``) and makes them deliverable to the
loopback TProxy listeners (``ip route add local 0.0.0.0/0 dev lo table N``).
This module is the *only* place the agent turns that into a process invocation.

Safety
------
* Every argument is a fixed keyword or an integer rendered from the single
  ownership registry (:data:`generators.marks.POLICY_ROUTES`). No caller-supplied
  string ever reaches ``argv``; ``argv`` is passed as a list, never a shell.
* The registry values are re-validated (int type, range, TProxy mark namespace)
  before any command is built, so a corrupted registry fails closed with a
  ``ValueError`` instead of emitting a malformed rule.
* A defence-in-depth token check rejects any argument that is not a fixed
  keyword/integer (nothing is ever "repaired").
* The loader is idempotent: it removes exactly the owned entries (a missing
  entry is not an error) and then adds them, so a repeated apply converges to
  one rule and one route.
"""
from __future__ import annotations

from .apply import ApplyError
from ..generators import marks
from ..generators.nftables import tproxy_policy_route_commands

#: Maximum value accepted for an ``ip rule`` priority / routing-table id.
_U32_MAX = 0xFFFFFFFF

#: Characters that must never appear in a generated argument. The argv is built
#: from keywords and integers only; a violation is a hard error.
_FORBIDDEN = set(" \t\r\n;|&$`<>*?\"'\\(){}[]")


def _check_token(token: object) -> None:
    if type(token) is int:
        return
    if not isinstance(token, str) or not token:
        raise ValueError("tproxy.policy_route_token")
    if any(char in _FORBIDDEN for char in token):
        raise ValueError("tproxy.policy_route_token")


def _validate_route(route: marks.PolicyRoute) -> None:
    if type(route.table_id) is not int or not 1 <= route.table_id <= _U32_MAX:
        raise ValueError("tproxy.policy_route_table")
    if type(route.rule_priority) is not int or not 0 <= route.rule_priority <= _U32_MAX:
        raise ValueError("tproxy.policy_route_priority")
    if type(route.fwmark) is not int or not 0 <= route.fwmark <= marks.MARK_MAX:
        raise ValueError("tproxy.policy_route_fwmark")
    # The routing mark must stay inside the TProxy namespace; a collision means
    # the registry itself is inconsistent and the rule is unsafe to install.
    marks.assert_no_collisions(route.fwmark, marks.Owner.TPROXY)


def commands(action: str = "add") -> tuple[tuple[str, ...], ...]:
    """Return the owned, validated ``ip rule``/``ip route`` argv for ``action``.

    ``action`` is ``"add"`` or ``"del"``. Fails closed (``ValueError``) on an
    unknown action, a malformed registry entry or an argument that is not a
    fixed keyword/integer.
    """
    if action not in ("add", "del"):
        raise ValueError("tproxy.policy_route_action")
    if not marks.POLICY_ROUTES:
        raise ValueError("tproxy.policy_route_missing")
    for route in marks.POLICY_ROUTES:
        _validate_route(route)
    built = tproxy_policy_route_commands(action)
    for argv in built:
        for token in argv:
            _check_token(token)
    return tuple(tuple(argv) for argv in built)


class PolicyRouteLoader:
    """Executor-backed, idempotent application of the owned policy route."""

    def __init__(self, executor):
        self.executor = executor

    def _run(self, argv: tuple[str, ...]) -> int:
        return self.executor.run(list(argv), 15).returncode

    def apply(self) -> None:
        """Idempotently install the owned rule+route.

        Delete first (a missing entry is not an error), then add: this converges
        to exactly one owned rule and route even if a previous apply was
        interrupted. A failing ``add`` is a hard ``agent.reload_failed``.
        """
        for argv in commands("del"):
            self._run(argv)
        for argv in commands("add"):
            if self._run(argv):
                raise ApplyError("agent.reload_failed")

    add = apply

    def remove(self) -> None:
        """Remove the owned rule+route; a missing entry is not an error."""
        for argv in commands("del"):
            self._run(argv)

    teardown = remove

    def __call__(self) -> None:
        self.apply()
