"""Typed policy-route adapter for the TProxy capture mark.

The loader observes the owned rule and route before changing them. Healthy
entries stay live across repeated applies; only missing entries are added.
Ambiguous/conflicting state fails closed rather than deleting an entry that may
belong to another writer.
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


def _route_table_aliases(table_id: int) -> set[str]:
    """Return exact iproute2 names for ``table_id``; malformed rows are ignored."""
    aliases = {str(table_id)}
    for path in ("/usr/lib/iproute2/rt_tables", "/etc/iproute2/rt_tables"):
        try:
            with open(path, encoding="utf-8") as registry:
                for raw in registry:
                    fields = raw.split("#", 1)[0].split()
                    if len(fields) != 2:
                        continue
                    number, name = fields
                    if number.isdecimal() and int(number) == table_id:
                        if name and not any(char in _FORBIDDEN for char in name):
                            aliases.add(name)
        except OSError:
            continue
    return aliases


def _rule_state(output: str, route: marks.PolicyRoute) -> bool:
    """Recognize one exact owned rule; reject ambiguity in its priority slot."""
    aliases = _route_table_aliases(route.table_id)
    mark_forms = {f"{route.fwmark:#x}", f"{route.fwmark:#x}/0xffffffff"}
    found = 0
    for raw in output.splitlines():
        fields = raw.split()
        if not fields or fields[0] != f"{route.rule_priority}:":
            continue
        exact = (len(fields) == 7 and fields[1:4] == ["from", "all", "fwmark"]
                 and fields[4] in mark_forms and fields[5] == "lookup"
                 and fields[6] in aliases)
        if not exact:
            raise ApplyError("agent.reload_failed")
        found += 1
    if found > 1:
        # Repeated identical lines cannot be removed one-at-a-time without a
        # transient gap, nor distinguished from another writer's duplicate.
        raise ApplyError("agent.reload_failed")
    return found == 1


def _route_state(output: str) -> bool:
    """Recognize the sole semantic rendering of our local default route."""
    lines = [line.split() for line in output.splitlines() if line.split()]
    if not lines:
        return False
    exact = (["local", "default", "dev", "lo", "scope", "host"],
             ["local", "0.0.0.0/0", "dev", "lo", "scope", "host"])
    if len(lines) == 1 and lines[0] in exact:
        return True
    # Table is owned, but arbitrary routes cannot safely be attributed or
    # reconstructed from host-rendered tokens. Never delete them blindly.
    raise ApplyError("agent.reload_failed")


class PolicyRouteLoader:
    """Executor-backed, idempotent application of the owned policy route."""

    def __init__(self, executor):
        self.executor = executor

    def _result(self, argv: tuple[str, ...]):
        result = self.executor.run(list(argv), 15)
        if result.returncode:
            raise ApplyError("agent.reload_failed")
        return result

    def _run(self, argv: tuple[str, ...]) -> int:
        return self.executor.run(list(argv), 15).returncode

    def apply(self) -> None:
        """Install only absent entries; never interrupt a healthy peer entry."""
        # Build and validate every mutation before observing or changing host
        # state. A malformed ownership registry therefore causes zero commands.
        add_rule, add_route = commands("add")
        route = marks.POLICY_ROUTES[0]
        rule_probe = ("ip", "-4", "rule", "show")
        route_probe = ("ip", "-4", "route", "show", "table", str(route.table_id))

        rule_result = self._result(rule_probe)
        route_result = self.executor.run(list(route_probe), 15)
        if route_result.returncode:
            # iproute2 exits 2 when a never-used table has no FIB; this is a
            # normal first-apply state, not a failed health probe.
            error = getattr(route_result, "stderr", b"") or b""
            if isinstance(error, bytes):
                error = error.decode("utf-8", "replace")
            if not (route_result.returncode == 2 and
                    "FIB table does not exist" in error and
                    not getattr(route_result, "stdout", None)):
                raise ApplyError("agent.reload_failed")
        rule_output = getattr(rule_result, "stdout", "") or ""
        route_output = getattr(route_result, "stdout", "") or ""
        if isinstance(rule_output, bytes):
            rule_output = rule_output.decode("utf-8", "replace")
        if isinstance(route_output, bytes):
            route_output = route_output.decode("utf-8", "replace")
        rule_present = _rule_state(rule_output, route)
        route_present = _route_state(route_output)

        # Route first: until rule exists it is inert. Installing rule first can
        # steer marked packets into an empty table between the two commands.
        for present, argv in ((route_present, add_route),
                              (rule_present, add_rule)):
            if not present:
                self._result(argv)

    add = apply

    def remove(self) -> None:
        """Remove the owned rule+route; a missing entry is not an error."""
        for argv in commands("del"):
            self._run(argv)

    teardown = remove

    def __call__(self) -> None:
        self.apply()
