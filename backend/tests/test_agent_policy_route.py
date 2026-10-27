"""Typed policy-route loader: fixed argv, no injection, idempotency, removal.

No shell, no systemd and no live ``ip``: the adapter runs through the injected
``FakeExecutor`` and its argv is checked token by token.
"""
from types import SimpleNamespace

import pytest

from vs_router.agent import policy_route
from vs_router.agent.apply import ApplyError
from vs_router.generators import marks
from vs_router.generators.nftables import tproxy_policy_route_commands


def test_argv_is_fixed_keywords_and_ints_from_the_registry():
    route = marks.POLICY_ROUTES[0]
    add = policy_route.commands("add")
    assert add == tproxy_policy_route_commands("add")  # single source of truth
    assert add == policy_route.commands()              # add is the default
    rule, local = add
    assert rule[:3] == ("ip", "rule", "add")
    assert rule[3:7] == ("priority", str(route.rule_priority),
                         "fwmark", f"{route.fwmark:#x}")
    assert rule[7:] == ("lookup", str(route.table_id))
    assert local == ("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo",
                     "table", str(route.table_id))
    # Every argument is a fixed keyword or a plain integer string: nothing
    # caller-supplied, no whitespace and no shell metacharacters.
    forbidden = set(" \t;|&$`<>*?\"'\\(){}[]")
    for argv in add:
        for token in argv:
            assert isinstance(token, str) and token
            assert not (set(token) & forbidden)


def test_del_is_the_exact_inverse_of_add():
    add = policy_route.commands("add")
    assert policy_route.commands("del") == tuple(
        tuple("del" if part == "add" else part for part in argv) for argv in add)


def test_unknown_action_is_rejected():
    with pytest.raises(ValueError, match="tproxy.policy_route_action"):
        policy_route.commands("flush")


def test_non_integer_registry_entry_fails_closed(monkeypatch):
    # A tampered/typed-wrong registry value must never reach argv.
    bad = SimpleNamespace(table_id=100, rule_priority=100,
                          fwmark="0x100; rm -rf /")
    monkeypatch.setattr(marks, "POLICY_ROUTES", (bad,))
    with pytest.raises(ValueError, match="tproxy.policy_route_fwmark"):
        policy_route.commands("add")


class PolicyStateExecutor:
    """Fake ``ip`` state: probes render kernel-like text, mutations update it."""

    def __init__(self, *, rules=(), routes=(), fail=()):
        self.rules = list(rules)
        self.routes = list(routes)
        self.fail = {tuple(argv) for argv in fail}
        self.calls = []

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        key = tuple(argv)
        if key in self.fail:
            return SimpleNamespace(returncode=1, stdout="")
        if argv == ["ip", "-4", "rule", "show"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(self.rules) + "\n")
        if argv == ["ip", "-4", "route", "show", "table", "100"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(self.routes) + "\n")
        if argv[:3] == ["ip", "rule", "add"]:
            self.rules.append("100: from all fwmark 0x100 lookup 100")
        elif argv[:3] == ["ip", "route", "add"]:
            self.routes.append("local default dev lo scope host")
        elif argv[:3] == ["ip", "rule", "del"]:
            self.rules = [line for line in self.rules if line !=
                          "100: from all fwmark 0x100 lookup 100"]
        elif argv[:3] == ["ip", "route", "del"]:
            self.routes = [line for line in self.routes if line !=
                           "local default dev lo scope host"]
        return SimpleNamespace(returncode=0, stdout="")


def _mutations(executor):
    return [argv for argv, _ in executor.calls if "add" in argv or "del" in argv]


def test_loader_exact_state_is_noop_including_rendered_mask_and_alias(monkeypatch):
    route = marks.POLICY_ROUTES[0]
    monkeypatch.setattr(policy_route, "_route_table_aliases",
                        lambda table_id: {str(table_id), "vs_tproxy"})
    executor = PolicyStateExecutor(
        rules=(f"{route.rule_priority}: from all fwmark {route.fwmark:#x}/0xffffffff "
               "lookup vs_tproxy",),
        routes=("local default dev lo scope host",),
    )

    policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == []
    assert executor.rules and executor.routes


def test_loader_installs_route_before_rule_when_both_are_missing():
    add_rule, add_route = [list(argv) for argv in policy_route.commands("add")]
    executor = PolicyStateExecutor()

    policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == [add_route, add_rule]


def test_real_subprocess_bytes_and_missing_fib_are_first_apply_not_error():
    class ByteExecutor(PolicyStateExecutor):
        def run(self, argv, timeout):
            result = super().run(argv, timeout)
            if argv == ['ip', '-4', 'route', 'show', 'table', '100'] and not self.routes:
                return SimpleNamespace(returncode=2, stdout=b'',
                                       stderr=b'Error: ipv4: FIB table does not exist.\n')
            result.stdout = result.stdout.encode()
            return result

    executor = ByteExecutor()
    policy_route.PolicyRouteLoader(executor).apply()
    assert executor.routes == ['local default dev lo scope host']
    assert executor.rules == ['100: from all fwmark 0x100 lookup 100']
    executor.calls.clear()
    policy_route.PolicyRouteLoader(executor).apply()
    assert _mutations(executor) == []


def test_loader_installs_only_missing_entry_without_tearing_down_peer():
    add_rule, add_route = [list(argv) for argv in policy_route.commands("add")]
    executor = PolicyStateExecutor(
        rules=("100: from all fwmark 0x100 lookup 100",), routes=())

    policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == [add_route]
    assert executor.rules == ["100: from all fwmark 0x100 lookup 100"]
    assert executor.routes == ["local default dev lo scope host"]
    assert add_rule not in _mutations(executor)


def test_loader_missing_rule_does_not_tear_down_healthy_route():
    add_rule, _ = [list(argv) for argv in policy_route.commands("add")]
    executor = PolicyStateExecutor(routes=("local default dev lo scope host",))

    policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == [add_rule]
    assert executor.routes == ["local default dev lo scope host"]


def test_loader_reports_conflicting_owned_rule_before_mutation():
    executor = PolicyStateExecutor(
        rules=("100: from all fwmark 0x100 lookup 200",),
        routes=("local default dev lo scope host",),
    )

    with pytest.raises(ApplyError, match="agent.reload_failed"):
        policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == []


def test_loader_reports_unrecognized_owned_table_route_before_mutation():
    executor = PolicyStateExecutor(
        rules=("100: from all fwmark 0x100 lookup 100",),
        routes=("default via 192.0.2.1 dev eth0",),
    )

    with pytest.raises(ApplyError, match="agent.reload_failed"):
        policy_route.PolicyRouteLoader(executor).apply()

    assert _mutations(executor) == []


def test_loader_probe_or_add_failure_is_reload_failed():
    probes = (["ip", "-4", "rule", "show"],
              ["ip", "-4", "route", "show", "table", "100"])
    for failed in probes:
        executor = PolicyStateExecutor(fail=(failed,))
        with pytest.raises(ApplyError, match="agent.reload_failed"):
            policy_route.PolicyRouteLoader(executor).apply()
        assert _mutations(executor) == []

    add_rule = list(policy_route.commands("add")[0])
    executor = PolicyStateExecutor(
        routes=("local default dev lo scope host",), fail=(add_rule,))
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        policy_route.PolicyRouteLoader(executor).apply()


def test_malformed_registry_fails_before_probe_or_mutation(monkeypatch):
    bad = SimpleNamespace(table_id=100, rule_priority=100,
                          fwmark="0x100; rm -rf /")
    monkeypatch.setattr(marks, "POLICY_ROUTES", (bad,))
    executor = PolicyStateExecutor()

    with pytest.raises(ValueError, match="tproxy.policy_route_fwmark"):
        policy_route.PolicyRouteLoader(executor).apply()

    assert executor.calls == []


def test_loader_remove_retains_exact_owned_deletion_semantics():
    executor = PolicyStateExecutor()
    policy_route.PolicyRouteLoader(executor).remove()
    assert [argv for argv, _ in executor.calls] == [
        list(argv) for argv in policy_route.commands("del")]
