"""Typed policy-route loader: fixed argv, no injection, idempotency, removal.

No shell, no systemd and no live ``ip``: the adapter runs through the injected
``FakeExecutor`` and its argv is checked token by token.
"""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeExecutor
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


def test_loader_is_idempotent_and_removable():
    executor = FakeExecutor()
    loader = policy_route.PolicyRouteLoader(executor)
    loader.apply()
    loader.apply()  # a repeated apply converges instead of duplicating the rule
    add = [list(argv) for argv in policy_route.commands("add")]
    delete = [list(argv) for argv in policy_route.commands("del")]
    assert [argv for argv, _ in executor.calls] == delete + add + delete + add
    executor.calls.clear()
    loader.remove()
    assert [argv for argv, _ in executor.calls] == delete


def test_loader_add_failure_is_reload_failed_but_delete_is_tolerant():
    executor = FakeExecutor()

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        # A missing entry on delete is not an error; a failing add is.
        return SimpleNamespace(returncode=0 if "del" in argv else 1)

    executor.run = run
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        policy_route.PolicyRouteLoader(executor).apply()
