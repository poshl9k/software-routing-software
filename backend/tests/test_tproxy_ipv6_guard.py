"""Host-free tests for the deterministic TProxy IPv6-WAN-escape guard.

The public gate ``tproxy.not_available`` still rejects ``tproxy.enabled=True``
(``validators.py``), so an enabled configuration only exists as an offline
``model_copy`` -- the same idiom the other offline generators use. These tests
never touch nftables, routing or a host: they pin rule narrowness, the fail-closed
priority, mark/table/hook ownership, determinism, the disabled/off behaviour and
the agent scaffold wiring, plus host-free checks of the VM fixture/probe.
"""
import ast
import json
from pathlib import Path

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent import tproxy_apply
from vs_router.agent.apply import ApplyEngine
from vs_router.generators import marks
from vs_router.generators.nftables import (generate_tproxy_containment,
                                           generate_tproxy_ipv6_guard)
from vs_router.schema import ConfigurationVersion

LAB = Path(__file__).parent / "lab"
GUARD_TABLE = "inet vs_router_tproxy_ipv6_guard"


def base(ingress=("lan0",)):
    return ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "lan1", "zone": "lan", "addresses": ["10.213.1.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": ["192.0.2.1/24"]},
        ],
        "dns": {"interfaces": ["lan0"]},
        "tproxy": {"ingress_interfaces": list(ingress)},
    }})


def enabled(ingress=("lan0",)):
    """Offline enabled snapshot: validate disabled, then model_copy the intent."""
    version = base(ingress)
    tproxy = version.configuration.tproxy.model_copy(update={"enabled": True})
    return version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": tproxy})})


def forced(ingress):
    """Enabled snapshot whose ingress bypasses the public validator.

    The generator must reject the ingress itself rather than trust a model_copy
    the public contract would never accept.
    """
    version = base(("lan0",))
    tproxy = version.configuration.tproxy.model_copy(
        update={"enabled": True, "ingress_interfaces": tuple(ingress)})
    return version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": tproxy})})


def test_disabled_guard_is_destroy_only():
    text = generate_tproxy_ipv6_guard(ConfigurationVersion())
    assert text == f"destroy table {GUARD_TABLE}\n"
    assert "chain" not in text and "hook" not in text and "counter" not in text


def test_guard_is_forward_before_containment():
    text = generate_tproxy_ipv6_guard(enabled())
    assert "chain forward" in text
    assert "type filter hook forward priority -11; policy accept;" in text
    # Lower priority runs first: the IPv6 guard drops before containment (-10)
    # and before the product filter hook (0).
    assert -11 < -10 < 0


def test_guard_is_ipv6_only_and_preserves_ipv4():
    text = generate_tproxy_ipv6_guard(enabled())
    assert "meta nfproto != ipv6 return" in text
    assert "meta nfproto ipv4" not in text
    assert "ip daddr" not in text  # never matches an IPv4 destination


def test_guard_preserves_local_management_and_link_local():
    text = generate_tproxy_ipv6_guard(enabled())
    # Router-owned (management/panel/loopback) destinations return via the FIB.
    assert "fib daddr type local return" in text
    # Link-local and multicast scopes are scope-local, never a WAN escape.
    assert "ip6 daddr { fe80::/10, ff00::/8 } return" in text


def test_guard_only_gates_selected_ingress():
    text = generate_tproxy_ipv6_guard(enabled(ingress=("lan1", "lan0")))
    assert 'iifname != { "lan0", "lan1" } return' in text
    # Source interface matched, not address: a selected host cannot evade by
    # changing its IPv6 address.
    assert "ip6 saddr" not in text


def test_guard_is_single_fail_closed_drop():
    text = generate_tproxy_ipv6_guard(enabled())
    assert 'counter drop comment "tproxy_ipv6_guard"' in text
    assert text.count("drop") == 1
    assert "accept" not in text.replace("policy accept", "")
    # No per-flow established shortcut: every packet is re-evaluated.
    assert "ct state" not in text and "ct status" not in text


def test_guard_output_is_deterministic():
    first = generate_tproxy_ipv6_guard(enabled(ingress=("lan1", "lan0")))
    second = generate_tproxy_ipv6_guard(enabled(ingress=("lan0", "lan1")))
    assert first == second  # sorted ingress -> no ordering dependence


def test_invalid_ingress_is_rejected():
    for ingress in ((), ("wan0",), ("lan0", "lan0"), ("missing",)):
        with pytest.raises(ValueError, match="tproxy.ipv6_guard_invalid_ingress"):
            generate_tproxy_ipv6_guard(forced(ingress))


def test_off_removes_only_its_own_table():
    text = generate_tproxy_ipv6_guard(ConfigurationVersion())
    assert text.count("destroy table") == 1
    assert GUARD_TABLE in text
    for other in ("vs_router_tproxy_guard", "vs_router_tproxy_preauth",
                  "vs_router_tproxy_interception", "vs_router_tproxy_dns"):
        assert other not in text


# --------------------------------------------------------------------------
# table / hook ownership
# --------------------------------------------------------------------------

def test_table_and_hook_are_registered_and_unique():
    tables = {t.name for t in marks.TABLES}
    hooks = {(h.table, h.chain): h.priority for h in marks.HOOKS}
    assert GUARD_TABLE in tables
    assert hooks[(GUARD_TABLE, "forward")] == -11
    marks.assert_unique_tables()
    marks.assert_registry_consistent()
    marks.assert_namespaces_disjoint()


# --------------------------------------------------------------------------
# agent scaffold wiring and inertness
# --------------------------------------------------------------------------

def test_agent_wires_ipv6_guard_into_the_guards_phase():
    content = tproxy_apply.guard_content(enabled())
    assert generate_tproxy_ipv6_guard(enabled()) in content
    # Containment stays first; the IPv6 guard rides in the same guard artifact.
    assert content.startswith(generate_tproxy_containment(enabled()))
    guard_phase = tproxy_apply.PHASE_ORDER[0]
    assert guard_phase == ("guards", ("tproxy_guards",))
    artifacts = tproxy_apply.build_artifacts(enabled())
    assert generate_tproxy_ipv6_guard(enabled()) in artifacts["tproxy_guards"]


def test_agent_is_inert_when_disabled():
    assert tproxy_apply.required(ConfigurationVersion()) is False
    assert tproxy_apply.build_artifacts(ConfigurationVersion()) == {}
    engine = tproxy_apply.guard_content(ConfigurationVersion())
    assert "chain" not in engine  # destroy-only, no live guard
    fs, executor = FakeFS(), FakeExecutor()
    apply_engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    result = apply_engine.apply_version(snapshot())
    assert result.status == "confirmed"
    assert "tproxy_guards" not in apply_engine.status()["phases"]


# --------------------------------------------------------------------------
# VM fixture / probe host-free checks (the probe itself runs only on a VM)
# --------------------------------------------------------------------------

def load_generator():
    import runpy
    return runpy.run_path(str(LAB / "generate_tproxy_ipv6_cases.py"))


def load_probe():
    import runpy
    return runpy.run_path(str(LAB / "tproxy_ipv6_guard_probe.py"))


def test_fixture_shape_matches_the_generator():
    outputs = load_generator()["generate_cases"]()
    assert outputs["__tproxy_ipv6_guard__"] is True
    assert outputs["ingress"] == ["lan0"]
    assert outputs["guard"] == generate_tproxy_ipv6_guard(enabled())
    assert outputs["guard"] == generate_tproxy_ipv6_guard(enabled(ingress=("lan0",)))
    assert outputs["off"] == generate_tproxy_ipv6_guard(ConfigurationVersion())


def test_probe_is_stdlib_only_and_import_safe():
    for name in ("generate_tproxy_ipv6_cases", "tproxy_ipv6_guard_probe"):
        tree = ast.parse((LAB / f"{name}.py").read_text())
        assert not any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                       for node in tree.body), name
    probe = ast.parse((LAB / "tproxy_ipv6_guard_probe.py").read_text())
    imported = set()
    for node in ast.walk(probe):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "vs_router" not in imported


def test_probe_fixture_validation_accepts_only_the_guard_fixture():
    validate = load_probe()["validate_fixture"]
    fixture = load_generator()["generate_cases"]()
    validate(fixture)  # must not raise
    with pytest.raises(AssertionError, match="opt-in"):
        validate({})
    broken = dict(fixture, guard=fixture["guard"].replace("meta nfproto != ipv6 return", ""))
    with pytest.raises(AssertionError):
        validate(broken)


def test_probe_reports_the_documented_boundary():
    text = (LAB / "tproxy_ipv6_guard_probe.py").read_text()
    assert "bridge/flow-offload" in text
    assert "ECMP" in text
    assert "not_available" in text
