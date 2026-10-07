"""Host-free tests for the deterministic TProxy interception generator.

The public gate ``tproxy.not_available`` still rejects ``tproxy.enabled=True``
(``validators.py``), so an enabled configuration only exists as an offline
``model_copy`` — the same idiom the other offline generators use. These tests
never touch nftables, policy routing or a host: they pin rule narrowness, hook
order/priority, mark ownership, determinism, the disabled/off behaviour and the
agent scaffold wiring (guards -> readiness -> interception).
"""
from pathlib import Path

import json
import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent import tproxy_apply
from vs_router.agent.apply import APPLIED_DIR, FILES, ApplyEngine
from vs_router.generators import marks
from vs_router.generators.nftables import (generate_tproxy_interception,
                                           tproxy_policy_route_commands)
from vs_router.schema import ConfigurationVersion

CAPTURE_FILE = "tproxy-intercept.nft"


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

    The generator must reject the ingress itself rather than trust a
    model_copy that the public contract would never accept.
    """
    version = base(("lan0",))
    tproxy = version.configuration.tproxy.model_copy(
        update={"enabled": True, "ingress_interfaces": tuple(ingress)})
    return version.model_copy(update={"configuration": version.configuration.model_copy(
        update={"tproxy": tproxy})})


def engine_with():
    fs, executor = FakeFS(), FakeExecutor()
    return ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0), fs, executor


# --------------------------------------------------------------------------
# Narrowness / hook order
# --------------------------------------------------------------------------

def test_disabled_interception_is_destroy_only():
    text = generate_tproxy_interception(ConfigurationVersion())
    assert text == "destroy table inet vs_router_tproxy_interception\n"
    assert "tproxy" not in text.replace("inet vs_router_tproxy_interception", "")
    assert "mark" not in text and "counter" not in text and "hook" not in text


def test_hook_is_prerouting_and_runs_after_preauth():
    text = generate_tproxy_interception(enabled())
    assert "chain prerouting" in text
    assert "type filter hook prerouting priority -80; policy accept;" in text
    # nft evaluates lower priorities first: preauth -90 before capture -80.
    assert -90 < -80


def test_capture_keeps_preauth_exemptions():
    text = generate_tproxy_interception(enabled(ingress=("lan1", "lan0")))
    # Unselected ingress, local FIB destinations and post-DNAT flows are kept.
    assert 'iifname != { "lan0", "lan1" } return' in text
    assert "fib daddr type local return" in text
    assert "ct status dnat return" in text
    assert "meta nfproto != ipv4 return" in text
    assert "meta l4proto != { tcp, udp } return" in text
    # No per-flow established shortcut: preauth re-evaluates every packet.
    assert "ct state established" not in text
    assert "ct state" not in text


def test_capture_targets_loopback_listeners_with_owned_mark():
    text = generate_tproxy_interception(enabled())
    assert f"meta mark set {marks.MARK_TPROXY_ROUTE_VALUE:#x}" in text
    assert f"tproxy ip to 127.0.0.1:{marks.TPROXY_TCP_PORT}" in text
    assert f"tproxy ip to 127.0.0.1:{marks.TPROXY_UDP_PORT}" in text
    assert "meta nfproto ipv4 meta l4proto tcp" in text
    assert "meta nfproto ipv4 meta l4proto udp" in text
    # Only ever the routing mark, never a proof bit.
    assert f"{marks.MARK_TPROXY_PROOF_VALUE:#x}" not in text


def test_capture_output_is_deterministic():
    first = generate_tproxy_interception(enabled())
    second = generate_tproxy_interception(enabled())
    assert first == second
    # Stable ordering of the two protocol rules (TCP then UDP).
    assert first.index("tproxy_tcp") < first.index("tproxy_udp")


def test_invalid_ingress_is_rejected():
    for ingress in ((), ("wan0",), ("lan0", "lan0"), ("missing",)):
        with pytest.raises(ValueError, match="tproxy.interception_invalid_ingress"):
            generate_tproxy_interception(forced(ingress))


def test_off_removes_only_its_own_table():
    text = generate_tproxy_interception(ConfigurationVersion())
    assert text.count("destroy table") == 1
    assert "vs_router_tproxy_interception" in text
    assert "vs_router_tproxy_preauth" not in text
    assert "vs_router_tproxy_guard" not in text


# --------------------------------------------------------------------------
# mark / table / hook ownership
# --------------------------------------------------------------------------

def test_mark_is_registered_tproxy_owner():
    marks.assert_no_collisions(marks.MARK_TPROXY_ROUTE_VALUE, marks.Owner.TPROXY)
    tables = {t.name for t in marks.TABLES}
    hooks = {(h.table, h.chain): h.priority for h in marks.HOOKS}
    assert "inet vs_router_tproxy_interception" in tables
    assert hooks[("inet vs_router_tproxy_interception", "prerouting")] == -80


def test_registry_matches_generator_source():
    text = (Path(__file__).resolve().parents[1] /
            "src/vs_router/generators/nftables.py").read_text()
    assert "inet vs_router_tproxy_interception" in text
    assert "priority -80;" in text


def test_policy_route_helper_is_owned_and_deterministic():
    route = marks.POLICY_ROUTES[0]
    add = tproxy_policy_route_commands("add")
    assert add == tproxy_policy_route_commands()  # add is the default
    rule, local = add
    assert rule[:3] == ("ip", "rule", "add")
    assert "fwmark" in rule and f"{route.fwmark:#x}" in rule
    assert str(route.table_id) in rule and str(route.rule_priority) in rule
    assert local[:3] == ("ip", "route", "add")
    assert "local" in local and "lo" in local and str(route.table_id) in local
    # The inverse removes exactly the same two owned entries.
    assert tproxy_policy_route_commands("del") == tuple(
        tuple("del" if part == "add" else part for part in argv) for argv in add)


def test_policy_route_helper_rejects_unknown_action():
    with pytest.raises(ValueError, match="tproxy.policy_route_action"):
        tproxy_policy_route_commands("flush")


# --------------------------------------------------------------------------
# agent scaffold wiring and inertness
# --------------------------------------------------------------------------

def test_agent_wires_interception_after_readiness():
    assert list(tproxy_apply.TPROXY_FILES) == [
        "tproxy_guards", "tproxy_unbound_selected", "tproxy_unbound_ordinary",
        "singbox", "tproxy_interception"]
    assert tproxy_apply.PHASE_ORDER == (
        ("guards", ("tproxy_guards",)),
        ("readiness", ("tproxy_unbound_selected", "tproxy_unbound_ordinary", "singbox")),
        ("interception", ("tproxy_interception",)))
    assert tproxy_apply.TPROXY_VALIDATORS["tproxy_interception"] == ["nft", "-c", "-f"]
    artifacts = tproxy_apply.build_artifacts(enabled())
    assert list(artifacts) == ["tproxy_guards", "tproxy_unbound_selected",
                               "tproxy_unbound_ordinary", "singbox",
                               "tproxy_interception"]
    assert artifacts["tproxy_interception"] == generate_tproxy_interception(enabled())


def test_agent_is_inert_when_disabled():
    assert tproxy_apply.required(ConfigurationVersion()) is False
    assert tproxy_apply.build_artifacts(ConfigurationVersion()) == {}
    engine, fs, _ = engine_with()
    result = engine.apply_version(snapshot())
    assert result.status == "confirmed"
    assert not any(Path(p).name == CAPTURE_FILE for p in fs.files)
    assert "tproxy_interception" not in engine.status()["phases"]


def test_enabled_apply_installs_capture_last():
    engine, fs, _ = engine_with()
    order = []

    def validator(name, path):
        order.append(name)
        from types import SimpleNamespace
        return SimpleNamespace(returncode=0)

    validators = {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}
    result = engine.apply_version(enabled(), validators=validators)
    assert result.status == "confirmed"
    assert order[-5:] == ["tproxy_guards", "tproxy_unbound_selected",
                          "tproxy_unbound_ordinary", "singbox", "tproxy_interception"]
    capture = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_interception"])
    assert capture == generate_tproxy_interception(enabled())


# --------------------------------------------------------------------------
# VM probe fixture (host-free checks; the probe itself runs only on a VM)
# --------------------------------------------------------------------------

import runpy  # noqa: E402  (kept next to the lab-fixture checks it serves)

LAB = Path(__file__).parent / "lab"


def _generator():
    return runpy.run_path(str(LAB / "generate_tproxy_preauth_cases.py"))


def _probe():
    return runpy.run_path(str(LAB / "tproxy_interception_probe.py"))


def test_interception_fixture_is_opt_in_and_preserves_baseline():
    generate = _generator()["generate_cases"]
    baseline = generate("tcp")
    fixture = generate("tcp", interception=True)
    for name in ("allow", "deny_first", "default_deny", "allow_first"):
        fixture.pop(name + "_interception")
    fixture.pop("off_interception")
    assert fixture == baseline
    assert "__tproxy_interception__" not in baseline


def test_interception_fixture_is_tcp_only():
    with pytest.raises(ValueError, match="TCP-only"):
        _generator()["generate_cases"]("udp", interception=True)


def test_interception_cli_mode_is_exclusive(tmp_path):
    module = _generator()
    target = tmp_path / "cases.json"
    for flags in (["--tproxy-interception", "--tcp"],
                  ["--tproxy-interception", "--tcp-ct-proof"]):
        with pytest.raises(SystemExit) as exc:
            module["main"]([str(target), *flags])
        assert exc.value.code == 2
        assert not target.exists()
    module["main"]([str(target), "--tproxy-interception"])
    output = json.loads(target.read_text())
    assert output["__tproxy_interception__"] is True
    assert "priority -80" in output["allow_interception"]


def test_probe_accepts_only_the_interception_fixture():
    validate = _probe()["validate_fixture"]
    with pytest.raises(AssertionError, match="tproxy-interception"):
        validate({})
    packet_proof = _generator()["generate_cases"]("tcp", input_proof=True)
    with pytest.raises(AssertionError, match="tproxy-interception"):
        validate(packet_proof)
    fixture = _generator()["generate_cases"]("tcp", interception=True)
    fixture["__tproxy_interception__"] = True
    validate(fixture)  # must not raise
