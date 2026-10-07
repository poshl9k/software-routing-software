"""Integration tests for the TProxy DNS contour inside the gated apply scaffold.

ADR-0014 fixes the DNS contour as two Unbound processes (selected/ordinary)
with ingress/listener/OUTPUT guards. These tests prove that contour is wired
into :mod:`vs_router.agent.tproxy_apply` / :mod:`vs_router.agent.apply` /
:mod:`vs_router.agent.boot_restore`:

* the scaffold stays inert for every reachable (``enabled=False``) version —
  no extra file, phase, validator or marker key;
* for an (offline-only) enabled version the ordered phases hold: guards
  (including the UID-scoped DNS OUTPUT boundary) load before the two readiness
  resolver configs and the engine, which load before capture;
* guards and resolver configs are composed from the *same* plan
  (:func:`generators.tproxy_dns.plan_tproxy_dns`), so listeners, UID and tables
  cannot disagree;
* an inconsistent contour fails closed (raises) instead of emitting partial
  protection;
* teardown removes the tables *and* the split resolver configs on rollback,
  first-apply failure and reboot recovery.

Nothing here opens the public gate, starts Unbound or touches a host.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent import tproxy_apply
from vs_router.agent.apply import APPLIED_DIR, FILES, ApplyEngine
from vs_router.generators import tproxy_dns
from vs_router.generators.nftables import (generate_tproxy_containment,
                                           generate_tproxy_dns_ingress_guard,
                                           generate_tproxy_dns_listener_guard,
                                           generate_tproxy_dns_output_guard,
                                           generate_tproxy_preauthorization)
from vs_router.generators.unbound import generate_tproxy_unbound_split
from vs_router.schema import ConfigurationVersion

SELECTED = "tproxy_unbound_selected"
ORDINARY = "tproxy_unbound_ordinary"
GUARDS = "tproxy_guards"


def enabled_version(ingress=("lan0",)):
    """Offline enabled snapshot: validate disabled, then model_copy the intent.

    Re-validating the dump fails with ``tproxy.not_available``; that is exactly
    why this branch is unreachable in production.
    """
    base = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "lan1", "zone": "lan", "addresses": ["10.212.3.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": ["192.0.2.1/24"]},
        ],
        "dns": {
            "interfaces": ["lan0", "lan1"],
            "access_control": ["10.212.0.0/16"],
            "records": [{"name": "router.test.", "value": "192.0.2.77"}],
            "forwards": [{"domain": "corp.test.", "upstreams": ["198.18.0.2"]}],
            "upstreams": ["198.18.0.3"],
        },
        "tproxy": {"ingress_interfaces": list(ingress)},
    }})
    tproxy = base.configuration.tproxy.model_copy(update={"enabled": True})
    return base.model_copy(update={"configuration": base.configuration.model_copy(
        update={"tproxy": tproxy})})


def engine_with(fs=None, executor=None, now=None):
    fs = fs or FakeFS()
    executor = executor or FakeExecutor()
    now = now or [100.0]
    return ApplyEngine(filesystem=fs, executor=executor, clock=lambda: now[0]), fs, executor


def recording_validators(order):
    def validator(name, path):
        order.append(name)
        return SimpleNamespace(returncode=0)
    return {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}


# --------------------------------------------------------------------------
# Inertness: enabled=False changes nothing
# --------------------------------------------------------------------------

def test_disabled_is_inert_in_plan_scaffold_and_apply():
    plain = ConfigurationVersion.model_validate({"configuration": {}})
    assert tproxy_dns.selected_uid_for(plain) is None
    assert tproxy_apply.plan(plain).enabled is False
    assert tproxy_apply.build_artifacts(plain) == {}
    engine, fs, executor = engine_with()
    assert engine.apply_version(snapshot()).status == "confirmed"
    assert len(executor.calls) == len(FILES)  # no TProxy validator ran
    marker = engine.status()
    assert "tproxy" not in marker
    assert set(marker["phases"]) == set(FILES)
    written = {Path(p).name for p in fs.files}
    assert tproxy_apply.TPROXY_FILES[GUARDS] not in written
    assert tproxy_apply.TPROXY_FILES[SELECTED] not in written


# --------------------------------------------------------------------------
# Phase order and guard composition
# --------------------------------------------------------------------------

def test_phase_order_is_guards_before_readiness_before_interception():
    assert tproxy_apply.PHASE_ORDER == (
        ("guards", (GUARDS,)),
        ("readiness", (SELECTED, ORDINARY, "singbox")),
        ("interception", ("tproxy_interception",)))
    # Readiness resolver configs are named and the phase list is one contract.
    assert list(tproxy_apply.cleanup_files()) == [
        tproxy_apply.TPROXY_FILES[SELECTED], tproxy_apply.TPROXY_FILES[ORDINARY]]


def test_guard_content_composes_the_plan_in_packet_order():
    version = enabled_version()
    content = tproxy_apply.guard_content(version)
    # Containment -> preauthorization -> DNS ingress(-110) -> listener(-10) ->
    # OUTPUT(-20): the very order a packet traverses the contour.
    order = [
        "vs_router_tproxy_guard",
        "vs_router_tproxy_preauth",
        "vs_router_tproxy_dns_ingress",
        "vs_router_tproxy_dns_listener",
        "vs_router_tproxy_dns_output",
    ]
    positions = [content.index(name) for name in order]
    assert positions == sorted(positions)
    assert content.startswith(generate_tproxy_containment(version))
    assert generate_tproxy_preauthorization(version) in content


def test_guards_come_byte_for_byte_from_the_plan():
    version = enabled_version()
    composed = tproxy_apply.plan(version)
    assert [g.role for g in composed.nft_guards] == ["ingress", "listener", "output"]
    assert composed.nft_guards[0].content == generate_tproxy_dns_ingress_guard(version)
    assert composed.nft_guards[1].content == generate_tproxy_dns_listener_guard(version)
    assert composed.nft_guards[2].content == generate_tproxy_dns_output_guard(
        version, tproxy_dns.TPROXY_SELECTED_UID)
    content = tproxy_apply.guard_content(version)
    for guard in composed.nft_guards:
        assert guard.content in content


def test_resolver_configs_and_guards_share_uid_and_listeners():
    version = enabled_version()
    plan = tproxy_apply.plan(version)
    assert plan.selected_uid == tproxy_dns.TPROXY_SELECTED_UID == 29092
    # Listeners agree between the plan, the resolver configs and the guards.
    assert plan.listener_addresses == {"selected": ("10.212.1.1",),
                                       "ordinary": ("10.212.3.1",)}
    assert "interface: 10.212.1.1\n" in plan.selected_unbound
    assert "interface: 10.212.3.1\n" not in plan.selected_unbound
    assert "interface: 10.212.3.1\n" in plan.ordinary_unbound
    assert 'iifname { "lan0" } ip daddr != { 10.212.1.1 } counter drop' in \
        plan.nft_guards[1].content
    assert 'meta skuid 29092 oifname "lan0" ip saddr 10.212.1.1' in \
        plan.nft_guards[2].content


def test_readiness_artifacts_match_the_plan():
    artifacts = tproxy_apply.build_artifacts(enabled_version())
    split = generate_tproxy_unbound_split(enabled_version())
    assert artifacts[SELECTED] == split["selected"]
    assert artifacts[ORDINARY] == split["ordinary"]
    assert "forward-addr: 127.0.0.1@15353" in artifacts[SELECTED]
    assert "forward-addr: 127.0.0.1@15353" not in artifacts[ORDINARY]


# --------------------------------------------------------------------------
# Fail-closed plan semantics
# --------------------------------------------------------------------------

def test_inconsistent_contour_fails_closed_not_partial():
    # Selected listener missing from dns.interfaces: the planner refuses rather
    # than emit guards/configs that disagree about the listener set.
    broken = enabled_version().model_copy(update={"configuration":
        enabled_version().configuration.model_copy(update={
            "dns": enabled_version().configuration.dns.model_copy(update={
                "interfaces": ("lan1",)})})})
    with pytest.raises(ValueError, match="tproxy.dns_split_missing_listener"):
        tproxy_apply.plan(broken)
    with pytest.raises(ValueError, match="tproxy.dns_split_missing_listener"):
        tproxy_apply.guard_content(broken)


def test_enabled_plan_requires_a_valid_reserved_uid():
    # The reserved constant is itself valid; an invalid override is rejected.
    version = enabled_version()
    with pytest.raises(ValueError, match="tproxy.dns_output_invalid_uid"):
        tproxy_dns.plan_tproxy_dns(version, 0)


# --------------------------------------------------------------------------
# Rollback and cleanup
# --------------------------------------------------------------------------

def _fail_on(executor, prefix):
    original = executor.run

    def run(argv, timeout):
        if argv[:1] == [prefix]:
            return SimpleNamespace(returncode=1)
        return original(argv, timeout)
    executor.run = run


def test_rollback_removes_readiness_files_and_tables():
    engine, fs, executor = engine_with()
    assert engine.apply_version(snapshot()).status == "confirmed"
    engine.reload_commands = {"singbox": ["fail-singbox"]}
    _fail_on(executor, "fail-singbox")
    result = engine.apply_version(enabled_version(), validators=recording_validators([]))
    assert result.status == "rolled_back"
    status = engine.status()
    assert status["phases"].get("tproxy_cleanup") == "applied"
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE) == \
        tproxy_apply.cleanup_content()
    # The split resolver configs a torn-down apply staged are gone as well.
    written = {Path(p).name for p in fs.files}
    assert tproxy_apply.TPROXY_FILES[SELECTED] not in written
    assert tproxy_apply.TPROXY_FILES[ORDINARY] not in written


def test_first_apply_failure_tears_down_tables_and_readiness_files():
    engine, fs, executor = engine_with()
    engine.reload_commands = {"singbox": ["fail-singbox"]}
    _fail_on(executor, "fail-singbox")
    result = engine.apply_version(enabled_version(), validators=recording_validators([]))
    assert result.status == "failed"
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE) == \
        tproxy_apply.cleanup_content()
    written = {Path(p).name for p in fs.files}
    assert tproxy_apply.TPROXY_FILES[SELECTED] not in written
    assert tproxy_apply.TPROXY_FILES[ORDINARY] not in written


def test_boot_recovery_tears_down_interrupted_dns_contour(monkeypatch):
    from vs_router.agent import boot_restore, apply as apply_mod
    fs = FakeFS()
    executor = FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    pending = {"version_id": 1, "status": "pending", "deadline": 4242.0,
               "phases": {GUARDS: "applied", SELECTED: "applied", ORDINARY: "applied"}}
    fs.files[apply_mod.JOURNAL_PATH] = json.dumps(pending)
    fs.files[apply_mod.MARKER_PATH] = json.dumps(pending)
    backup = {"version_id": 1, "files": {name: "" for name in FILES},
              "version_snapshot": {"id": 1, "configuration": {}}}
    fs.files[apply_mod.CONFIRMED_DIR / "snapshot.json"] = json.dumps(backup)
    applied = "/run/does-not-matter"
    for key in (GUARDS, SELECTED, ORDINARY):
        fs.files[Path(applied) / tproxy_apply.TPROXY_FILES[key]] = "stale"

    monkeypatch.setattr(apply_mod, "ApplyEngine", lambda: engine)
    monkeypatch.setattr(boot_restore, "APPLIED", applied)
    monkeypatch.setattr("vs_router.management.read_management", lambda: None)

    boot_restore.recover_interrupted_apply()

    assert engine.status()["status"] == "rolled_back"
    guard = fs.read(Path(applied) / tproxy_apply.TPROXY_FILES[GUARDS])
    assert guard == tproxy_apply.cleanup_content()
    assert Path(applied) / tproxy_apply.TPROXY_FILES[SELECTED] not in fs.files
    assert Path(applied) / tproxy_apply.TPROXY_FILES[ORDINARY] not in fs.files
