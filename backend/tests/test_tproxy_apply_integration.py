"""Integration scaffold for the sing-box TProxy apply/boot path.

The public gate ``tproxy.not_available`` still rejects ``tproxy.enabled=True``,
so an enabled configuration only exists as an offline ``model_copy`` (the idiom
the offline generators already use). These tests therefore:

* prove the scaffold is inert for every reachable (``enabled=False``)
  configuration — no extra file, validator, phase or marker key;
* exercise the enabled branch **offline** to pin the activation order
  (guards -> engine/readiness; no capture artifact while the gate is closed),
  rollback compensation and boot behaviour.

Nothing here opens the gate, runs bpf/sing-box or touches a live host.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent import tproxy_apply
from vs_router.agent.apply import (APPLIED_DIR, FILES, ApplyEngine)
from vs_router.schema import ConfigurationVersion


def enabled_version(ingress=("lan0",)):
    """Offline enabled snapshot: validate disabled, then model_copy the intent.

    Re-validating the dump would fail with ``tproxy.not_available``; that is the
    point — the gate is what keeps this branch unreachable in production.
    """
    base = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "lan0", "zone": "lan", "addresses": ["10.212.1.1/24"]},
            {"name": "wan0", "zone": "wan", "addresses": ["192.0.2.1/24"]},
        ],
        "dns": {"interfaces": ["lan0"]},
        "tproxy": {"ingress_interfaces": list(ingress)},
    }})
    tproxy = base.configuration.tproxy.model_copy(update={"enabled": True})
    return base.model_copy(update={"configuration": base.configuration.model_copy(
        update={"tproxy": tproxy})})


def engine_with(fs=None, executor=None, now=None, **kw):
    fs = fs or FakeFS()
    executor = executor or FakeExecutor()
    original = executor.run
    def with_loaded_tables(argv, timeout):
        if argv == ['/usr/sbin/nft', 'list', 'tables']:
            return SimpleNamespace(returncode=0, stdout=''.join(
                f'table {name}\n' for name in tproxy_apply.owned_tables()))
        return original(argv, timeout)
    executor.run = with_loaded_tables
    now = now or [100.0]
    return ApplyEngine(filesystem=fs, executor=executor, clock=lambda: now[0], **kw), fs, executor


# --------------------------------------------------------------------------
# Contract
# --------------------------------------------------------------------------

def test_scaffold_contract_is_ordered_and_closed():
    assert list(tproxy_apply.TPROXY_FILES) == [
        "tproxy_guards", "tproxy_unbound_selected", "tproxy_unbound_ordinary",
        "singbox", "tproxy_interception"]
    # Guards precede the readiness resolver configs/engine, which precede capture.
    assert tproxy_apply.PHASE_ORDER == (
        ("guards", ("tproxy_guards",)),
        ("readiness", ("tproxy_unbound_selected", "tproxy_unbound_ordinary", "singbox")),
        ("interception", ("tproxy_interception",)))
    assert set(tproxy_apply.TPROXY_FILES) <= set(tproxy_apply.TPROXY_VALIDATORS)
    assert tproxy_apply.build_artifacts(ConfigurationVersion()) == {}
    assert tproxy_apply.describe()["phase_order"][-1] == ["interception", ["tproxy_interception"]]
    assert list(tproxy_apply.cleanup_files()) == [
        "tproxy-unbound-selected.conf", "tproxy-unbound-ordinary.conf"]


def test_cleanup_destroys_every_owned_table_only():
    content = tproxy_apply.cleanup_content()
    for table in tproxy_apply.owned_tables():
        assert f"destroy table {table}\n" in content
    # Destroy-only: no rule is ever added by the teardown text.
    assert "counter" not in content and "hook" not in content


# --------------------------------------------------------------------------
# Inertness: enabled=False must not change anything
# --------------------------------------------------------------------------

def test_disabled_apply_adds_no_tproxy_file_or_marker_key():
    engine, fs, executor = engine_with()
    result = engine.apply_version(snapshot())
    assert result.status == "confirmed"
    # Exactly the historical validator executions, no TProxy validator.
    assert len(executor.calls) == len(FILES)
    marker = engine.status()
    assert "tproxy" not in marker
    assert set(marker["phases"]) == set(FILES)
    written = {Path(p).name for p in fs.files}
    assert "tproxy-guards.nft" not in written
    assert "singbox.json" not in written


def test_boot_protection_restore_is_a_noop_without_artifacts(monkeypatch, tmp_path):
    from vs_router.agent import boot_restore
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    calls = []
    monkeypatch.setattr(boot_restore, "run", lambda argv: calls.append(argv) or 0)
    assert boot_restore.restore_tproxy_protection() == 0
    assert calls == []


def test_boot_protection_restore_loads_guard_when_present(monkeypatch, tmp_path):
    from vs_router.agent import boot_restore
    guard = tmp_path / tproxy_apply.TPROXY_FILES["tproxy_guards"]
    guard.write_text("destroy table inet vs_router_tproxy_guard\n")
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    calls = []
    monkeypatch.setattr(boot_restore, "run", lambda argv: calls.append(argv) or 0)
    assert boot_restore.restore_tproxy_protection() == 0
    assert calls == [["/usr/sbin/nft", "-f", str(guard)]]


# --------------------------------------------------------------------------
# Enabled branch (offline): order, rollback, first apply
# --------------------------------------------------------------------------

def _recording_validators(order):
    def validator(name, path):
        order.append(name)
        return SimpleNamespace(returncode=0)
    return {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}


def test_enabled_apply_installs_guards_before_engine():
    engine, fs, executor = engine_with()
    order = []
    # Isolate from the live readiness adapters (policy route + pinned engine):
    # this test pins file/phase order, not the process. The adapters now verify
    # the pinned binary and the config, which needs a real host.
    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: (lambda: None),
                              tproxy_apply.SINGBOX_PROCESS_STEP: (lambda: None)}
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators(order))
    assert result.status == "confirmed"
    # Activation order: ordinary files, then guards, then the two readiness
    # resolver configs, then the engine/readiness file, then the capture table.
    assert order[-5:] == ["tproxy_guards", "tproxy_unbound_selected",
                          "tproxy_unbound_ordinary", "singbox", "tproxy_interception"]
    assert order.index("tproxy_guards") < order.index("tproxy_unbound_selected") \
        < order.index("tproxy_unbound_ordinary") < order.index("singbox") \
        < order.index("tproxy_interception")
    marker = engine.status()
    assert marker["tproxy"]["files"] == ["tproxy_guards", "tproxy_unbound_selected",
                                         "tproxy_unbound_ordinary", "singbox",
                                         "tproxy_interception"]
    assert marker["tproxy"]["phase_order"][-1] == ["interception", ["tproxy_interception"]]
    assert marker["tproxy"]["selected_uid"] == 29092
    assert marker["tproxy"]["readiness"]["selected_uid"] == 29092
    guards = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_guards"])
    assert "vs_router_tproxy_guard" in guards
    assert "vs_router_tproxy_preauth" in guards
    assert "vs_router_tproxy_dns_ingress" in guards
    assert "vs_router_tproxy_dns_listener" in guards
    assert "vs_router_tproxy_dns_output" in guards
    assert "meta skuid 29092" in guards
    selected = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_selected"])
    ordinary = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_ordinary"])
    assert "forward-addr: 127.0.0.1@15353" in selected
    assert "cache-max-ttl: 0" in selected
    assert "forward-addr: 127.0.0.1@15353" not in ordinary
    engine_json = json.loads(fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["singbox"]))
    assert {i["type"] for i in engine_json["inbounds"]} == {"tproxy"}
    capture = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_interception"])
    assert "vs_router_tproxy_interception" in capture
    assert "tproxy ip to 127.0.0.1:51272" in capture


def _fail_on(executor, argv_prefix):
    original = executor.run

    def run(argv, timeout):
        if argv[:1] == [argv_prefix]:
            return SimpleNamespace(returncode=1)
        return original(argv, timeout)
    executor.run = run


def test_enabled_failure_rolls_back_and_tears_down_owned_tables():
    engine, fs, executor = engine_with()
    # A confirmed non-TProxy baseline is the rollback target.
    assert engine.apply_version(snapshot()).status == "confirmed"
    original_nft = fs.read(APPLIED_DIR / FILES["nftables"])
    # Fail during activation, after the guards are already applied.
    engine.reload_commands = {"singbox": ["fail-singbox"]}
    _fail_on(executor, "fail-singbox")
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators([]))
    assert result.status == "rolled_back"
    status = engine.status()
    assert status["status"] == "rolled_back"
    assert status["phases"].get("tproxy_cleanup") == "applied"
    cleanup = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE)
    assert cleanup == tproxy_apply.cleanup_content()
    # The confirmed target was restored, not left half-applied.
    assert fs.read(APPLIED_DIR / FILES["nftables"]) == original_nft


def test_enabled_first_apply_failure_has_no_target_and_torn_down():
    engine, fs, executor = engine_with()
    engine.reload_commands = {"singbox": ["fail-singbox"]}
    _fail_on(executor, "fail-singbox")
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators([]))
    assert result.status == "failed"
    # No confirmed target existed, so the scaffold tore the half-open tract down
    # explicitly instead of leaving guards live.
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE) == tproxy_apply.cleanup_content()


def test_old_snapshot_without_singbox_file_yields_empty_branch():
    from vs_router.agent.apply import _tproxy_branch_from_snapshot
    assert _tproxy_branch_from_snapshot({"id": 1, "configuration": {}}) == ({}, {})
    # A snapshot the schema cannot re-validate (an enabled one) must not raise.
    assert _tproxy_branch_from_snapshot(enabled_version().model_dump(mode="json")) == ({}, {})


# --------------------------------------------------------------------------
# Boot: pending is never promoted and a half-open tract is torn down
# --------------------------------------------------------------------------

def test_boot_does_not_confirm_pending_and_tears_down_interrupted_tproxy(monkeypatch):
    from vs_router.agent import boot_restore, apply as apply_mod
    fs = FakeFS()
    executor = FakeExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor)
    pending = {"version_id": 1, "status": "pending", "deadline": 4242.0,
               "phases": {"nftables": "applied", "tproxy_guards": "applied"}}
    fs.files[apply_mod.JOURNAL_PATH] = json.dumps(pending)
    fs.files[apply_mod.MARKER_PATH] = json.dumps(pending)
    backup = {"version_id": 1, "files": {name: "" for name in FILES},
              "version_snapshot": {"id": 1, "configuration": {}}}
    fs.files[apply_mod.CONFIRMED_DIR / "snapshot.json"] = json.dumps(backup)

    monkeypatch.setattr(apply_mod, "ApplyEngine", lambda: engine)
    monkeypatch.setattr(boot_restore, "APPLIED", "/run/does-not-matter")
    monkeypatch.setattr("vs_router.management.read_management", lambda: None)

    boot_restore.recover_interrupted_apply()

    status = engine.status()
    assert status["status"] == "rolled_back"
    assert status["reason"] == "reboot"
    assert status["status"] != "confirmed"
    # The interrupted TProxy artifact is replaced by destroy-only teardown so
    # boot cannot restore a half-open guard.
    guard = fs.read(Path("/run/does-not-matter") / tproxy_apply.TPROXY_FILES["tproxy_guards"])
    assert guard == tproxy_apply.cleanup_content()
