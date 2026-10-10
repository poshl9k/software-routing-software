"""Readiness gating and phase order for the TProxy agent adapters.

Exercises the *offline* enabled branch (public gate ``tproxy.not_available``
stays closed, so an enabled version only exists as a ``model_copy``) and proves:

* the typed readiness steps add no file/phase for an ``enabled=False`` config;
* the policy route and the engine start run after the engine config and strictly
  before the capture table;
* a readiness failure blocks interception;
* rollback/teardown stops the engine and removes the owned policy route.

No real shell/systemd: ``FakeFS``/``FakeExecutor`` only.
"""
from types import SimpleNamespace

from test_agent_apply import FakeExecutor, FakeFS
from test_tproxy_apply_integration import enabled_version
from vs_router.agent import singbox_service, tproxy_apply
from vs_router.agent.apply import APPLIED_DIR, FILES, ApplyEngine, ApplyError


def engine_with(fs=None, executor=None):
    engine = ApplyEngine(filesystem=fs or FakeFS(), executor=executor or FakeExecutor(),
                         clock=lambda: 100.0)
    engine._verify_tproxy_tables = lambda expected=None: None  # readiness order only
    return engine


def _recording_validators(order):
    def validator(name, path):
        order.append(name)
        return SimpleNamespace(returncode=0)
    return {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}


def test_contract_exposes_typed_readiness_steps_without_touching_the_file_map():
    assert tproxy_apply.READINESS_STEPS == (
        tproxy_apply.POLICY_ROUTE_STEP, tproxy_apply.UNBOUND_PROCESS_STEP,
        tproxy_apply.SINGBOX_PROCESS_STEP)
    assert tproxy_apply.TEARDOWN_STEPS == (
        tproxy_apply.SINGBOX_PROCESS_STEP, tproxy_apply.UNBOUND_PROCESS_STEP,
        tproxy_apply.POLICY_ROUTE_STEP)
    # Steps are actions, not artifacts: they add no key to the closed file map.
    assert set(tproxy_apply.READINESS_STEPS).isdisjoint(tproxy_apply.TPROXY_FILES)
    assert tproxy_apply.describe()["readiness_steps"] == list(tproxy_apply.READINESS_STEPS)


def test_disabled_apply_runs_no_readiness_step():
    engine = engine_with()
    result = engine.apply_version({"id": 1, "status": "draft", "configuration": {}})
    assert result.status == "confirmed"
    marker = engine.status()
    assert "tproxy" not in marker
    assert tproxy_apply.POLICY_ROUTE_STEP not in marker["phases"]
    assert tproxy_apply.SINGBOX_PROCESS_STEP not in marker["phases"]
    # No policy-route or systemd command ever surfaced for a disabled config.
    argv = [call for call, _ in engine.executor.calls]
    assert all(call[0] not in ("ip", "systemctl") for call in argv)


def test_readiness_runs_after_engine_config_and_before_capture():
    engine = engine_with()
    seen = {"order": []}

    def policy():
        seen["policy_at"] = dict(engine.status()["phases"])
        seen["order"].append("policy")

    def process():
        seen["process_at"] = dict(engine.status()["phases"])
        seen["order"].append("process")

    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: policy,
                              tproxy_apply.SINGBOX_PROCESS_STEP: process}
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators([]))
    assert result.status == "confirmed"
    # Policy route first, then the engine process (activation order).
    assert seen["order"] == ["policy", "process"]
    # Both ran after the engine config was applied...
    assert seen["policy_at"]["singbox"] == "applied"
    # ...and before the capture table was applied (the key exists from the
    # generate/validate stage; it must not yet be 'applied').
    assert seen["policy_at"].get("tproxy_interception") != "applied"
    assert seen["process_at"].get("tproxy_interception") != "applied"
    assert engine.status()["phases"]["tproxy_interception"] == "applied"


def test_readiness_failure_blocks_interception():
    engine = engine_with()

    def fail():
        raise ApplyError("agent.reload_failed")

    engine.reload_commands = {tproxy_apply.SINGBOX_PROCESS_STEP: fail}
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators([]))
    assert result.status == "failed"
    # The capture table is never activated and its artifact never appears.
    assert "tproxy_interception" not in engine.status()["phases"]
    assert APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_interception"] \
        not in engine.fs.files


def test_rollback_tears_down_engine_and_owned_policy_route():
    engine = engine_with()
    assert engine.apply_version({"id": 1, "status": "draft",
                                 "configuration": {}}).status == "confirmed"

    def run(argv, timeout):
        engine.executor.calls.append((argv, timeout))
        return SimpleNamespace(returncode=int(argv == ["fail-capture"]))

    engine.executor.run = run
    engine.reload_commands = {"tproxy_interception": ["fail-capture"]}
    result = engine.apply_version(enabled_version(),
                                  validators=_recording_validators([]))
    assert result.status == "rolled_back"
    argv = [call for call, _ in engine.executor.calls]
    assert ["systemctl", "disable", "--now", singbox_service.SINGBOX_UNIT] in argv
    assert ["ip", "rule", "del", "priority", "100", "fwmark", "0x100",
            "lookup", "100"] in argv
