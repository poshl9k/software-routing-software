"""Typed sing-box lifecycle adapter: pinned unit, start/stop, readiness.

No real systemd and no real binary: everything runs through ``FakeExecutor`` /
``FakeFS``. Readiness must be proven before the caller installs the capture.
"""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeExecutor, FakeFS
from vs_router.agent import singbox_service
from vs_router.agent.apply import ApplyError


def test_unit_is_pinned_minimal_and_secret_free():
    text = singbox_service.unit_content()
    assert (f"ExecStart={singbox_service.SINGBOX_BINARY} run -c "
            f"{singbox_service.SINGBOX_CONFIG}") in text
    assert "NoNewPrivileges=true" in text
    assert "AmbientCapabilities=CAP_NET_ADMIN" in text
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in text
    assert "ProtectSystem=strict" in text
    assert "WantedBy=multi-user.target" in text
    # No secret material is ever placed in the unit.
    lowered = text.lower()
    assert "password" not in lowered and "uuid" not in lowered


def test_start_installs_unit_then_waits_for_readiness():
    fs, executor = FakeFS(), FakeExecutor()
    singbox_service.SingboxService(executor, fs).start()
    assert fs.read(singbox_service.UNIT_PATH) == singbox_service.unit_content()
    argv = [call for call, _ in executor.calls]
    enable = ["systemctl", "enable", "--now", singbox_service.SINGBOX_UNIT]
    active = ["systemctl", "is-active", "--quiet", singbox_service.SINGBOX_UNIT]
    assert enable in argv and active in argv
    # Readiness is waited for after the unit is started.
    assert argv.index(enable) < argv.index(active)


def test_start_fails_when_unit_never_becomes_ready():
    fs, executor = FakeFS(), FakeExecutor()

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv[:2] == ["systemctl", "is-active"]:
            return SimpleNamespace(returncode=3)
        return SimpleNamespace(returncode=0)

    executor.run = run
    service = singbox_service.SingboxService(executor, fs, attempts=3,
                                             sleep=lambda _: None)
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        service.start()


def test_start_fails_when_enable_fails():
    fs, executor = FakeFS(), FakeExecutor()

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv[:3] == ["systemctl", "enable", "--now"]:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)

    executor.run = run
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        singbox_service.SingboxService(executor, fs).start()


def test_stop_is_best_effort_and_typed():
    fs, executor = FakeFS(), FakeExecutor()
    singbox_service.SingboxService(executor, fs).stop()
    assert [call for call, _ in executor.calls] == [
        ["systemctl", "disable", "--now", singbox_service.SINGBOX_UNIT]]
