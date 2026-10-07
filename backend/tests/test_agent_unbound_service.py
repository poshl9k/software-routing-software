"""Typed Unbound lifecycle adapter: two processes, distinct UID, fail-closed.

No real systemd, no real Unbound: everything runs through a recording fake
executor / ``FakeFS``. The adapter must fail closed *before* activation when a
staged resolver config does not pass ``unbound-checkconf``, readiness must be
reached for both units before the caller installs the capture table, and a
teardown must stop both processes. ``enabled=False`` stays inert.
"""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from test_tproxy_apply_integration import enabled_version
from vs_router.agent import tproxy_apply, unbound_service
from vs_router.agent.apply import APPLIED_DIR, FILES, ApplyEngine, ApplyError
from vs_router.generators import tproxy_dns

SELECTED = unbound_service.SELECTED_ROLE
ORDINARY = unbound_service.ORDINARY_ROLE


class UnboundExecutor:
    """Recording executor that mimics ``unbound-checkconf`` and systemd.

    Per-role fields let a test flip exactly one thing to its failing value.
    """

    def __init__(self):
        self.calls = []
        self.check_rc = {SELECTED: 0, ORDINARY: 0}
        self.enable_rc = 0
        self.active = {SELECTED: True, ORDINARY: True}

    def _role_of_check(self, argv):
        for role in unbound_service.ROLES:
            if argv == list(unbound_service.checkconf_argv(role)):
                return role
        return None

    def _role_of_unit(self, argv):
        for role in unbound_service.ROLES:
            if argv and argv[-1] == unbound_service.unit_name(role):
                return role
        return None

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        role = self._role_of_check(argv)
        if role is not None:
            return SimpleNamespace(returncode=self.check_rc[role], stdout="")
        if argv[:3] == ["systemctl", "enable", "--now"]:
            return SimpleNamespace(returncode=self.enable_rc, stdout="")
        if argv[:2] == ["systemctl", "is-active"]:
            role = self._role_of_unit(argv)
            return SimpleNamespace(returncode=0 if self.active[role] else 3, stdout="")
        return SimpleNamespace(returncode=0, stdout="")


def argv_of(executor):
    return [call for call, _ in executor.calls]


def _recording_validators(order):
    def validator(name, path):
        order.append(name)
        return SimpleNamespace(returncode=0)
    return {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}


# --------------------------------------------------------------------------
# Unit identity: names, UIDs, config paths
# --------------------------------------------------------------------------

def test_two_units_and_two_distinct_reserved_uids():
    assert set(unbound_service.ROLES) == {SELECTED, ORDINARY}
    assert unbound_service.unit_name(SELECTED) == "vs-router-unbound-selected.service"
    assert unbound_service.unit_name(ORDINARY) == "vs-router-unbound-ordinary.service"
    assert unbound_service.unit_name(SELECTED) != unbound_service.unit_name(ORDINARY)
    # UIDs come from the plan module, are distinct and are not invented here.
    assert unbound_service.uid_for(SELECTED) == tproxy_dns.TPROXY_SELECTED_UID == 29092
    assert unbound_service.uid_for(ORDINARY) == tproxy_dns.TPROXY_ORDINARY_UID == 29093
    assert unbound_service.uid_for(SELECTED) != unbound_service.uid_for(ORDINARY)
    assert tproxy_dns.ordinary_uid_for(enabled_version()) == 29093


def test_config_paths_match_the_apply_file_map():
    assert unbound_service.config_path(SELECTED) == \
        APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_selected"]
    assert unbound_service.config_path(ORDINARY) == \
        APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_ordinary"]


def test_split_configs_disable_the_privilege_drop():
    # The dedicated systemd User= owns the UID, so the split configs must disable
    # unbound's compiled-in username drop (empty value), or the process refuses to
    # start as a non-root dedicated UID. The ordinary product generator keeps it.
    plan = tproxy_apply.plan(enabled_version())
    for config in (plan.selected_unbound, plan.ordinary_unbound):
        assert 'username: ""' in config
        assert 'username: "unbound"' not in config


def test_unit_is_deterministic_pinned_and_privilege_minimal():
    for role in unbound_service.ROLES:
        text = unbound_service.unit_content(role)
        assert text == unbound_service.unit_content(role)  # deterministic
        assert f"ExecStart={unbound_service.UNBOUND_BINARY} -d -c " \
               f"{unbound_service.config_path(role)}" in text
        assert f"User={unbound_service.uid_for(role)}" in text
        assert "NoNewPrivileges=true" in text
        assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in text
        assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in text
        assert "ProtectSystem=strict" in text
        assert "WantedBy=multi-user.target" in text
        # No secret material is ever placed in a unit.
        lowered = text.lower()
        assert "password" not in lowered and "token" not in lowered
    # The two units differ only by role/UID/config: the selected UID is never
    # reused by the ordinary listener.
    assert "User=29092" in unbound_service.unit_content(SELECTED)
    assert "User=29093" in unbound_service.unit_content(ORDINARY)


def test_unknown_role_fails_closed():
    with pytest.raises(ValueError, match="agent.unbound_role_invalid"):
        unbound_service.unit_content("not-a-role")


# --------------------------------------------------------------------------
# Fixed, shell-free argv
# --------------------------------------------------------------------------

def test_all_argv_are_fixed_lists_without_shell_metacharacters():
    for role in unbound_service.ROLES:
        argv = unbound_service.checkconf_argv(role)
        assert isinstance(argv, tuple)
        assert all(isinstance(token, str) for token in argv)
        assert not any(ch in " \t\r\n;|&$`<>*?\"'\\(){}[]" for token in argv
                       for ch in token)
    # The config path is the pinned absolute constant, never caller input.
    assert unbound_service.checkconf_argv(SELECTED) == (
        unbound_service.UNBOUND_CHECKCONF_BINARY,
        str(unbound_service.config_path(SELECTED)))


def test_start_uses_only_fixed_argv():
    fs, executor = FakeFS(), UnboundExecutor()
    unbound_service.UnboundService(executor, fs).start()
    for argv, _ in executor.calls:
        assert isinstance(argv, list)  # never a shell string
        assert argv[0] in ("systemctl", unbound_service.UNBOUND_CHECKCONF_BINARY)


# --------------------------------------------------------------------------
# Readiness ordering (fail-closed)
# --------------------------------------------------------------------------

def test_start_checks_both_configs_installs_units_then_enables_and_waits():
    fs, executor = FakeFS(), UnboundExecutor()
    unbound_service.UnboundService(executor, fs).start()
    for role in unbound_service.ROLES:
        assert fs.read(unbound_service.unit_path(role)) == \
            unbound_service.unit_content(role)
    argv = argv_of(executor)
    sel_check = list(unbound_service.checkconf_argv(SELECTED))
    ord_check = list(unbound_service.checkconf_argv(ORDINARY))
    sel_enable = ["systemctl", "enable", "--now", unbound_service.unit_name(SELECTED)]
    ord_enable = ["systemctl", "enable", "--now", unbound_service.unit_name(ORDINARY)]
    active = ["systemctl", "is-active", "--quiet", unbound_service.unit_name(SELECTED)]
    # Check every config -> install -> enable both -> prove readiness.
    assert argv.index(sel_check) < argv.index(ord_check) \
        < argv.index(sel_enable) < argv.index(ord_enable) < argv.index(active)


@pytest.mark.parametrize("role", [SELECTED, ORDINARY])
def test_start_blocks_when_a_config_check_fails(role):
    fs, executor = FakeFS(), UnboundExecutor()
    executor.check_rc[role] = 1
    with pytest.raises(ApplyError, match=unbound_service.CONFIG_INVALID):
        unbound_service.UnboundService(executor, fs).start()
    argv = argv_of(executor)
    # No unit is enabled and no unit file is written on an invalid config.
    assert not any(call[:3] == ["systemctl", "enable", "--now"] for call in argv)
    assert unbound_service.unit_path(role) not in fs.files


def test_start_fails_when_a_unit_never_becomes_ready():
    fs, executor = FakeFS(), UnboundExecutor()
    executor.active[ORDINARY] = False
    service = unbound_service.UnboundService(executor, fs, attempts=3,
                                             sleep=lambda _: None)
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        service.start()


def test_start_fails_when_enable_fails():
    fs, executor = FakeFS(), UnboundExecutor()
    executor.enable_rc = 1
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        unbound_service.UnboundService(executor, fs).start()


def test_stop_is_best_effort_and_typed():
    fs, executor = FakeFS(), UnboundExecutor()
    unbound_service.UnboundService(executor, fs).stop()
    assert argv_of(executor) == [
        ["systemctl", "disable", "--now", unbound_service.unit_name(SELECTED)],
        ["systemctl", "disable", "--now", unbound_service.unit_name(ORDINARY)]]


# --------------------------------------------------------------------------
# Wiring into the gated apply phases (readiness before capture)
# --------------------------------------------------------------------------

def _engine(fs=None, executor=None):
    return ApplyEngine(filesystem=fs or FakeFS(), executor=executor or UnboundExecutor(),
                       clock=lambda: 100.0)


def test_readiness_runs_resolvers_after_policy_route_and_before_capture():
    engine = _engine()
    order = []
    engine.reload_commands = {
        tproxy_apply.POLICY_ROUTE_STEP: lambda: order.append("policy"),
        tproxy_apply.UNBOUND_PROCESS_STEP: lambda: order.append("unbound"),
        tproxy_apply.SINGBOX_PROCESS_STEP: lambda: order.append("singbox")}
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))
    assert result.status == "confirmed"
    assert order == ["policy", "unbound", "singbox"]
    assert engine.status()["phases"][tproxy_apply.UNBOUND_PROCESS_STEP] == "applied"
    assert engine.status()["phases"]["tproxy_interception"] == "applied"
    assert engine.status()["tproxy"]["ordinary_uid"] == 29093


def test_readiness_checkconf_failure_blocks_interception():
    fs, executor = FakeFS(), UnboundExecutor()
    executor.check_rc[SELECTED] = 1
    engine = _engine(fs, executor)
    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: lambda: None,
                              tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None}
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))
    assert result.status == "failed"
    assert "tproxy_interception" not in engine.status()["phases"]
    assert APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_interception"] \
        not in fs.files


def test_teardown_stops_both_resolvers_engine_and_route():
    fs, executor = FakeFS(), UnboundExecutor()
    engine = _engine(fs, executor)
    engine._teardown_tproxy_steps()
    argv = [call for call, _ in executor.calls]
    for role in unbound_service.ROLES:
        assert ["systemctl", "disable", "--now", unbound_service.unit_name(role)] in argv


def test_rollback_stops_both_resolvers():
    fs, executor = FakeFS(), UnboundExecutor()
    engine = _engine(fs, executor)
    assert engine.apply_version(snapshot()).status == "confirmed"
    engine.reload_commands = {"tproxy_interception": ["fail-capture"],
                              tproxy_apply.POLICY_ROUTE_STEP: lambda: None,
                              tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None}

    def run(argv, timeout):
        executor.calls.append((argv, timeout))
        if argv == ["fail-capture"]:
            return SimpleNamespace(returncode=1)
        return UnboundExecutor.run(executor, argv, timeout)

    executor.run = run
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))
    assert result.status == "rolled_back"
    argv = [call for call, _ in executor.calls]
    for role in unbound_service.ROLES:
        assert ["systemctl", "disable", "--now", unbound_service.unit_name(role)] in argv


# --------------------------------------------------------------------------
# Inertness for the reachable (enabled=False) configuration
# --------------------------------------------------------------------------

def test_disabled_apply_runs_no_unbound_command():
    fs, executor = FakeFS(), UnboundExecutor()
    engine = _engine(fs, executor)
    result = engine.apply_version(snapshot())
    assert result.status == "confirmed"
    argv = argv_of(executor)
    assert all(call[0] not in ("systemctl", unbound_service.UNBOUND_CHECKCONF_BINARY)
               for call in argv)
    marker = engine.status()
    assert tproxy_apply.UNBOUND_PROCESS_STEP not in marker["phases"]
    assert "tproxy" not in marker
