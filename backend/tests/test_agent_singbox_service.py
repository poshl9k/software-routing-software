"""Typed sing-box lifecycle adapter: pinned binary, config check, readiness.

No real systemd and no real binary: everything runs through a recording fake
executor / ``FakeFS``. The adapter must fail closed *before* activation when the
pinned artifact or the staged config is not proven good, and readiness must be
reached before the caller installs the capture table.
"""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeExecutor, FakeFS
from vs_router.agent import singbox_service, tproxy_apply
from vs_router.agent.apply import ApplyEngine, ApplyError

#: Exactly the shape ``sing-box version`` prints for the pinned release
#: (ADR-0012): version line + provenance revision.
VERSION_OUTPUT = (
    "sing-box version 1.14.2\n"
    "\n"
    "Environment: go1.26.8 linux/amd64\n"
    "Tags: with_gvisor,with_quic,with_wireguard\n"
    "Revision: af6e64c3b69e6132ebaee0e1a3d24e93903f6709\n"
    "CGO: disabled\n"
)
#: ``sha256sum <binary>`` prints ``<digest>  <path>``.
DIGEST_OUTPUT = f"{singbox_service.SINGBOX_BINARY_SHA256}  {singbox_service.SINGBOX_BINARY}\n"


class PinExecutor:
    """Recording executor that mimics the pinned binary and systemd.

    ``stdout`` is provided so the adapter's version/SHA256 verification can be
    exercised. Fields let a test flip exactly one thing to its failing value.
    """

    def __init__(self):
        self.calls = []
        self.version_rc = 0
        self.version_output = VERSION_OUTPUT
        self.digest_rc = 0
        self.digest_output = DIGEST_OUTPUT
        self.check_rc = 0
        self.enable_rc = 0
        self.active = True

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv == list(singbox_service.SINGBOX_VERSION_ARGV):
            return SimpleNamespace(returncode=self.version_rc, stdout=self.version_output)
        if argv == list(singbox_service.SINGBOX_DIGEST_ARGV):
            return SimpleNamespace(returncode=self.digest_rc, stdout=self.digest_output)
        if argv == list(singbox_service.SINGBOX_CHECK_ARGV):
            return SimpleNamespace(returncode=self.check_rc, stdout="")
        if argv[:3] == ["systemctl", "enable", "--now"]:
            return SimpleNamespace(returncode=self.enable_rc, stdout="")
        if argv[:2] == ["systemctl", "is-active"]:
            return SimpleNamespace(returncode=0 if self.active else 3, stdout="")
        return SimpleNamespace(returncode=0, stdout="")


def argv_of(executor):
    return [call for call, _ in executor.calls]


# --------------------------------------------------------------------------
# Release pinning (ADR-0012)
# --------------------------------------------------------------------------

def test_constants_are_pinned_to_the_adr_artifact():
    assert singbox_service.SINGBOX_VERSION == "1.14.2"
    assert singbox_service.SINGBOX_ARCHIVE_SHA256 == (
        "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6")
    assert singbox_service.SINGBOX_BINARY_SHA256 == (
        "fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8")
    assert singbox_service.SINGBOX_PROVENANCE_REVISION == (
        "af6e64c3b69e6132ebaee0e1a3d24e93903f6709")
    assert singbox_service.SINGBOX_BINARY == "/usr/local/lib/vs-router/sing-box"


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


# --------------------------------------------------------------------------
# Fixed, shell-free argv
# --------------------------------------------------------------------------

def test_all_argv_are_fixed_lists_without_shell_metacharacters():
    for argv in (singbox_service.SINGBOX_VERSION_ARGV,
                 singbox_service.SINGBOX_CHECK_ARGV,
                 singbox_service.SINGBOX_DIGEST_ARGV):
        assert isinstance(argv, tuple)
        assert all(isinstance(token, str) for token in argv)
        assert not any(ch in " \t\r\n;|&$`<>*?\"'\\(){}[]" for token in argv
                       for ch in token)
    # The config path is the pinned absolute constant, not caller input.
    assert singbox_service.SINGBOX_CHECK_ARGV == (
        singbox_service.SINGBOX_BINARY, "check", "-c", singbox_service.SINGBOX_CONFIG)


def test_start_uses_only_fixed_argv():
    fs, executor = FakeFS(), PinExecutor()
    singbox_service.SingboxService(executor, fs).start()
    for argv, _ in executor.calls:
        assert isinstance(argv, list)  # never a shell string
        assert singbox_service.SINGBOX_CONFIG in argv or argv[0] in (
            "systemctl", "sha256sum", singbox_service.SINGBOX_BINARY)


# --------------------------------------------------------------------------
# Binary verification (fail-closed)
# --------------------------------------------------------------------------

def test_start_verifies_binary_checks_config_then_enables():
    fs, executor = FakeFS(), PinExecutor()
    singbox_service.SingboxService(executor, fs).start()
    assert fs.read(singbox_service.UNIT_PATH) == singbox_service.unit_content()
    argv = argv_of(executor)
    version = list(singbox_service.SINGBOX_VERSION_ARGV)
    digest = list(singbox_service.SINGBOX_DIGEST_ARGV)
    check = list(singbox_service.SINGBOX_CHECK_ARGV)
    enable = ["systemctl", "enable", "--now", singbox_service.SINGBOX_UNIT]
    active = ["systemctl", "is-active", "--quiet", singbox_service.SINGBOX_UNIT]
    assert enable in argv and active in argv
    # Verify -> check -> enable -> ready, in that order.
    assert argv.index(version) < argv.index(digest) < argv.index(check) \
        < argv.index(enable) < argv.index(active)


@pytest.mark.parametrize("field,value", [
    ("version_rc", 1),                     # binary missing / not runnable
    ("version_output", "sing-box version 1.13.0\n"),   # wrong version
    ("version_output", VERSION_OUTPUT.replace(
        singbox_service.SINGBOX_PROVENANCE_REVISION, "deadbeef")),  # foreign build
])
def test_verification_rejects_unpinned_binary(field, value):
    fs, executor = FakeFS(), PinExecutor()
    setattr(executor, field, value)
    service = singbox_service.SingboxService(executor, fs)
    with pytest.raises(ApplyError, match=singbox_service.BINARY_UNVERIFIED):
        service.start()
    # Nothing was enabled and the config was never checked.
    argv = argv_of(executor)
    assert ["systemctl", "enable", "--now", singbox_service.SINGBOX_UNIT] not in argv
    assert list(singbox_service.SINGBOX_CHECK_ARGV) not in argv


@pytest.mark.parametrize("field,value", [
    ("digest_rc", 1),                      # sha256sum failed (unreadable/missing)
    ("digest_output", "0" * 64 + "\n"),    # digest mismatch
])
def test_verification_rejects_bad_digest(field, value):
    fs, executor = FakeFS(), PinExecutor()
    setattr(executor, field, value)
    with pytest.raises(ApplyError, match=singbox_service.BINARY_UNVERIFIED):
        singbox_service.SingboxService(executor, fs).start()


# --------------------------------------------------------------------------
# Config check and readiness block interception
# --------------------------------------------------------------------------

def test_start_blocks_when_config_check_fails():
    fs, executor = FakeFS(), PinExecutor()
    executor.check_rc = 1
    with pytest.raises(ApplyError, match=singbox_service.CONFIG_INVALID):
        singbox_service.SingboxService(executor, fs).start()
    argv = argv_of(executor)
    assert list(singbox_service.SINGBOX_CHECK_ARGV) in argv
    # The unit is never enabled when the config does not validate.
    assert ["systemctl", "enable", "--now", singbox_service.SINGBOX_UNIT] not in argv


def test_start_fails_when_unit_never_becomes_ready():
    fs, executor = FakeFS(), PinExecutor()
    executor.active = False
    service = singbox_service.SingboxService(executor, fs, attempts=3,
                                             sleep=lambda _: None)
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        service.start()


def test_start_fails_when_enable_fails():
    fs, executor = FakeFS(), PinExecutor()
    executor.enable_rc = 1
    with pytest.raises(ApplyError, match="agent.reload_failed"):
        singbox_service.SingboxService(executor, fs).start()


def test_stop_is_best_effort_and_typed():
    fs, executor = FakeFS(), PinExecutor()
    singbox_service.SingboxService(executor, fs).stop()
    assert argv_of(executor) == [
        ["systemctl", "disable", "--now", singbox_service.SINGBOX_UNIT]]


# --------------------------------------------------------------------------
# Inertness for the reachable (enabled=False) configuration
# --------------------------------------------------------------------------

def test_disabled_apply_runs_no_singbox_command():
    fs, executor = FakeFS(), PinExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    result = engine.apply_version({"id": 1, "status": "draft", "configuration": {}})
    assert result.status == "confirmed"
    # A disabled config never surfaces the engine adapter or the pin checks.
    argv = argv_of(executor)
    assert all(call[0] not in ("ip", "systemctl", "sha256sum",
                               singbox_service.SINGBOX_BINARY) for call in argv)
    marker = engine.status()
    assert marker is not None
    assert tproxy_apply.SINGBOX_PROCESS_STEP not in marker["phases"]
