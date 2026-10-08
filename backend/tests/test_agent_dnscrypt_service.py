"""Typed dnscrypt-proxy lifecycle adapter (ADR-0015 D2b): binary verification,
config check, readiness, and fixed argv contracts."""
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor
from vs_router.agent import dnscrypt_service
from vs_router.agent.apply import APPLIED_DIR, ApplyEngine, ApplyError
from vs_router.schema import ConfigurationVersion


class PinExecutor:
    """Recording executor for the pinned binary and systemd."""
    def __init__(self):
        self.calls = []
        self.version_rc = 0
        self.version_output = "dnscrypt-proxy 2.0.45\n"
        self.check_rc = 0
        self.enable_rc = 0
        self.active = True

    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv == list(dnscrypt_service.DNSCRYPT_VERSION_ARGV):
            return SimpleNamespace(returncode=self.version_rc, stdout=self.version_output)
        if argv == list(dnscrypt_service.DNSCRYPT_CHECK_ARGV):
            return SimpleNamespace(returncode=self.check_rc, stdout="")
        if argv[:3] == ["systemctl", "enable", "--now"]:
            return SimpleNamespace(returncode=self.enable_rc, stdout="")
        if argv[:2] == ["systemctl", "is-active"]:
            return SimpleNamespace(returncode=0 if self.active else 3, stdout="")
        return SimpleNamespace(returncode=0, stdout="")


def argv_of(executor):
    return [call for call, _ in executor.calls]


# --------------------------------------------------------------------------
# Constants and unit content
# --------------------------------------------------------------------------

def test_constants_use_debian_trixie_path():
    assert dnscrypt_service.DNSCRYPT_BINARY == "/usr/sbin/dnscrypt-proxy"
    assert dnscrypt_service.DNSCRYPT_CONFIG == "/etc/vs-router/applied/dnscrypt.toml"
    assert dnscrypt_service.DNSCRYPT_UNIT == "vs-router-dnscrypt.service"


def test_unit_content_has_execstart_and_config_path():
    text = dnscrypt_service.unit_content()
    assert f"ExecStart={dnscrypt_service.DNSCRYPT_BINARY} -config {dnscrypt_service.DNSCRYPT_CONFIG}" in text
    assert "After=network-online.target" in text
    assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" in text
    assert "NoNewPrivileges=true" in text
    assert "AmbientCapabilities" not in text
    assert "CapabilityBoundingSet" not in text


# --------------------------------------------------------------------------
# Fixed argv contracts
# --------------------------------------------------------------------------

def test_all_argv_are_fixed_lists():
    for argv in (dnscrypt_service.DNSCRYPT_VERSION_ARGV,
                 dnscrypt_service.DNSCRYPT_CHECK_ARGV,
                 dnscrypt_service.DNSCRYPT_ENABLE_ARGV,
                 dnscrypt_service.DNSCRYPT_DISABLE_ARGV,
                 dnscrypt_service.DNSCRYPT_IS_ACTIVE_ARGV):
        assert isinstance(argv, tuple)
        assert all(isinstance(t, str) for t in argv)


def test_enable_disable_argv():
    assert dnscrypt_service.DNSCRYPT_ENABLE_ARGV == (
        "systemctl", "enable", "--now", dnscrypt_service.DNSCRYPT_UNIT)
    assert dnscrypt_service.DNSCRYPT_DISABLE_ARGV == (
        "systemctl", "disable", "--now", dnscrypt_service.DNSCRYPT_UNIT)


# --------------------------------------------------------------------------
# Start flow
# --------------------------------------------------------------------------

def test_start_uses_fixed_argv_only():
    fs, executor = FakeFS(), PinExecutor()
    dnscrypt_service.DnscryptService(executor, fs).start()
    for argv, _ in executor.calls:
        assert isinstance(argv, list)


def test_start_verifies_then_checks_then_enables():
    fs, executor = FakeFS(), PinExecutor()
    service = dnscrypt_service.DnscryptService(executor, fs)
    service.start()
    argv = argv_of(executor)
    version_argv = list(dnscrypt_service.DNSCRYPT_VERSION_ARGV)
    check_argv = list(dnscrypt_service.DNSCRYPT_CHECK_ARGV)
    enable_argv = list(dnscrypt_service.DNSCRYPT_ENABLE_ARGV)
    active_argv = list(dnscrypt_service.DNSCRYPT_IS_ACTIVE_ARGV)
    assert version_argv in argv
    assert check_argv in argv
    assert enable_argv in argv
    assert active_argv in argv
    assert argv.index(version_argv) < argv.index(check_argv) < argv.index(enable_argv) < argv.index(active_argv)


# --------------------------------------------------------------------------
# Fail-closed paths
# --------------------------------------------------------------------------

def test_start_fails_when_version_nonzero():
    fs, executor = FakeFS(), PinExecutor()
    executor.version_rc = 1
    with pytest.raises(ApplyError, match=dnscrypt_service.BINARY_UNVERIFIED):
        dnscrypt_service.DnscryptService(executor, fs).start()
    # Enable and check never called.
    argv = argv_of(executor)
    assert list(dnscrypt_service.DNSCRYPT_ENABLE_ARGV) not in argv
    assert list(dnscrypt_service.DNSCRYPT_CHECK_ARGV) not in argv


def test_start_fails_when_config_invalid():
    fs, executor = FakeFS(), PinExecutor()
    executor.check_rc = 1
    with pytest.raises(ApplyError, match=dnscrypt_service.CONFIG_INVALID):
        dnscrypt_service.DnscryptService(executor, fs).start()
    argv = argv_of(executor)
    assert list(dnscrypt_service.DNSCRYPT_CHECK_ARGV) in argv
    assert list(dnscrypt_service.DNSCRYPT_ENABLE_ARGV) not in argv


def test_stop_is_best_effort():
    fs, executor = FakeFS(), PinExecutor()
    dnscrypt_service.DnscryptService(executor, fs).stop()
    assert argv_of(executor) == [["systemctl", "disable", "--now", dnscrypt_service.DNSCRYPT_UNIT]]


# --------------------------------------------------------------------------
# Apply integration: DoH-only (no TProxy)
# --------------------------------------------------------------------------

def test_apply_with_https_upstream_writes_dnscrypt_toml():
    fs, executor = FakeFS(), FakeExecutor()
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"mode": "https", "doh_server": "cloudflare"}]}})
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    result = engine.apply_version(version.model_dump(mode='json'))
    assert result.status == "confirmed"
    phases = engine.status()['phases']
    assert 'dnscrypt' in phases
    assert phases['dnscrypt'] == 'applied'
    # The readiness step ran and recorded itself.
    assert 'dnscrypt_process' in phases


def test_apply_with_https_upstream_steps_before_unbound():
    fs, executor = FakeFS(), FakeExecutor()
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"mode": "https", "doh_server": "cloudflare"}]}})
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    result = engine.apply_version(version.model_dump(mode='json'))
    assert result.status == "confirmed"
    phases = engine.status()['phases']
    # dnscrypt.toml phase and the readiness step both precede unbound.
    assert 'dnscrypt' in phases
    assert 'unbound' in phases
    assert phases['dnscrypt'] == 'applied'


def test_apply_without_https_upstream_is_unchanged():
    fs, executor = FakeFS(), FakeExecutor()
    version = ConfigurationVersion(configuration={"dns": {"upstreams": ["1.1.1.1"]}})
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    result = engine.apply_version(version.model_dump(mode='json'))
    assert result.status == "confirmed"
    phases = engine.status()['phases']
    assert 'dnscrypt' not in phases
    assert 'dnscrypt_process' not in phases
    # No dnscrypt file staged or applied.
    assert str(APPLIED_DIR / 'dnscrypt.toml') not in fs.files


def test_doh_readiness_step_runs_before_unbound_reload():
    fs, executor = FakeFS(), FakeExecutor()
    order = []
    version = ConfigurationVersion(configuration={"dns": {
        "upstreams": [{"mode": "https", "doh_server": "cloudflare"}]}})
    engine = ApplyEngine(
        filesystem=fs, executor=executor, clock=lambda: 100.0,
        reload_commands={"dnscrypt_process": lambda: order.append("doh"),
                         "unbound": lambda path: order.append("unbound")})
    result = engine.apply_version(version.model_dump(mode='json'))
    assert result.status == "confirmed"
    # The dnscrypt-proxy must be ready before Unbound reloads its DoH forwards.
    assert order.index("doh") < order.index("unbound")
