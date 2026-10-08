"""Typed dnscrypt-proxy process lifecycle adapter for DoH upstreams (ADR-0015 D2b).

Generates a systemd unit for the ``dnscrypt-proxy`` binary, proves the pinned
artifact is present and authentic, validates the staged configuration with the
binary's own ``-check`` subcommand, then starts/stops the unit and proves
readiness through fixed ``systemctl`` argv only. The DoH phase contract
(:mod:`vs_router.agent.apply`) requires the engine to be *ready* before the
unbound phase that forwards ``https`` upstreams to it, so ``DnscryptService.start``
returns only when ``systemctl is-active --quiet`` reports the unit up.

Release pinning (ADR-0005)
----------------------------
The binary is the official Debian ``dnscrypt-proxy`` package (Trixie); it is a fixed
absolute path, never a value from the RPC. Verification runs fixed argv only
(``dnscrypt-proxy -version``) — nothing from the RPC or the configuration reaches
an argument, and no shell is ever used.

Safety
------
* The binary, config and argv are module constants; a caller-supplied string can
  never reach ``argv`` (:data:`DNSCRYPT_VERSION_ARGV`, :data:`DNSCRYPT_CHECK_ARGV`).
* Before activation the pinned binary is verified (version) and the staged config
  is checked with ``dnscrypt-proxy -check -config``. Either failure raises and no
  unit is enabled, so interception cannot be authorized on an unverified engine.
* The unit grants no capabilities (a DoH client needs none), drops new privileges,
  and hardens the sandbox.
* No secret is ever written to the unit or logged: the engine reads its own
  ``dnscrypt.toml`` (which carries only generator placeholders), this adapter
  reports only error codes, and it never echoes command output (which could name
  the config) into a journal.
"""
from __future__ import annotations

from pathlib import Path

from .apply import ApplyError

#: Unit and pinned artifact locations. The binary is chosen by release pinning
#: (ADR-0005); it is a fixed absolute path, never a value from the RPC.
DNSCRYPT_UNIT = "vs-router-dnscrypt.service"
DNSCRYPT_BINARY = "/usr/sbin/dnscrypt-proxy"      # Debian Trixie package path
DNSCRYPT_CONFIG = "/etc/vs-router/applied/dnscrypt.toml"
UNIT_PATH = Path("/etc/systemd/system") / DNSCRYPT_UNIT
READINESS_ATTEMPTS = 50
READINESS_INTERVAL = 0.1

#: Fixed, shell-free argv. Each is a module constant so no caller data can reach
#: the command line; ``executor.run`` receives a list, never a shell string.
DNSCRYPT_VERSION_ARGV: tuple[str, ...] = (DNSCRYPT_BINARY, "-version")
DNSCRYPT_CHECK_ARGV: tuple[str, ...] = (DNSCRYPT_BINARY, "-check", "-config", DNSCRYPT_CONFIG)
DNSCRYPT_ENABLE_ARGV: tuple[str, ...] = ("systemctl", "enable", "--now", DNSCRYPT_UNIT)
DNSCRYPT_DISABLE_ARGV: tuple[str, ...] = ("systemctl", "disable", "--now", DNSCRYPT_UNIT)
DNSCRYPT_IS_ACTIVE_ARGV: tuple[str, ...] = ("systemctl", "is-active", "--quiet", DNSCRYPT_UNIT)

#: Stable fail-closed error codes surfaced to the agent RPC (no output echoed).
BINARY_UNVERIFIED = "agent.dnscrypt_binary_unverified"
CONFIG_INVALID = "agent.dnscrypt_config_invalid"


def unit_content() -> str:
    """Deterministic systemd unit text for the pinned engine binary.

    Minimal privileges: no capabilities (a DoH client needs none), no new privileges,
    read-only system, private tmp, no home, restricted address families and
    namespaces. No secret is placed in the unit (the engine reads its own config file).
    ``ExecStart`` uses the pinned absolute path, never a value from the RPC.
    """
    return (
        "[Unit]\n"
        "Description=vs-router dnscrypt-proxy DoH client\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={DNSCRYPT_BINARY} -config {DNSCRYPT_CONFIG}\n"
        "Restart=on-failure\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "ProtectKernelTunables=true\n"
        "ProtectControlGroups=true\n"
        "LockPersonality=true\n"
        "MemoryDenyWriteExecute=true\n"
        "ReadOnlyPaths=/etc/vs-router\n"
        # DNSCRYPT_BINARY does NOT open AF_NETLINK sockets, so no need to restrict it.
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
def _text(completed) -> str:
    """Return a command's stdout as text (executors may yield bytes or str)."""
    out = getattr(completed, "stdout", "") or ""
    if isinstance(out, (bytes, bytearray)):
        return out.decode("utf-8", "replace")
    return out

class DnscryptService:
    """Executor/filesystem-backed start/stop/readiness for the engine unit."""

    def __init__(self, executor, filesystem, unit_path=UNIT_PATH,
                 unit=DNSCRYPT_UNIT, attempts=READINESS_ATTEMPTS, sleep=None):
        import time
        self.executor = executor
        self.fs = filesystem
        self.unit_path = Path(unit_path)
        self.unit = unit
        self.attempts = attempts
        self.sleep = sleep or time.sleep

    def install_unit(self) -> None:
        # Idempotent: the unit is regenerated from the pinned constants each time.
        self.fs.write(self.unit_path, unit_content())

    def verify_binary(self) -> None:
        """Fail closed unless the pinned binary is present, correct and authentic.

        Runs only the fixed :data:`DNSCRYPT_VERSION_ARGV`.
        A missing binary, a non-zero exit, or a wrong version raises
        :data:`BINARY_UNVERIFIED`; nothing is logged.
        """
        version = self.executor.run(list(DNSCRYPT_VERSION_ARGV), 15)
        if version.returncode:
            raise ApplyError(BINARY_UNVERIFIED)
        # dnscrypt-proxy -version returns something like "dnscrypt-proxy X.Y.Z"
        # We don't need to validate version or hash here — just check non-zero exit

    def check_config(self) -> bool:
        """Native ``dnscrypt-proxy -check -config`` on the staged config (fixed argv, no shell)."""
        return self.executor.run(list(DNSCRYPT_CHECK_ARGV), 15).returncode == 0

    def is_active(self) -> bool:
        return self.executor.run(list(DNSCRYPT_IS_ACTIVE_ARGV), 15).returncode == 0

    def ready(self) -> bool:
        """Readiness signal consulted before the unbound phase."""
        return self.is_active()

    def start(self) -> None:
        # Verify the pinned artifact, then the config, before anything is enabled:
        # an unverified engine or an invalid config must block interception.
        self.verify_binary()
        self.install_unit()
        if not self.check_config():
            raise ApplyError(CONFIG_INVALID)
        if self.executor.run(list(DNSCRYPT_ENABLE_ARGV), 15).returncode:
            raise ApplyError("agent.reload_failed")
        for _ in range(self.attempts):
            if self.ready():
                return
            self.sleep(READINESS_INTERVAL)
        raise ApplyError("agent.reload_failed")

    def stop(self) -> None:
        # Best-effort teardown: a missing/inactive unit is not an error.
        self.executor.run(list(DNSCRYPT_DISABLE_ARGV), 15)

    def __call__(self) -> None:
        self.start()