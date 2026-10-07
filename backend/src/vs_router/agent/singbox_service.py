"""Typed sing-box process lifecycle adapter for the gated TProxy engine.

Generates a systemd unit for a *pinned* sing-box binary and starts/stops it and
proves readiness through fixed ``systemctl`` argv only. The TProxy phase contract
(:mod:`vs_router.agent.tproxy_apply`) requires the engine to be *ready* before
the capture table is installed, so :meth:`SingboxService.start` does not return
until ``systemctl is-active --quiet`` reports the unit up.

Safety
------
* The binary and config paths are module constants (release pinning, ADR-0005);
  nothing from the RPC or the configuration reaches ``argv``.
* The unit grants exactly one capability (``CAP_NET_ADMIN`` for the loopback
  ``IP_TRANSPARENT`` listener), drops new privileges, and hardens the sandbox.
* No secret is ever written to the unit or logged: the engine reads its own
  ``singbox.json`` (which carries only generator placeholders), and this adapter
  reports only error codes.
"""
from __future__ import annotations

from pathlib import Path

from .apply import ApplyError

#: Unit and pinned artifact locations. The binary is chosen by release pinning
#: (ADR-0005); it is a fixed absolute path, never a value from the RPC.
SINGBOX_UNIT = "vs-router-singbox.service"
SINGBOX_BINARY = "/usr/local/lib/vs-router/sing-box"
SINGBOX_CONFIG = "/etc/vs-router/applied/singbox.json"
UNIT_PATH = Path("/etc/systemd/system") / SINGBOX_UNIT
READINESS_ATTEMPTS = 50
READINESS_INTERVAL = 0.1

#: The only capability the loopback TProxy listener needs (``IP_TRANSPARENT``).
SINGBOX_CAPABILITIES = "CAP_NET_ADMIN"


def unit_content() -> str:
    """Deterministic systemd unit text for the pinned engine binary.

    Minimal privileges: one capability, no new privileges, read-only system,
    private tmp, no home, restricted address families and namespaces. No secret
    is placed in the unit (the engine reads its own config file).
    """
    return (
        "[Unit]\n"
        "Description=vs-router sing-box TProxy engine\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={SINGBOX_BINARY} run -c {SINGBOX_CONFIG}\n"
        "Restart=on-failure\n"
        "NoNewPrivileges=true\n"
        f"AmbientCapabilities={SINGBOX_CAPABILITIES}\n"
        f"CapabilityBoundingSet={SINGBOX_CAPABILITIES}\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "ProtectKernelTunables=true\n"
        "ProtectControlGroups=true\n"
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
        "RestrictNamespaces=true\n"
        "LockPersonality=true\n"
        "MemoryDenyWriteExecute=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class SingboxService:
    """Executor/filesystem-backed start/stop/readiness for the engine unit."""

    def __init__(self, executor, filesystem, unit_path=UNIT_PATH,
                 unit=SINGBOX_UNIT, attempts=READINESS_ATTEMPTS, sleep=None):
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

    def is_active(self) -> bool:
        return self.executor.run(
            ["systemctl", "is-active", "--quiet", self.unit], 15).returncode == 0

    def ready(self) -> bool:
        """Readiness signal consulted before interception is authorized."""
        return self.is_active()

    def start(self) -> None:
        self.install_unit()
        if self.executor.run(["systemctl", "enable", "--now", self.unit], 15).returncode:
            raise ApplyError("agent.reload_failed")
        for _ in range(self.attempts):
            if self.ready():
                return
            self.sleep(READINESS_INTERVAL)
        raise ApplyError("agent.reload_failed")

    def stop(self) -> None:
        # Best-effort teardown: a missing/inactive unit is not an error.
        self.executor.run(["systemctl", "disable", "--now", self.unit], 15)

    def __call__(self) -> None:
        self.start()
