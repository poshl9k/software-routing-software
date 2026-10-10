"""Typed sing-box process lifecycle adapter for the gated TProxy engine.

Generates a systemd unit for a *pinned* sing-box binary, proves the pinned
artifact is present and authentic, validates the staged configuration with the
pinned binary's own ``check`` subcommand, then starts/stops the unit and proves
readiness through fixed ``systemctl`` argv only. The TProxy phase contract
(:mod:`vs_router.agent.tproxy_apply`) requires the engine to be *ready* before
the capture table is installed, so :meth:`SingboxService.start` does not return
until ``systemctl is-active --quiet`` reports the unit up.

Release pinning (ADR-0012 / ADR-0005)
-------------------------------------
The engine is the official ``SagerNet/sing-box`` ``v1.14.2`` ``linux/amd64``
GitHub Release. The archive SHA256 is the ADR-0012 pin; the extracted ``sing-box``
ELF digest and provenance revision are pinned constants too, so a swapped or
stale binary fails closed *before* the unit is enabled. Verification runs fixed
argv only (``sing-box version`` and ``sha256sum``) — nothing from the RPC or the
configuration reaches an argument, and no shell is ever used.

Safety
------
* The binary, config and argv are module constants; a caller-supplied string can
  never reach ``argv`` (:data:`SINGBOX_VERSION_ARGV`, :data:`SINGBOX_CHECK_ARGV`,
  :data:`SINGBOX_DIGEST_ARGV`).
* Before activation the pinned binary is verified (version + provenance revision
  + SHA256) and the staged config is checked with ``sing-box check -c``. Either
  failure raises and no unit is enabled, so interception cannot be authorized on
  an unverified engine.
* The unit grants exactly one capability (``CAP_NET_ADMIN`` for the loopback
  ``IP_TRANSPARENT`` listener), drops new privileges, and hardens the sandbox.
* No secret is ever written to the unit or logged: the engine reads its own
  ``singbox.json`` (which carries only generator placeholders), this adapter
  reports only error codes, and it never echoes command output (which could name
  the config) into a journal.
"""
from __future__ import annotations

import re
from pathlib import Path

from .apply import ApplyError

#: Unit and pinned artifact locations. The binary is chosen by release pinning
#: (ADR-0012); it is a fixed absolute path, never a value from the RPC.
SINGBOX_UNIT = "vs-router-singbox.service"
SINGBOX_BINARY = "/usr/local/lib/vs-router/sing-box"
SINGBOX_CONFIG = "/etc/vs-router/applied/singbox.json"
UNIT_PATH = Path("/etc/systemd/system") / SINGBOX_UNIT
READINESS_ATTEMPTS = 50
READINESS_INTERVAL = 0.1

#: Release pin (ADR-0012). ``SINGBOX_ARCHIVE_SHA256`` is the digest of the
#: published asset ``sing-box-1.14.2-linux-amd64.tar.gz``;
#: ``SINGBOX_BINARY_SHA256`` is the digest of the extracted ``sing-box`` ELF that
#: ``ExecStart`` runs and that this adapter verifies. Both are constants — a hash
#: from another architecture or an unpublished file is never accepted.
SINGBOX_VERSION = "1.14.2"
SINGBOX_ARCHIVE_SHA256 = (
    "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6")
SINGBOX_BINARY_SHA256 = (
    "fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8")
#: Provenance commit the release build reports (ADR-0012). A different build of
#: the same version string must not pass verification.
SINGBOX_PROVENANCE_REVISION = "af6e64c3b69e6132ebaee0e1a3d24e93903f6709"

#: Fixed, shell-free argv. Each is a module constant so no caller data can reach
#: the command line; ``executor.run`` receives a list, never a shell string.
SINGBOX_VERSION_ARGV: tuple[str, ...] = (SINGBOX_BINARY, "version")
SINGBOX_CHECK_ARGV: tuple[str, ...] = (SINGBOX_BINARY, "check", "-c", SINGBOX_CONFIG)
SINGBOX_DIGEST_ARGV: tuple[str, ...] = ("sha256sum", SINGBOX_BINARY)

#: Stable fail-closed error codes surfaced to the agent RPC (no output echoed).
BINARY_UNVERIFIED = "agent.singbox_binary_unverified"
CONFIG_INVALID = "agent.singbox_config_invalid"

#: The only capability the loopback TProxy listener needs (``IP_TRANSPARENT``).
SINGBOX_CAPABILITIES = "CAP_NET_ADMIN"

_VERSION_RE = re.compile(r"^sing-box version\s+(\S+)\s*$", re.MULTILINE)
_PROVENANCE_RE = re.compile(r"^Revision:\s*(\S+)\s*$", re.MULTILINE)
_DIGEST_RE = re.compile(r"^\s*([0-9a-fA-F]{64})\b")


def unit_content() -> str:
    """Deterministic systemd unit text for the pinned engine binary.

    Minimal privileges: one capability, no new privileges, read-only system,
    private tmp, no home, restricted address families and namespaces. No secret
    is placed in the unit (the engine reads its own config file). ``ExecStart``
    uses the pinned absolute path, never a value from the RPC.
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
        # sing-box opens an AF_NETLINK socket at startup (auto_detect_interface /
        # route monitoring); omitting AF_NETLINK makes the pinned engine fail
        # closed under this sandbox ("create netlink socket: address family not
        # supported"). Proven on a disposable Debian VM (docs/lab-32).
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"
        "RestrictNamespaces=true\n"
        "LockPersonality=true\n"
        "MemoryDenyWriteExecute=true\n"
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


def _version_ok(output: str) -> bool:
    """True iff ``output`` is the pinned version *and* provenance revision."""
    version = _VERSION_RE.search(output)
    provenance = _PROVENANCE_RE.search(output)
    return (version is not None and version.group(1) == SINGBOX_VERSION
            and provenance is not None
            and provenance.group(1) == SINGBOX_PROVENANCE_REVISION)


def _digest_ok(output: str) -> bool:
    """True iff ``output`` (``sha256sum`` form) carries the pinned binary hash."""
    match = _DIGEST_RE.match(output)
    return match is not None and match.group(1).lower() == SINGBOX_BINARY_SHA256


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

    def verify_binary(self) -> None:
        """Fail closed unless the pinned binary is present, correct and authentic.

        Runs only the fixed :data:`SINGBOX_VERSION_ARGV` / :data:`SINGBOX_DIGEST_ARGV`.
        A missing binary, a non-zero exit, a wrong version, a foreign provenance
        revision or a digest mismatch all raise :data:`BINARY_UNVERIFIED`; nothing
        is logged.
        """
        version = self.executor.run(list(SINGBOX_VERSION_ARGV), 15)
        if version.returncode or not _version_ok(_text(version)):
            raise ApplyError(BINARY_UNVERIFIED)
        digest = self.executor.run(list(SINGBOX_DIGEST_ARGV), 15)
        if digest.returncode or not _digest_ok(_text(digest)):
            raise ApplyError(BINARY_UNVERIFIED)

    def check_config(self) -> bool:
        """Native ``sing-box check -c`` on the staged config (fixed argv, no shell)."""
        return self.executor.run(list(SINGBOX_CHECK_ARGV), 15).returncode == 0

    def is_active(self) -> bool:
        return self.executor.run(
            ["systemctl", "is-active", "--quiet", self.unit], 15).returncode == 0

    def ready(self) -> bool:
        """Readiness signal consulted before interception is authorized."""
        return self.is_active()

    def start(self) -> None:
        # Verify the pinned artifact, then the config, before anything is enabled:
        # an unverified engine or an invalid config must block interception.
        self.verify_binary()
        self.install_unit()
        if not self.check_config():
            raise ApplyError(CONFIG_INVALID)
        if self.executor.run(["systemctl", "disable", self.unit], 15).returncode:
            raise ApplyError("agent.reload_failed")
        # Boot restore starts the engine after guards; never auto-start it at
        # multi-user.target before the fail-closed nft boundary exists.
        if self.executor.run(["systemctl", "restart", self.unit], 15).returncode:
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
