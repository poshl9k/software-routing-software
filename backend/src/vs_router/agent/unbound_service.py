"""Typed Unbound process lifecycle adapter for the gated TProxy DNS contour.

ADR-0014 fixes the DNS contour as **two** resolver processes: a *selected*
Unbound (own listener, own numeric UID, cache off, unmatched forwarded to the
loopback sing-box stub) and an *ordinary* Unbound (current behaviour, distinct
numeric UID). :mod:`generators.tproxy_dns` composes their config text and the
selected UID; this module is the *only* place the agent turns that contour into
two deterministic systemd units and fixed ``systemctl``/``unbound-checkconf``
argv.

Safety
------
* Unit names, config paths, UIDs and argv are module constants. A caller-supplied
  string can never reach ``argv``: :func:`checkconf_argv` and the ``systemctl``
  calls are built from the role registry only, and ``executor.run`` receives a
  list, never a shell string.
* ``start`` fails closed **before** enabling anything: each config must pass
  native ``unbound-checkconf`` and both units must reach ``systemctl is-active``
  before it returns. Either failure raises; no unit is enabled on an invalid
  config, so interception cannot be authorized on an unproven resolver.
* Minimal privileges: no new privileges, one capability (``CAP_NET_BIND_SERVICE``
  for the ``:53`` listener), read-only system, private tmp, restricted address
  families/namespaces. No secret is placed in a unit (each resolver reads its own
  generated config) and no command output is echoed.
* The two processes have distinct numeric UIDs — the selected one from
  :data:`generators.tproxy_dns.TPROXY_SELECTED_UID`, the ordinary one from the
  sibling reserved constant — so the OUTPUT guard's ``meta skuid`` boundary and
  the resolver processes cannot drift apart.

This is the scaffold counterpart of :mod:`agent.singbox_service`: it is
unreachable from any valid configuration while ``tproxy.not_available`` stays
closed (only an offline ``model_copy`` snapshot reaches the enabled branch).
"""
from __future__ import annotations

from pathlib import Path

from . import tproxy_apply
from .apply import ApplyError
from ..generators import tproxy_dns

#: Roles and their reserved locations. The config filenames are taken from the
#: apply scaffold's file map so the unit ``ExecStart`` path and the artifact the
#: apply phase stages can never disagree.
SELECTED_ROLE = "selected"
ORDINARY_ROLE = "ordinary"
ROLES: tuple[str, str] = (SELECTED_ROLE, ORDINARY_ROLE)

APPLIED_DIR = Path("/etc/vs-router/applied")
UNIT_DIR = Path("/etc/systemd/system")

#: Fixed absolute paths. Never a value from the RPC or the configuration.
UNBOUND_BINARY = "/usr/sbin/unbound"
UNBOUND_CHECKCONF_BINARY = "/usr/sbin/unbound-checkconf"

READINESS_ATTEMPTS = 50
READINESS_INTERVAL = 0.1

#: The only capability a ``:53`` listener needs when running as a non-root UID.
UNBOUND_CAPABILITIES = "CAP_NET_BIND_SERVICE"

#: Stable fail-closed error codes surfaced to the agent RPC (no output echoed).
CONFIG_INVALID = "agent.unbound_config_invalid"

_ROLE_SPECS: dict[str, dict] = {
    SELECTED_ROLE: {
        "unit": "vs-router-unbound-selected.service",
        "config": APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_selected"],
        "uid": tproxy_dns.TPROXY_SELECTED_UID,
    },
    ORDINARY_ROLE: {
        "unit": "vs-router-unbound-ordinary.service",
        "config": APPLIED_DIR / tproxy_apply.TPROXY_FILES["tproxy_unbound_ordinary"],
        "uid": tproxy_dns.TPROXY_ORDINARY_UID,
    },
}


def _spec(role: str) -> dict:
    try:
        return _ROLE_SPECS[role]
    except KeyError:
        raise ValueError("agent.unbound_role_invalid") from None


def unit_name(role: str) -> str:
    """Deterministic systemd unit name for ``role`` (``selected``/``ordinary``)."""
    return _spec(role)["unit"]


def config_path(role: str) -> Path:
    """Absolute generated-config path the unit's ``ExecStart`` reads for ``role``."""
    return _spec(role)["config"]


def uid_for(role: str) -> int:
    """Reserved numeric UID of the resolver process for ``role``."""
    return _spec(role)["uid"]


def unit_path(role: str) -> Path:
    return UNIT_DIR / unit_name(role)


def checkconf_argv(role: str) -> tuple[str, ...]:
    """Fixed, shell-free ``unbound-checkconf`` argv for ``role``'s config."""
    return (UNBOUND_CHECKCONF_BINARY, str(config_path(role)))


def unit_content(role: str) -> str:
    """Deterministic systemd unit text for one resolver process.

    Minimal privileges: one capability, no new privileges, read-only system,
    private tmp, no home, restricted address families and namespaces. ``ExecStart``
    runs the fixed absolute binary against the fixed generated-config path — never
    a value from the RPC. No secret is placed in the unit.
    """
    spec = _spec(role)
    return (
        "[Unit]\n"
        f"Description=vs-router TProxy DNS resolver ({role})\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={spec['uid']}\n"
        f"ExecStart={UNBOUND_BINARY} -d -c {spec['config']}\n"
        "Restart=on-failure\n"
        "NoNewPrivileges=true\n"
        f"AmbientCapabilities={UNBOUND_CAPABILITIES}\n"
        f"CapabilityBoundingSet={UNBOUND_CAPABILITIES}\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "ProtectKernelTunables=true\n"
        "ProtectControlGroups=true\n"
        # Unbound may open an AF_NETLINK socket while it monitors interfaces;
        # omitting it makes the process fail closed under this sandbox.
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"
        "RestrictNamespaces=true\n"
        "LockPersonality=true\n"
        "MemoryDenyWriteExecute=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


class UnboundService:
    """Executor/filesystem-backed start/stop/readiness for the two resolver units."""

    def __init__(self, executor, filesystem, attempts=READINESS_ATTEMPTS, sleep=None):
        import time
        self.executor = executor
        self.fs = filesystem
        self.attempts = attempts
        self.sleep = sleep or time.sleep

    def install_units(self) -> None:
        # Idempotent: both units are regenerated from the pinned constants.
        for role in ROLES:
            self.fs.write(unit_path(role), unit_content(role))

    def check_config(self, role: str) -> bool:
        """Native ``unbound-checkconf`` on one staged config (fixed argv, no shell)."""
        return self.executor.run(list(checkconf_argv(role)), 15).returncode == 0

    def is_active(self, role: str) -> bool:
        return self.executor.run(
            ["systemctl", "is-active", "--quiet", unit_name(role)], 15).returncode == 0

    def ready(self) -> bool:
        """True only when *both* resolvers are active (readiness before capture)."""
        return all(self.is_active(role) for role in ROLES)

    def start(self) -> None:
        # Check every config before enabling anything: an invalid resolver config
        # must block interception, not leave one unit up and one down.
        for role in ROLES:
            if not self.check_config(role):
                raise ApplyError(CONFIG_INVALID)
        self.install_units()
        for role in ROLES:
            if self.executor.run(
                    ["systemctl", "enable", "--now", unit_name(role)], 15).returncode:
                raise ApplyError("agent.reload_failed")
        for _ in range(self.attempts):
            if self.ready():
                return
            self.sleep(READINESS_INTERVAL)
        raise ApplyError("agent.reload_failed")

    def stop(self) -> None:
        # Best-effort teardown: a missing/inactive unit is not an error.
        for role in ROLES:
            self.executor.run(["systemctl", "disable", "--now", unit_name(role)], 15)

    def __call__(self) -> None:
        self.start()
