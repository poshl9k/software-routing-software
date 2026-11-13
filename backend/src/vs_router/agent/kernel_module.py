"""Keep the kernel ``wireguard`` module out of the way on a border router.

The product runs AWG as a userspace daemon on hosts without a native amneziawg
link type. That daemon refuses to start as soon as the plain ``wireguard`` module
is loaded ("this kernel has first class support for AmneziaWG"), and it is loaded
on demand by anything that touches a WireGuard link — including probes and other
tools on the same host. Observed live: after a reboot the AWG tunnel stayed down
until an operator unloaded the module by hand.

The scope is deliberately narrow: only the ``router`` profile, and only while the
configuration has no ``protocol: wg`` tunnel. Anything else (a node or a VPS panel
that serves subscribers with kernel WireGuard) must keep the module — blacklisting
it there would silently move their tunnels into userspace.
"""
from pathlib import Path

BLACKLIST_PATH = Path('/etc/modprobe.d/vs-router-awg.conf')
BLACKLIST_CONTENT = """\
# Managed by vs-router. The router profile runs AmneziaWG as a userspace daemon,
# and that daemon refuses to start while the plain wireguard kernel module is
# loaded. Remove this file to allow kernel WireGuard links on this host.
blacklist wireguard
install wireguard /bin/false
"""

BLACKLISTED = 'blacklisted'
REMOVED = 'removed'
UNCHANGED = 'unchanged'
SKIPPED_PROFILE = 'skipped_profile'
SKIPPED_WG_TUNNELS = 'skipped_wg_tunnels'


def uses_kernel_wireguard(configuration) -> bool:
    """A ``wg`` tunnel uses the kernel implementation when the host has one."""
    return any(tunnel.protocol == 'wg' for tunnel in configuration.tunnels)


def _exists(fs) -> bool:
    try:
        fs.read(BLACKLIST_PATH)
    except (FileNotFoundError, KeyError, OSError):
        return False
    return True


def sync(profile, configuration, fs, executor) -> str:
    """Make the modprobe file match this host; returns what happened.

    Idempotent: it runs on every apply, so a profile change or a new ``wg`` tunnel
    takes effect without a separate command.
    """
    wanted = profile == 'router' and not uses_kernel_wireguard(configuration)
    if not wanted:
        if _exists(fs):
            fs.remove(BLACKLIST_PATH)
            return REMOVED
        if profile is None:
            return UNCHANGED
        return SKIPPED_WG_TUNNELS if profile == 'router' else SKIPPED_PROFILE
    if _exists(fs):
        return UNCHANGED
    fs.write(BLACKLIST_PATH, BLACKLIST_CONTENT)
    # Best effort: the module may be in use by an existing kernel link, and a
    # failure here must not fail the apply — it is retried on the next one.
    executor.run(['modprobe', '-r', 'wireguard'], 30)
    return BLACKLISTED
