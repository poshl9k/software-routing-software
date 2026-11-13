"""systemd ExecStart for one tunnel link: keep it alive under either backend.

The panel probes the kernel for a native ``wireguard``/``amneziawg`` link type,
and that probe loads the module. From then on the userspace daemon refuses to run
("this kernel has first class support"), so a unit that hardcodes ``awg-go`` dies
at boot and the tunnel never comes up — observed live after a reboot, where the
enabled userspace unit entered a restart loop while the kernel backend was idle.

This wrapper keeps one main process alive in both cases and leaves the actual
configuration to ``ExecStartPost`` (``vs_router.agent.tunnel_start``), which is
backend-agnostic.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CONFIG_DIR = Path('/etc/vs-router/wireguard')
DAEMON = {('wg', 'userspace'): '/usr/local/bin/wg-go',
          ('awg', 'userspace'): '/usr/local/bin/awg-go'}
KIND = {'wg': 'wireguard', 'awg': 'amneziawg'}
PROTOCOL_BINARY = {'wg': 'wg', 'awg': 'awg'}


def _run(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def kernel_supports(protocol: str) -> bool:
    """Ask the kernel directly; a probe link is always removed."""
    probe = 'vsrwprobe1'
    _run(['ip', 'link', 'del', probe])
    created = _run(['ip', 'link', 'add', probe, 'type', KIND[protocol]])
    if created.returncode == 0:
        _run(['ip', 'link', 'del', probe])
        return True
    return False


def main(argv=None) -> int:
    argv = sys.argv if argv is None else argv
    if len(argv) < 2:
        return 2
    iface = argv[1]
    entry = {}
    try:
        entry = json.loads((CONFIG_DIR / 'manifest.json').read_text()).get(iface, {})
    except (OSError, ValueError):
        entry = {}
    protocol = 'wg' if entry.get('protocol') == 'wg' else 'awg'
    present = _run(['ip', 'link', 'show', 'dev', iface]).returncode == 0
    if present or kernel_supports(protocol):
        # Either the kernel owns the link, or it already exists (a leftover TUN from
        # an earlier daemon — that one refuses to start anyway with "device or
        # resource busy"). In both cases the unit only has to stay active so that
        # `systemctl` reports the tunnel as up and ExecStartPost can configure it.
        if not present:
            _run(['ip', 'link', 'add', iface, 'type', KIND[protocol]])
        _run(['ip', 'link', 'set', 'dev', iface, 'up'])
        while True:
            time.sleep(3600)
    daemon = DAEMON[(protocol, 'userspace')]
    os.execv(daemon, [daemon, iface])
    return 1


if __name__ == '__main__':
    sys.exit(main())
