"""systemd ExecStartPost: wait for the userspace device, then configure one link.

Boot races are the normal case here, not an exception: the daemon creates the TUN
link asynchronously, so a single immediate attempt is a coin toss. Observed live:
after a reboot the first attempt lost the race, the restart limit was exhausted,
and the tunnel stayed down with ``agent.tunnel_start_failed`` until an operator
reset the unit.
"""
import json
import sys
import time
from pathlib import Path
from .apply import SubprocessExecutor, ApplyError
from .services import WireGuardReloader

#: ~60 s of patience: enough for a slow boot, and still under the unit's
#: TimeoutStartSec. Both waits share the same budget on purpose.
ATTEMPTS = 300
DELAY = 0.2


def _wait(executor, argv, attempts=ATTEMPTS, delay=DELAY, sleep=time.sleep):
    for _ in range(attempts):
        if executor.run(argv, 15).returncode == 0:
            return True
        sleep(delay)
    return False


def configure(iface, executor=None, config_dir=Path('/etc/vs-router/wireguard'), sleep=time.sleep):
    executor = executor or SubprocessExecutor()
    entry = json.loads((config_dir / 'manifest.json').read_text())[iface]
    # The link itself comes first: until the daemon has created it there is
    # nothing to configure, and `wg show` cannot answer for a missing link either.
    if not _wait(executor, ['ip', 'link', 'show', 'dev', iface], sleep=sleep):
        raise ApplyError('agent.reload_failed')
    # Then the UAPI: an existing TUN link does not prove the daemon is ready.
    if not _wait(executor, [entry['protocol'], 'show', iface], sleep=sleep):
        raise ApplyError('agent.reload_failed')
    WireGuardReloader(executor=executor, config_dir=config_dir).configure(
        iface, entry, entry['protocol'])


if __name__ == '__main__':
    try:
        configure(sys.argv[1])
    except Exception:
        # Never print daemon output, decrypted keys, or tracebacks on startup.
        sys.exit('agent.tunnel_start_failed')
