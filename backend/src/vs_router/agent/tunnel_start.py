"""systemd ExecStartPost: wait for the userspace socket, then configure one link."""
import json
import sys
import time
from pathlib import Path
from .apply import SubprocessExecutor, ApplyError
from .services import checked, WireGuardReloader


def configure(iface, executor=None, config_dir=Path('/etc/vs-router/wireguard'), sleep=time.sleep):
    executor = executor or SubprocessExecutor()
    entry = json.loads((config_dir / 'manifest.json').read_text())[iface]
    for _ in range(50):
        # show via UAPI verifies readiness, not just the existence of the TUN link.
        if executor.run([entry['protocol'], 'show', iface], 15).returncode == 0:
            break
        sleep(0.1)
    else:
        raise ApplyError('agent.reload_failed')
    checked(executor, [entry['protocol'], 'setconf', iface, str(config_dir / entry['file'])])
    for address in entry['addresses']:
        checked(executor, ['ip', 'addr', 'replace', address, 'dev', iface])
    checked(executor, ['ip', 'link', 'set', 'dev', iface, 'up'])
    for route in entry['routes']:
        checked(executor, WireGuardReloader.route('replace', route, iface))


if __name__ == '__main__':
    try:
        configure(sys.argv[1])
    except Exception:
        # Never print daemon output, decrypted keys, or tracebacks on startup.
        sys.exit('agent.tunnel_start_failed')
