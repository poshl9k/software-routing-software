"""Block until every listen address in a generated config is assigned locally.

Boot order is not a guarantee: caddy came up before systemd-networkd had put the
panel address on the link, failed to bind `192.168.22.59:443`, and the restart
limit then left the unit permanently failed — the panel stayed unreachable after
a reboot. Waiting for a default route is not enough, because the address caddy
binds is not necessarily on the interface that carries that route.

Usage: wait-for-addresses.py <config.json> [timeout-seconds]
"""
import ipaddress
import json
import subprocess
import sys
import time


def _add(value, found):
    """Add the host part of one ``listen`` value (``"192.0.2.10:443"``)."""
    values = value if isinstance(value, list) else [value]
    for item in values:
        if not isinstance(item, str):
            continue
        host = item.rsplit(":", 1)[0].strip("[]") if ":" in item else item
        try:
            found.add(str(ipaddress.ip_address(host)))
        except ValueError:
            # A hostname or a bare ":443": nothing to wait for on this host.
            continue


def _hosts(node, found):
    """Collect the host part of every ``listen`` value in a caddy-style config."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "listen":
                _add(value, found)
            else:
                _hosts(value, found)
    elif isinstance(node, list):
        for item in node:
            _hosts(item, found)


def local_addresses():
    result = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True, text=True, check=False)
    addresses = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[2] in ("inet", "inet6"):
            addresses.add(parts[3].split("/")[0])
    return addresses


def wait_for(path, timeout, sleep=time.sleep, addresses=local_addresses, stream=None):
    wanted = set()
    with open(path, encoding="utf-8") as handle:
        _hosts(json.load(handle), wanted)
    if not wanted:
        return True
    deadline = time.monotonic() + timeout
    while True:
        missing = wanted - addresses()
        if not missing:
            return True
        if time.monotonic() >= deadline:
            print("listen addresses not assigned: " + ", ".join(sorted(missing)),
                  file=stream or sys.stderr)
            return False
        sleep(0.5)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: wait-for-addresses.py <config.json> [timeout-seconds]")
    limit = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
    sys.exit(0 if wait_for(sys.argv[1], limit) else 1)
