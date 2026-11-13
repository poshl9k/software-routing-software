"""Routes that make a tunnel usable as a routing exit.

A tunnel exit is a sing-box outbound bound to the tunnel's own address, so the
kernel must send that traffic into the tunnel. The main table cannot carry a
second default — the tunnel would compete with the WAN for every packet on the
host — so each tunnel exit gets its own table, selected by the tunnel address,
exactly like an interface exit is selected by its WAN source address.

Without this the outbound dials ``10.66.66.10 -> 1.1.1.1:443`` and the packet
leaves through the WAN interface with the tunnel address as its source, where
nothing answers: `i/o timeout` in the engine log and a segment that silently
falls back to whatever the main table says.
"""
from __future__ import annotations

import json

from ..generators import marks

STATE_PATH = "/etc/vs-router/applied/tunnel-policy.json"
RULE_PRIORITY_BASE = 33000


def plan(configuration) -> list[dict]:
    """Tables needed by tunnel exits, in a stable order.

    Only a client tunnel with an explicit source address can be selected this
    way; a server tunnel has no single local address to key on.
    """
    tunnels = {tunnel.name: tunnel.interface for tunnel in configuration.tunnels}
    wanted = set()
    exits = [rule.exit for rule in configuration.routing_rules]
    exits += [member for group in configuration.proxies.groups for member in group.exits]
    for exit_value in exits:
        if exit_value.kind != "tunnel" or not exit_value.source or not exit_value.name:
            continue
        interface = tunnels.get(exit_value.name)
        if interface:
            wanted.add((exit_value.source, interface))
    ordered = sorted(wanted)
    if len(ordered) > marks.POLICY_TABLE_LIMIT:
        raise ValueError("networkd.policy_table_exhausted")
    return [{"source": source, "interface": interface,
             "table": marks.TUNNEL_POLICY_TABLE_BASE + index,
             "priority": RULE_PRIORITY_BASE + index}
            for index, (source, interface) in enumerate(ordered)]


def _rules(executor) -> str:
    result = executor.run(["ip", "-4", "rule", "show"], 15)
    output = getattr(result, "stdout", "") or ""
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    return output


def sync(executor, filesystem, entries, path=STATE_PATH) -> list[str]:
    """Install the tables for ``entries`` and retire the ones no longer wanted."""
    try:
        previous = json.loads(filesystem.read(path))
    except (OSError, ValueError):
        previous = []
    current = {(entry["source"], entry["interface"], entry["table"], entry["priority"])
               for entry in entries}
    removed = [item for item in previous
               if (item["source"], item["interface"], item["table"], item["priority"]) not in current]
    changes = []
    for item in removed:
        executor.run(["ip", "-4", "rule", "del", "from", item["source"],
                      "lookup", str(item["table"]), "priority", str(item["priority"])], 15)
        executor.run(["ip", "-4", "route", "flush", "table", str(item["table"])], 15)
        changes.append(f"removed {item['source']} -> table {item['table']}")
    live = _rules(executor)
    for entry in entries:
        executor.run(["ip", "-4", "route", "replace", "default", "dev", entry["interface"],
                      "table", str(entry["table"])], 15)
        selector = f"from {entry['source']} lookup {entry['table']}"
        if selector not in live:
            executor.run(["ip", "-4", "rule", "add", "from", entry["source"],
                          "lookup", str(entry["table"]), "priority", str(entry["priority"])], 15)
            changes.append(f"added {selector} priority {entry['priority']}")
    filesystem.write(path, json.dumps(entries))
    return changes


def teardown(executor, filesystem, path=STATE_PATH) -> list[str]:
    """Remove every table this module installed (a configuration without tunnels)."""
    return sync(executor, filesystem, [], path=path)


def main() -> int:
    """Re-assert the tunnel tables from the applied snapshot.

    Runs as ExecStartPost of a tunnel unit: after a reboot the links come up in
    their own order, and the tables that make them usable as exits must exist
    again even though no apply happens at boot.
    """
    import sys

    from pathlib import Path

    from ..schema import ConfigurationVersion
    from .apply import LocalFileSystem, SubprocessExecutor

    try:
        snapshot = json.loads(Path('/etc/vs-router/applied/snapshot.json').read_text())
        configuration = ConfigurationVersion.model_validate(snapshot).configuration
    except (OSError, ValueError):
        return 0
    entries = plan(configuration)
    if not entries:
        return 0
    sync(SubprocessExecutor(), LocalFileSystem(), entries)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
