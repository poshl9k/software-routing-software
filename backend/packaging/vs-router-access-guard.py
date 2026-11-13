#!/usr/bin/env python3
"""Keep the management path reachable whatever the panel just applied.

The panel rewrites nftables and networkd as a whole. A configuration that is
wrong about its own management interface — or an apply that fails half way and
restores an older ruleset — can leave the host without the address, without SSH
and without ICMP: reachable over nothing, diagnosable only from the console. The
lab stand lost its management address three times, each time needing hands on the
ESXi console.

This guard is deliberately independent of the panel: it reads the host-owned
management record written by the installer, and re-asserts the two facts that make
the host reachable — the pinned address on the pinned interface, and an accept for
SSH and ICMP on that interface. It runs at boot and every 30 seconds, is
idempotent, and does nothing at all on a host without a management record.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

STATE_PATH = Path('/var/lib/vs-router-bootstrap/management.json')
TABLE = ('inet', 'vs_router')
COMMENT = 'vs-router_access_guard'
PORTS = ('tcp dport 22', 'icmp type echo-request')


def ip(args, timeout=15):
    binary = shutil.which('ip') or '/usr/sbin/ip'
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)


def nft(args, timeout=15):
    binary = shutil.which('nft') or '/usr/sbin/nft'
    return subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)


def read_state(path=STATE_PATH):
    """The host-owned management record, or None when this host has none."""
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (FileNotFoundError, ValueError):
        return None


def interface_for(state):
    """The pinned interface name, or the link that carries the pinned MAC.

    A rename (predictable names differ between installs) must not silently turn
    the guard off; the MAC is the identity the record pins.
    """
    name = state.get('interface')
    mac = (state.get('mac') or '').lower()
    links = ip(['-o', 'link', 'show']).stdout
    for line in links.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[1].rstrip(':') == name:
            return name
    for line in links.splitlines():
        if mac and f'link/ether {mac}' in line.lower():
            return line.split()[1].rstrip(':')
    return name


def address_missing(output, address):
    """True when ``ip -4 addr show`` output does not carry ``address``.

    Compared as a prefix, not as text: `192.168.22.64/16` and `192.168.22.64/24`
    are the same host on the wire, and a guard that fights the panel over prefix
    length would flap the address on every tick.
    """
    wanted = address.split('/')[0]
    return not re.search('inet ' + re.escape(wanted) + '/[0-9]+', output)


def missing_rules(chain, interface, comment=COMMENT):
    """nft rules that the input chain still needs, as ready-to-insert commands."""
    text = chain or ''
    needed = []
    for match in PORTS:
        guarded = (f'iifname "{interface}"' in text and match in text
                   and comment in text)
        if guarded:
            continue
        rule = [f'iifname "{interface}"']
        if match.startswith('tcp'):
            rule += ['tcp', 'dport', '22']
        else:
            rule += ['icmp', 'type', 'echo-request']
        rule += ['counter', 'accept', 'comment', comment]
        needed.append(' '.join(rule))
    return needed


def apply_state(state, dry_run=False):
    """Re-assert the management path; returns what was changed."""
    actions = []
    interface = interface_for(state)
    address = state.get('address')
    if not interface or not address:
        return actions
    current = ip(['-4', 'addr', 'show', 'dev', interface]).stdout
    if address_missing(current, address):
        actions.append(f'address {address} on {interface}')
        if not dry_run:
            ip(['addr', 'replace', address, 'dev', interface])
            ip(['link', 'set', interface, 'up'])
    listed = nft(['list', 'chain', *TABLE, 'input'])
    if listed.returncode == 0:
        for rule in missing_rules(listed.stdout, interface):
            actions.append(f'rule {rule}')
            if not dry_run:
                # One argument: nft keeps the quoting of `iifname "ens1"` and of
                # the comment intact only when the expression arrives whole.
                nft(['insert', 'rule', *TABLE, 'input', rule])
    return actions


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    dry_run = '--dry-run' in argv
    state = read_state()
    if state is None:
        return 0
    actions = apply_state(state, dry_run=dry_run)
    for action in actions:
        print(('would restore ' if dry_run else 'restored ') + action, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
