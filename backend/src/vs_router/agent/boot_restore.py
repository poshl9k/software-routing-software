#!/usr/bin/env python3
"""Restore-on-boot: apply the last applied vs-router configs after the machine
comes up. Runs BEFORE vs-router-web, so the panel (and the confirmation loop)
always starts on the last applied state; nftables ruleset is not persistent
across reboots by design, networkd/unbound/kea read their own config files.

Order matters:
1. networkd files -> /etc/systemd/network (before networkd starts via Before=)
2. nftables ruleset (network is useless without it)
3. unbound include + config check (no restart needed: systemctl reload after boot)
4. kea config copy (kea-dhcp4 reads it at its own startup)
"""
import json
import os
import subprocess
import sys

APPLIED = "/etc/vs-router/applied"
NETWORK_DIR = "/etc/systemd/network"
UNBOUND_INCLUDE = "/etc/unbound/unbound.conf.d/vs-router.conf"
KEA_CONF = "/etc/kea/kea-dhcp4.conf"


def run(argv: list[str]) -> int:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL {argv}: {exc}", file=sys.stderr)
        return 1
    if result.returncode:
        print(f"FAIL {argv}: {result.stderr.strip()[:200]}", file=sys.stderr)
    return result.returncode


def unpack_networkd_bundle() -> int:
    path = os.path.join(APPLIED, "networkd.conf")
    if not os.path.exists(path):
        return 0
    for name, content in parse_bundle(path).items():
        target = os.path.join(NETWORK_DIR, name)
        with open(target, "w") as handle:
            handle.write(content)
    return 0


def parse_bundle(path: str) -> dict[str, str]:
    files: dict[str, str] = {}
    current: str | None = None
    with open(path) as handle:
        for line in handle:
            marker = line.startswith("### FILE: ")
            if marker:
                current = line[len("### FILE: "):].strip()
                files[current] = ""
            elif current is not None:
                files[current] += line
    return files


def main() -> int:
    failures = 0

    # 1. networkd files
    try:
        failures += unpack_networkd_bundle()
    except OSError as exc:
        print(f"networkd unpack: {exc}", file=sys.stderr)
        failures += 1

    # 2. nftables
    nft = os.path.join(APPLIED, "nftables.conf")
    if os.path.exists(nft):
        failures += run(["/usr/sbin/nft", "-f", nft])

    # 3. unbound include
    unbound = os.path.join(APPLIED, "unbound.conf")
    if os.path.exists(unbound) and os.path.isdir("/etc/unbound"):
        with open(UNBOUND_INCLUDE, "w") as handle:
            handle.write(f'include: "{unbound}"\n')
        failures += run(["/usr/sbin/unbound-checkconf", "/etc/unbound/unbound.conf"])

    # 4. kea
    kea = os.path.join(APPLIED, "kea.json")
    if os.path.exists(kea) and os.path.isdir("/etc/kea"):
        with open(kea) as src, open(KEA_CONF, "w") as dst:
            dst.write(src.read())
        os.chmod(KEA_CONF, 0o644)

    print("boot-restore:", "OK" if not failures else f"{failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
