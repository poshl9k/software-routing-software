"""Notice a capture contour that stopped serving — and try once to restore it.

The product is fail-closed by design: when the engine dies, a captured segment
loses its traffic instead of leaking it past the tunnel. That is the right
behaviour and the wrong silence. On the lab stand the engine was stopped for a
test and nothing anywhere said so; the segments simply went dark and the panel
answered 200 the whole time.

This checker runs from a timer, compares the applied configuration with what is
actually live (capture tables, the policy route, the engine unit, tunnel
handshakes), attempts one repair pass, and records the outcome. If a webhook is
configured (`VS_ROUTER_ALERT_WEBHOOK`) the finding is posted there as JSON; the
journal entry is written either way, so `journalctl -u vs-router-health` is the
minimum viable alerting on a box with no other channel.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

STATE_PATH = Path('/run/vs-router/health.json')
HANDSHAKE_LIMIT_SECONDS = 600
ENGINE_UNIT = 'vs-router-singbox'


def _output(result) -> str:
    value = getattr(result, 'stdout', '') or ''
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    return value


def _active(executor, unit: str):
    """True/False from the unit state, ``None`` when systemd did not answer.

    ``is-active --quiet`` uses 3 for inactive and 4 for "no such unit"; anything
    else means systemd itself did not answer, which is not evidence about the
    engine.
    """
    result = executor.run(['systemctl', 'is-active', '--quiet', unit], 10)
    code = getattr(result, 'returncode', 1)
    if code == 0:
        return True
    if code in (3, 4):
        return False
    return None


def tables(executor):
    """Existing tables as ``"<family> <name>"``, or ``None`` when unverifiable.

    ``None`` and "no tables" are different answers: a missing `nft` binary or an
    unreadable ruleset is not evidence that the capture contour is gone, and a
    checker that cries wolf gets turned off.
    """
    result = executor.run(['nft', 'list', 'tables'], 15)
    if getattr(result, 'returncode', 1):
        return None
    found = set()
    for line in _output(result).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'table':
            found.add(f'{parts[1]} {parts[2]}')
    return found


def handshake_ages(executor, tunnel_interfaces) -> dict[str, int | None]:
    """Seconds since the last handshake per tunnel; None when the tool is silent."""
    ages: dict[str, int | None] = {}
    for interface, tool in tunnel_interfaces:
        result = executor.run([tool, 'show', interface, 'dump'], 10)
        if getattr(result, 'returncode', 1):
            ages[interface] = None
            continue
        lines = _output(result).splitlines()
        peer = lines[1] if len(lines) > 1 else ''
        # `wg/awg show <iface> dump` peer line:
        # pubkey, preshared, endpoint, allowed-ips, latest-handshake, rx, tx, keepalive
        fields = peer.split(chr(9))
        try:
            stamp = int(fields[4]) if len(fields) > 4 else 0
        except ValueError:
            ages[interface] = None
            continue
        if not stamp:
            ages[interface] = None
            continue
        ages[interface] = max(0, int(datetime.now(timezone.utc).timestamp()) - stamp)
    return ages


def inspect(executor, capture_required: bool, tunnel_interfaces=()) -> list[dict]:
    """Findings that mean the applied configuration is not being served."""
    findings: list[dict] = []
    if capture_required:
        from . import tproxy_apply
        present = tables(executor)
        missing = ([name for name in tproxy_apply.owned_tables()
                    if name not in present]
                   if present is not None else [])
        if missing:
            findings.append({'code': 'health.capture_tables_missing',
                             'detail': ', '.join(sorted(missing))})
        elif present is not None:
            from .policy_route import PolicyRouteLoader
            # `None` means the probe could not answer: that is not a finding.
            if PolicyRouteLoader(executor).present() is False:
                findings.append({'code': 'health.capture_route_missing',
                                 'detail': 'ip rule fwmark 0x100 lookup 100'})
        if _active(executor, ENGINE_UNIT) is False:
            findings.append({'code': 'health.engine_inactive',
                             'detail': ENGINE_UNIT})
    for interface, age in handshake_ages(executor, tunnel_interfaces).items():
        if age is None:
            findings.append({'code': 'health.tunnel_no_handshake',
                             'detail': interface})
        elif age > HANDSHAKE_LIMIT_SECONDS:
            findings.append({'code': 'health.tunnel_handshake_stale',
                             'detail': f'{interface}: {age}s'})
    return findings


def repair(executor) -> list[str]:
    """One targeted restart pass; returns the actions that were taken.

    Only units and the policy route are touched: the readiness steps used at apply
    time also write unit files under /etc, which this checker must not need (it runs
    under ProtectSystem=strict). A repair that fails is simply another finding on the
    next tick.
    """
    done: list[str] = []
    from .policy_route import PolicyRouteLoader

    try:
        if PolicyRouteLoader(executor).present() is False:
            PolicyRouteLoader(executor).apply()
            done.append('policy')
    except Exception:  # noqa: BLE001
        return done
    for unit in ('vs-router-unbound-selected', 'vs-router-unbound-ordinary', ENGINE_UNIT):
        try:
            if _active(executor, unit) is False:
                executor.run(['systemctl', 'restart', unit], 60)
                done.append(unit)
        except Exception:  # noqa: BLE001
            return done
    return done


def _tunnels(configuration) -> list[tuple[str, str]]:
    return [(tunnel.interface, 'awg' if tunnel.protocol == 'awg' else 'wg')
            for tunnel in configuration.tunnels]


def _notify(payload: dict) -> bool:
    url = os.environ.get('VS_ROUTER_ALERT_WEBHOOK', '').strip()
    if not url:
        return False
    import urllib.request
    # No proxy: an alert must not depend on the egress path it is reporting about.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=10):
            return True
    except OSError:
        return False


def main() -> int:
    from . import tproxy_apply
    from .apply import LocalFileSystem, SubprocessExecutor
    from ..schema import ConfigurationVersion

    executor, filesystem = SubprocessExecutor(), LocalFileSystem()
    try:
        snapshot = json.loads(Path('/etc/vs-router/applied/snapshot.json').read_text())
        configuration = ConfigurationVersion.model_validate(snapshot).configuration
    except (OSError, ValueError):
        return 0

    capture = tproxy_apply.capture_required(ConfigurationVersion.model_validate(snapshot))
    findings = inspect(executor, capture, _tunnels(configuration))
    repaired: list[str] = []
    if findings and capture:
        repaired = repair(executor)
        findings = inspect(executor, capture, _tunnels(configuration))
    payload = {
        'host': socket.gethostname(),
        'checked_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'capture_required': capture,
        'findings': findings,
        'repaired': repaired,
    }
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(payload) + '\n')
    except OSError:
        pass
    if findings:
        for finding in findings:
            print(f'{finding["code"]}: {finding["detail"]}', file=sys.stderr)
        _notify(payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
