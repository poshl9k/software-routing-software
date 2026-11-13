"""A dark segment must be noticed, not just fail closed.

Fail-closed is the right behaviour and the wrong silence: with the engine down a
captured segment loses its traffic while the panel keeps answering 200. The
checker compares the applied snapshot against what is actually live, repairs once,
and leaves a record — the journal entry is the minimum alerting on a box with no
other channel, a webhook is the optional one.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from vs_router.agent import health


from vs_router.agent import tproxy_apply

def _owned_tables():
    # `owned_tables()` already carries the family ("inet vs_router_...").
    return tuple(tproxy_apply.owned_tables())


class Executor:
    def __init__(self, tables=None, active=True,
                 rules='100:\tfrom all fwmark 0x100 lookup 100\n', dump=None):
        self.calls = []
        self._tables = _owned_tables() if tables is None else tables
        self._active = active
        self._rules = rules
        self._dump = dump

    def run(self, argv, timeout=None):
        self.calls.append(list(argv))
        if argv[:3] == ['nft', 'list', 'tables']:
            body = ''.join(f'table {line}\n' for line in self._tables)
            return SimpleNamespace(returncode=0, stdout=body, stderr='')
        if argv[:4] == ['ip', '-4', 'rule', 'show']:
            return SimpleNamespace(returncode=0, stdout=self._rules, stderr='')
        if argv[:3] == ['systemctl', 'is-active', '--quiet']:
            return SimpleNamespace(returncode=0 if self._active else 3, stdout='', stderr='')
        if argv[-1] == 'dump':
            text = self._dump(argv[1]) if self._dump else ''
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')


def _dump(interface, stamp):
    # `wg show <iface> dump`: interface line, then one line per peer
    # (pubkey, preshared, endpoint, allowed-ips, latest-handshake, rx, tx, keepalive).
    tab, nl = chr(9), chr(10)
    header = tab.join(['privkey', 'pubkey', '51820', 'off'])
    peer = tab.join(['peerpubkey', 'psk', '203.0.113.1:51820', '10.0.0.2/32',
                     str(stamp), '0', '0', '0'])
    return header + nl + peer + nl


def test_a_missing_capture_table_is_a_finding():
    findings = health.inspect(Executor(tables=()), capture_required=True)
    assert any(item['code'] == 'health.capture_tables_missing' for item in findings)


def test_a_missing_policy_route_is_a_finding():
    findings = health.inspect(Executor(rules='0:\tfrom all lookup local\n'),
                              capture_required=True)
    assert any(item['code'] == 'health.capture_route_missing' for item in findings)


def test_an_inactive_engine_is_a_finding():
    findings = health.inspect(Executor(active=False), capture_required=True)
    assert any(item['code'] == 'health.engine_inactive' for item in findings)


def test_an_unreadable_probe_is_not_a_finding():
    """Silence from a tool is not evidence that the contour is broken."""

    class Silent(Executor):
        def run(self, argv, timeout=None):
            return SimpleNamespace(returncode=1, stdout='', stderr='')

    assert health.inspect(Silent(), capture_required=True) == []


def test_a_healthy_contour_produces_nothing():
    assert health.inspect(Executor(), capture_required=True) == []


def test_tunnel_handshakes_are_judged_by_age(monkeypatch):
    import time
    now = int(time.time())
    healthy = Executor(dump=lambda _iface: _dump('awg0', now - 30))
    assert health.inspect(healthy, capture_required=False,
                          tunnel_interfaces=[('awg0', 'awg')]) == []

    stale = Executor(dump=lambda _iface: _dump('awg0', now - 4000))
    findings = health.inspect(stale, capture_required=False,
                              tunnel_interfaces=[('awg0', 'awg')])
    assert findings[0]['code'] == 'health.tunnel_handshake_stale'

    never = Executor(dump=lambda _iface: _dump('awg0', 0))
    findings = health.inspect(never, capture_required=False,
                              tunnel_interfaces=[('awg0', 'awg')])
    assert findings[0]['code'] == 'health.tunnel_no_handshake'


def test_the_report_is_what_a_webhook_receives(monkeypatch, tmp_path):
    import urllib.request

    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class Opener:
        def open(self, request, timeout=None):
            captured['body'] = json.loads(request.data)
            captured['url'] = request.full_url
            captured['headers'] = dict(request.header_items())
            return Response()

    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a, **k: Opener())
    monkeypatch.setenv('VS_ROUTER_ALERT_WEBHOOK', 'https://alerts.example/hook')
    payload = {'host': 'router', 'findings': [{'code': 'health.engine_inactive'}]}
    assert health._notify(payload) is True
    assert captured['url'] == 'https://alerts.example/hook'
    assert captured['body'] == payload
    assert captured['headers']['Content-type'] == 'application/json'


def test_no_webhook_configured_is_not_an_error(monkeypatch):
    monkeypatch.delenv('VS_ROUTER_ALERT_WEBHOOK', raising=False)
    assert health._notify({'findings': []}) is False


def test_the_timer_ships_with_the_installer():
    from pathlib import Path
    packaging = Path(__file__).resolve().parents[1] / 'packaging'
    assert (packaging / 'vs-router-health.service').is_file()
    timer = (packaging / 'vs-router-health.timer').read_text()
    assert 'OnUnitActiveSec=60s' in timer
    install = (packaging / 'install.sh').read_text(encoding='utf-8')
    assert 'vs-router-health.timer' in install


def test_repair_restarts_only_what_is_down():
    calls = []

    class Down(Executor):
        def run(self, argv, timeout=None):
            calls.append(list(argv))
            if argv[:3] == ['systemctl', 'is-active', '--quiet']:
                unit = argv[3]
                return SimpleNamespace(
                    returncode=3 if unit in ('vs-router-singbox',) else 0,
                    stdout='', stderr='')
            if argv[:4] == ['ip', '-4', 'rule', 'show']:
                rules = '100:' + chr(9) + 'from all fwmark 0x100 lookup 100' + chr(10)
                return SimpleNamespace(returncode=0, stdout=rules, stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

    done = health.repair(Down())
    assert done == ['vs-router-singbox']
    assert ['systemctl', 'restart', 'vs-router-singbox'] in calls
    assert ['systemctl', 'restart', 'vs-router-unbound-selected'] not in calls
