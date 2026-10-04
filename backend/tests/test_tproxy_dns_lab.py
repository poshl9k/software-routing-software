"""Offline checks for the ordinary, TProxy-off DNS lab fixture."""
import ast
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest


LAB = Path(__file__).parent / 'lab'


def load_generator():
    spec = importlib.util.spec_from_file_location('generate_tproxy_dns_cases',
                                                  LAB / 'generate_tproxy_dns_cases.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_probe():
    spec = importlib.util.spec_from_file_location('tproxy_dns_baseline_probe',
                                                  LAB / 'tproxy_dns_baseline_probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_baseline():
    fixture = load_generator().generate_cases()
    assert fixture['kind'] == 'ordinary_dns_tproxy_off'
    dns, nft = fixture['unbound'], fixture['firewall']
    assert 'interface: 10.212.1.1' in dns
    assert 'access-control: 10.212.1.0/24 allow' in dns
    assert 'router.test. 300 IN A 192.0.2.77' in dns
    assert 'local-zone: "." refuse' in dns
    assert 'local-zone: "forward.test." transparent' in dns
    assert 'name: "forward.test."' in dns
    assert 'forward-addr: 198.18.0.2' in dns
    assert 'forward-addr: 198.18.0.2:53' not in dns
    assert 'interface: 10.212.2.1' not in dns
    assert 'policy drop;' in nft
    assert 'comment "dns_udp"' in nft and 'comment "dns_tcp"' in nft
    assert 'udp dport 53' in nft and 'tcp dport 53' in nft
    assert 'hook forward' in nft
    assert all(token not in nft.lower() for token in ('tproxy', 'meta mark', 'sing-box'))
    assert fixture['expected']['forward_name'] == 'www.forward.test.'
    assert fixture['expected']['forward_name_tcp'] == 'tcp.forward.test.'
    assert fixture['expected']['unknown_name'] == 'unknown.test.'


def test_generation_and_probe_have_no_import_side_effects():
    generator = ast.parse((LAB / 'generate_tproxy_dns_cases.py').read_text())
    probe = ast.parse((LAB / 'tproxy_dns_baseline_probe.py').read_text())
    for tree in (generator, probe):
        top_calls = [node for node in tree.body if isinstance(node, ast.Expr)
                     and isinstance(node.value, ast.Call)]
        assert not top_calls
    assert any(isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
               for node in probe.body)
    assert not any(isinstance(node, ast.Import) and any(alias.name in ('dnspython', 'dns')
                   for alias in node.names) for node in probe.body)


def test_dns_wire_helpers_offline():
    module = load_probe()
    import socket
    import struct
    ident = 0x4d21
    query = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0)
    query += module.name_wire('www.forward.test.') + struct.pack('!HH', 1, 1)
    response = module.answer(query, '203.0.113.7')
    assert module.parse_response(response, ident, 'www.forward.test.') == (0, ['203.0.113.7'])
    assert socket.inet_aton('203.0.113.7') in response
    guard_query = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0)
    guard_query += module.name_wire('guard.forward.test.') + struct.pack('!HH', 1, 1)
    assert module.parse_response(module.answer(guard_query, '203.0.113.7'),
                                 ident, 'guard.forward.test.') == (0, ['203.0.113.7'])


def test_guard_counter_is_scoped_to_selected_forward_rule(monkeypatch):
    module = load_probe()
    import json
    rules = {'nftables': [
        {'rule': {'comment': 'dns_selected_guard', 'expr': [{'counter': {'packets': 0}}]}},
        {'rule': {'comment': 'dns_baseline_drop', 'expr': [{'counter': {'packets': 4}}]}},
    ]}
    monkeypatch.setattr(module, 'run', lambda *args: json.dumps(rules))
    assert module.guard_count('router') == 0
    assert module.drop_count('router') == 4


def test_vm_probe_accounts_for_resolver_cache_and_upstream_ids():
    source = (LAB / 'tproxy_dns_baseline_probe.py').read_text()
    assert "fixture['expected']['forward_name_tcp'] if transport == 'tcp'" in source
    assert "('unknown','10.212.1.1','unknown.test.',3,None)" in source
    assert "a['id'] == b['id'] and a['transport'] == b['transport']" in source
    assert "e.get('id') == ident" in source
    assert "config.unlink(missing_ok=True)" in source


def test_cleanup_attempts_every_resource_after_stop_and_delete_failures(monkeypatch, tmp_path):
    probe = load_probe()
    calls = []

    def child(name, fail=False):
        def stop():
            calls.append(('stop', name))
            if fail:
                raise RuntimeError('stop failed')
        return Mock(stop=stop)

    def delete(args, check):
        calls.append(('delete', args[-1]))
        assert check is True
        if args[-1] == 'second':
            raise RuntimeError('delete failed')

    monkeypatch.setattr(probe.subprocess, 'run', delete)
    config = tmp_path / 'apparmor.conf'
    config.write_text('config')
    errors = probe.cleanup([child('first'), child('second', True), child('third')],
                           ['first', 'second', 'third'], config)
    assert calls == [('stop', 'third'), ('stop', 'second'), ('stop', 'first'),
                     ('delete', 'third'), ('delete', 'second'), ('delete', 'first')]
    assert len(errors) == 2
    assert not config.exists()


def test_startup_failure_stops_registered_child_and_removes_config(monkeypatch, tmp_path):
    probe = load_probe()
    fixture = load_generator().generate_cases()
    fixture_file = tmp_path / 'fixture.json'
    import json
    fixture_file.write_text(json.dumps(fixture))
    monkeypatch.setattr(probe.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(probe.shutil, 'which', lambda binary: '/usr/bin/' + binary)
    monkeypatch.setattr(probe.sys, 'argv', ['probe', str(fixture_file)])
    real_path = probe.Path
    monkeypatch.setattr(probe, 'Path', lambda value: tmp_path if value == '/etc/unbound' else real_path(value))
    calls = []
    monkeypatch.setattr(probe, 'run', lambda *args, **kwargs: calls.append(args) or '')

    class FailingChild:
        def __init__(self, *args):
            calls.append(('child',))
        def ready(self):
            raise RuntimeError('ready failed')
        def stop(self):
            calls.append(('stop',))

    monkeypatch.setattr(probe, 'Child', FailingChild)
    monkeypatch.setattr(probe.subprocess, 'run',
                        lambda args, check: calls.append(tuple(args)))
    with pytest.raises(RuntimeError, match='ready failed'):
        probe.main()
    assert ('stop',) in calls
    assert sum(args[:3] == ('ip', 'netns', 'del') for args in calls) == 3
    assert not list(tmp_path.glob('vsr-dns-*.conf'))


def test_missing_unbound_preflight_has_no_guest_changes(monkeypatch, tmp_path):
    probe = load_probe()
    monkeypatch.setattr(probe.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(probe.sys, 'argv', ['probe', str(tmp_path / 'fixture.json')])
    monkeypatch.setattr(probe.shutil, 'which',
                        lambda binary: None if binary == 'unbound' else '/usr/bin/' + binary)
    forbidden = Mock(side_effect=AssertionError('guest change before preflight'))
    monkeypatch.setattr(probe, 'run', forbidden)
    monkeypatch.setattr(probe.subprocess, 'run', forbidden)
    monkeypatch.setattr(probe.Path, 'write_text', forbidden)
    with pytest.raises(AssertionError, match='missing installed binary: unbound'):
        probe.main()
    forbidden.assert_not_called()
