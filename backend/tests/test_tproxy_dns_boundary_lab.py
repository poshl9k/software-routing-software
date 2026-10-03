"""Host-free fixture and import checks; the namespace probe is VM-only."""
import ast
import importlib.util
import json
from pathlib import Path

import pytest

LAB = Path(__file__).parent / 'lab'


def load(name):
    spec = importlib.util.spec_from_file_location(name, LAB / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_boundary_fixture(tmp_path):
    generator = load('generate_tproxy_dns_boundary_cases')
    fixture = generator.generate_cases()
    load('tproxy_dns_boundary_probe').check_fixture(fixture)
    assert fixture['kind'] == 'tproxy_dns_boundary_vm_v1'
    assert '"lan0", "lan1"' in fixture['firewall']
    assert 'iifname != { "lan0" } return' in fixture['preauth']
    assert 'fib daddr type local return' in fixture['preauth']
    assert 'comment "dns_local"' in fixture['firewall']
    assert 'comment "dns_external"' in fixture['firewall']
    assert 'udp dport 53' in fixture['firewall']
    assert 'comment "tproxy_containment"' in fixture['guard_on']
    assert 'lan1' not in fixture['guard_on']
    path = tmp_path / 'fixture.json'
    generator.main([str(path)])
    assert json.loads(path.read_text()) == fixture


def test_imports_do_not_start_probe(monkeypatch):
    for name in ('generate_tproxy_dns_boundary_cases','tproxy_dns_boundary_probe'):
        tree = ast.parse((LAB / f'{name}.py').read_text())
        assert not [node for node in tree.body if isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Call)]
        assert isinstance(tree.body[-1], ast.If)
        load(name)


def test_imported_fixture_rejected_if_boundary_is_wrong():
    fixture = load('generate_tproxy_dns_boundary_cases').generate_cases()
    probe = load('tproxy_dns_boundary_probe')
    for key, bad in [('kind','wrong'), ('guard_on',fixture['guard_off']),
                     ('preauth',fixture['preauth_off']), ('firewall','table inet x {}')]:
        mutated = dict(fixture, **{key: bad})
        with pytest.raises(AssertionError):
            probe.check_fixture(mutated)


def test_cleanup_attempts_all_namespaces(monkeypatch):
    probe = load('tproxy_dns_boundary_probe')
    calls = []
    class Child:
        def __init__(self, name): self.name = name
        def stop(self):
            calls.append(self.name)
            if self.name == 'b': raise RuntimeError('stop')
    def fake_run(*args):
        calls.append(args[-1])
        if args[-1] == 'n2': raise RuntimeError('delete')
    monkeypatch.setattr(probe, 'run', fake_run)
    errors = probe.cleanup([Child('a'),Child('b')],['n1','n2'])
    assert calls == ['b','a','n2','n1']
    assert len(errors) == 2
