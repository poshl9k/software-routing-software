"""Host-free checks for the VM-only two-process DNS split fixture/probe."""
import ast
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch

from vs_router.schema import ConfigurationVersion

LAB = Path(__file__).parent / "lab"


def load(name):
    spec = importlib.util.spec_from_file_location(name, LAB / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, 'path', [str(LAB), *sys.path]):
        spec.loader.exec_module(module)
    return module


def test_dns_split_fixture_is_isolated_from_live_generators():
    fixture = load("generate_tproxy_dns_split_cases").generate_cases()
    load("tproxy_dns_split_probe").check_fixture(fixture)
    selected = fixture["unbound"]["selected"]
    ordinary = fixture["unbound"]["ordinary"]
    assert "interface: 10.212.1.1" in selected
    assert "interface: 10.212.3.1" not in selected
    assert "interface: 10.212.3.1" in ordinary
    assert "interface: 10.212.1.1" not in ordinary
    assert 'do-not-query-localhost: no' in selected
    assert 'forward-addr: 127.0.0.1@15353' in selected
    assert 'forward-addr: 198.18.0.3' in ordinary
    assert 'tproxy_dns_stub_external' in fixture["listener_guard"]
    assert 'tproxy_dns_direct' in fixture["direct_guard"]
    assert 'meta skuid 29092' in fixture["output_guard"]
    assert 'tproxy' not in fixture["firewall"].lower()
    assert ConfigurationVersion.model_validate({"configuration": {}}).configuration.tproxy.enabled is False


def test_dns_split_fixture_comes_from_the_integrated_contour():
    fixture = load("generate_tproxy_dns_split_cases").generate_cases()
    # The fixture is the gated apply scaffold's own output, not a copy.
    assert fixture["source"] == "plan_tproxy_dns+tproxy_apply"
    assert fixture["selected_uid"] == 29092
    assert fixture["apply_files"] == [
        "tproxy_guards", "tproxy_unbound_selected", "tproxy_unbound_ordinary",
        "singbox", "tproxy_interception"]
    # The three VM-probe guards are the exact phase-1 guard components.
    for content in (fixture["listener_guard"], fixture["direct_guard"],
                    fixture["output_guard"]):
        assert content in fixture["apply_guard"]


def test_dns_split_probe_import_does_not_change_host():
    for name in ("generate_tproxy_dns_split_cases", "tproxy_dns_split_probe"):
        tree = ast.parse((LAB / f"{name}.py").read_text())
        assert not any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                       for n in tree.body)
        load(name)
