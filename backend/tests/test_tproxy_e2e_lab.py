"""Host-free checks for the VM-only full-stack TProxy e2e fixture/probe."""
import ast
import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch

from vs_router.generators import marks

LAB = Path(__file__).parent / "lab"


def load(name):
    spec = importlib.util.spec_from_file_location(name, LAB / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(LAB), *sys.path]):
        spec.loader.exec_module(module)
    return module


def test_e2e_fixture_is_offline_and_generator_sourced():
    fixture = load("generate_tproxy_e2e_cases").generate_cases()
    assert fixture["kind"] == "tproxy_e2e_vm_v1"
    assert fixture["source"] == "generate_nftables+plan_tproxy_dns+tproxy_apply"
    assert fixture["selected_uid"] == 29092
    # Ordinary firewall never carries a TProxy mark/rule.
    assert "tproxy" not in fixture["ordinary_firewall"].lower()
    assert "meta mark" not in fixture["ordinary_firewall"].lower()
    # Real generated forwarding policy is present.
    assert 'comment "allow_tcp"' in fixture["ordinary_firewall"]
    assert 'comment "allow_udp"' in fixture["ordinary_firewall"]


def test_e2e_fixture_carries_the_whole_stack():
    fixture = load("generate_tproxy_e2e_cases").generate_cases()
    assert "priority -10" in fixture["containment"]
    assert "priority -90" in fixture["preauth"]
    capture = fixture["interception"]
    for priority in ("priority -85", "priority -80", "priority -20"):
        assert priority in capture
    assert "tproxy ip to 127.0.0.1:51272" in capture
    assert "tproxy ip to 127.0.0.1:51271" in capture
    assert "meta mark set 0x100" in capture
    assert "ct mark set ct mark | 0x200" in capture
    assert "ct mark & 0x200 == 0" in capture
    assert "meta mark set meta mark | 0x200" not in capture
    for role in ("ingress", "listener", "output"):
        assert fixture["dns_guards"][role]
    assert "meta skuid 29092" in fixture["dns_guards"]["output"]
    assert "127.0.0.1@15353" in fixture["unbound"]["selected"]
    assert "interface: 10.212.3.1" in fixture["unbound"]["ordinary"]
    import json
    singbox = json.loads(fixture["singbox"])
    assert any(i.get("type") == "tproxy" and i.get("listen_port") == 51272
               for i in singbox["inbounds"])


def test_e2e_fixture_policy_route_matches_registry():
    fixture = load("generate_tproxy_e2e_cases").generate_cases()
    route = marks.POLICY_ROUTES[0]
    assert fixture["policy_route"] == {
        "rule_priority": route.rule_priority,
        "fwmark": route.fwmark,
        "table_id": route.table_id,
    }


def test_e2e_off_text_destroys_only_owned_tables():
    fixture = load("generate_tproxy_e2e_cases").generate_cases()
    for key in ("containment", "preauth", "dns_ingress", "dns_listener", "dns_output"):
        assert fixture["off"][key].startswith("destroy table ")
        assert "table inet vs_router {" not in fixture["off"][key]
    interception_off = fixture["off"]["interception"]
    for table in ("vs_router_tproxy_ct_reset", "vs_router_tproxy_interception",
                  "vs_router_tproxy_input"):
        assert f"destroy table inet {table}" in interception_off


def test_e2e_probe_is_stdlib_only_and_import_safe():
    for name in ("generate_tproxy_e2e_cases", "tproxy_e2e_probe"):
        text = (LAB / f"{name}.py").read_text()
        tree = ast.parse(text)
        assert not any(isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                       for n in tree.body)
        if name == "tproxy_e2e_probe":
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            assert "vs_router" not in imported
            assert imported <= {
                "json", "os", "pathlib", "queue", "re", "shutil", "socket",
                "struct", "subprocess", "sys", "tempfile", "threading", "time",
                "uuid", "__future__",
            }
        load(name)
