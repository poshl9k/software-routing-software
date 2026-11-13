"""Boot ordering: a listener must not start before its address exists.

Live defect: after a reboot caddy started before systemd-networkd had assigned
the panel address, failed to bind, and the restart limit left it permanently
failed — the panel was unreachable until an operator restarted the unit.
"""
import json

import importlib.util
from pathlib import Path

HELPER = Path(__file__).resolve().parent.parent / "packaging" / "wait-for-addresses.py"
_spec = importlib.util.spec_from_file_location("wait_for_addresses", HELPER)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
wait_for = _module.wait_for


def config(tmp_path, listen):
    path = tmp_path / "caddy.json"
    path.write_text(json.dumps({"apps": {"http": {"servers": {"s": {"listen": [listen]}}}}}))
    return path


def test_waits_until_the_listen_address_is_assigned(tmp_path, capsys):
    path = config(tmp_path, "192.0.2.10:443")
    seen = []
    calls = {"n": 0}

    def addresses():
        calls["n"] += 1
        seen.append(calls["n"])
        return {"192.0.2.10"} if calls["n"] > 2 else set()

    assert wait_for(str(path), 5, sleep=lambda _: None, addresses=addresses) is True
    assert calls["n"] == 3
    assert "not assigned" not in capsys.readouterr().err


def test_fails_closed_when_the_address_never_appears(tmp_path, capsys):
    path = config(tmp_path, "192.0.2.10:443")
    assert wait_for(str(path), 0, sleep=lambda _: None, addresses=lambda: set()) is False
    assert "192.0.2.10" in capsys.readouterr().err


def test_hostnames_and_ports_need_no_wait(tmp_path):
    path = config(tmp_path, ":443")
    assert wait_for(str(path), 0, sleep=lambda _: None, addresses=lambda: set()) is True
