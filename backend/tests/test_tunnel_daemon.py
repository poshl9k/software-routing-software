"""The tunnel unit must survive either backend.

Live defect: the kernel probe (``ip link add type amneziawg``) loads the vendor
module, after which the userspace daemon refuses to run. A unit that execs the
daemon directly therefore dies at every boot and the tunnel never returns.
"""
import types

from vs_router.agent import tunnel_daemon


def test_kernel_backend_creates_the_link_and_stays_alive(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["ip", "link", "add", "vsrwprobe1"]:
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[:4] == ["ip", "link", "show", "dev"]:
            return types.SimpleNamespace(returncode=1, stdout="", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(tunnel_daemon.subprocess, "run", fake_run)
    monkeypatch.setattr(tunnel_daemon, "CONFIG_DIR", _dir_with_manifest("awg"))
    slept = []
    monkeypatch.setattr(tunnel_daemon.time, "sleep", lambda seconds: slept.append(seconds))
    # One iteration is enough: the loop must not fall through to the daemon.
    def stop(_seconds):
        raise SystemExit(0)
    monkeypatch.setattr(tunnel_daemon.time, "sleep", stop)

    try:
        tunnel_daemon.main(["prog", "awg0"])
    except SystemExit:
        pass
    assert ["ip", "link", "add", "awg0", "type", "amneziawg"] in calls
    assert ["ip", "link", "set", "dev", "awg0", "up"] in calls


def test_userspace_backend_execs_the_daemon(monkeypatch):
    executed = []
    monkeypatch.setattr(tunnel_daemon.subprocess, "run",
                        lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    monkeypatch.setattr(tunnel_daemon, "CONFIG_DIR", _dir_with_manifest("awg"))
    monkeypatch.setattr(tunnel_daemon.os, "execv", lambda path, argv: executed.append((path, argv)))
    with_bound = tunnel_daemon.main(["prog", "awg0"])
    assert executed == [("/usr/local/bin/awg-go", ["/usr/local/bin/awg-go", "awg0"])]
    assert with_bound == 1


def _dir_with_manifest(protocol):
    import json, tempfile
    from pathlib import Path
    path = Path(tempfile.mkdtemp())
    (path / "manifest.json").write_text(json.dumps({"awg0": {"protocol": protocol},
                                                    "wg0": {"protocol": protocol}}))
    return path


def test_wireguard_daemon_path_matches_what_the_release_installs(monkeypatch):
    """The release installs `wg-go`, not `wireguard-go`: the unit must exec the former."""
    executed = []
    monkeypatch.setattr(tunnel_daemon.subprocess, "run",
                        lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    monkeypatch.setattr(tunnel_daemon, "CONFIG_DIR", _dir_with_manifest("wg"))
    monkeypatch.setattr(tunnel_daemon.os, "execv", lambda path, argv: executed.append(path))
    tunnel_daemon.main(["prog", "wg0"])
    assert executed == ["/usr/local/bin/wg-go"]
