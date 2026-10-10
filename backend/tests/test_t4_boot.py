"""Defect 5 (lab-37): boot-restore fail-closed order and non-fatal substeps.

Lab-37 found the product boot path restored only the protective guards and the
split resolvers; it never loaded ``tproxy-intercept.nft`` nor installed the owned
policy route, and a hung ``systemctl enable --now`` raised
``subprocess.TimeoutExpired`` (a ``SubprocessError``, *not* an ``OSError``) that
escaped ``main()`` and aborted the whole boot restore, leaving
``vs-router-agent``/Caddy down.

These tests exercise :mod:`vs_router.agent.boot_restore` with **injected
execution only** (monkeypatched factories and ``run``): no shell, no systemd, no
live VM, no host networking. They pin:

* the fail-closed activation order guards -> bounded DNS + engine readiness ->
  interception + policy route, with the base product files after;
* capture is withheld whenever any readiness substep fails (fail closed);
* a substep failure is non-fatal: ``main()`` still returns 0 so agent/Caddy come
  up, and the base product firewall/SSH restore still run;
* a resolver/engine timeout is reported, never raised;
* every TProxy function is inert (a no-op) with no TProxy artifacts.
"""
import subprocess

import pytest

from vs_router.agent import boot_restore, tproxy_apply

GUARD = tproxy_apply.TPROXY_FILES["tproxy_guards"]
SELECTED = tproxy_apply.TPROXY_FILES["tproxy_unbound_selected"]
ORDINARY = tproxy_apply.TPROXY_FILES["tproxy_unbound_ordinary"]
SINGBOX = tproxy_apply.TPROXY_FILES["singbox"]
CAPTURE = tproxy_apply.TPROXY_FILES["tproxy_interception"]


class FakeService:
    """Stand-in for the typed Unbound/Sing-box adapters: records + may fail."""

    def __init__(self, tag, order, error=None):
        self.tag = tag
        self.order = order
        self.error = error

    def start(self):
        self.order.append(self.tag)
        if self.error is not None:
            raise self.error


class FakePolicyRoute:
    """Stand-in for :class:`PolicyRouteLoader`: records + may fail."""

    def __init__(self, order, error=None):
        self.order = order
        self.error = error

    def apply(self):
        self.order.append("policy_route")
        if self.error is not None:
            raise self.error


def _write(applied, names, content="x\n"):
    for name in names:
        (applied / name).write_text(content)


def _run_main(monkeypatch, applied, order, *, guard_rc=0, dns_error=None,
              engine_error=None, policy_error=None):
    """Drive ``boot_restore.main()`` with everything injected."""
    monkeypatch.setattr(boot_restore, "APPLIED", str(applied))
    monkeypatch.setattr("vs_router.agent.management_console.check", lambda: None)
    monkeypatch.setattr("vs_router.management.read_management", lambda: None)
    monkeypatch.setattr(boot_restore, "recover_interrupted_apply", lambda: None)
    monkeypatch.setattr(boot_restore, "restore_tunnel_proxy_files", lambda: 0)
    monkeypatch.setattr(boot_restore, "restore_ssh", lambda: order.append("ssh"))
    monkeypatch.setattr(boot_restore, "_unbound_service",
                        lambda: FakeService("dns", order, dns_error))
    monkeypatch.setattr(boot_restore, "_singbox_service",
                        lambda: FakeService("engine", order, engine_error))
    monkeypatch.setattr(boot_restore, "_policy_route_loader",
                        lambda: FakePolicyRoute(order, policy_error))

    guard_path = str(applied / GUARD)
    capture_path = str(applied / CAPTURE)

    def fake_run(argv):
        order.append(tuple(argv))
        if argv[1:3] == ["-f", guard_path]:
            return guard_rc
        return 0

    monkeypatch.setattr(boot_restore, "run", fake_run)
    main_rc = boot_restore.main()
    # The post-boot unit runs in a separate transaction after the base unit.
    class Tables:
        stdout = ('\n'.join('table ' + name for name in tproxy_apply.owned_tables())
                  if not guard_rc else '')
    monkeypatch.setattr(boot_restore.subprocess, 'run', lambda *a, **kw: Tables())
    boot_restore.post_boot_tproxy()
    return main_rc


def _index(order, item):
    return order.index(item)


def test_post_boot_requires_live_kernel_guards(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE])
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path))
    class Tables:
        stdout = 'table inet vs_router_tproxy_guard\n'
    monkeypatch.setattr(boot_restore.subprocess, 'run', lambda *a, **kw: Tables())
    monkeypatch.setattr(boot_restore, '_unbound_service',
                        lambda: pytest.fail('must not start DNS before guards'))
    assert boot_restore.post_boot_tproxy() == 1


def test_base_oneshot_never_starts_tproxy_units(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE])
    order = []
    monkeypatch.setattr(boot_restore, 'APPLIED', str(tmp_path))
    monkeypatch.setattr('vs_router.agent.management_console.check', lambda: None)
    monkeypatch.setattr('vs_router.management.read_management', lambda: None)
    monkeypatch.setattr(boot_restore, 'recover_interrupted_apply', lambda: None)
    monkeypatch.setattr(boot_restore, 'restore_tunnel_proxy_files', lambda: 0)
    monkeypatch.setattr(boot_restore, 'restore_ssh', lambda: order.append('ssh'))
    monkeypatch.setattr(boot_restore, '_unbound_service',
                        lambda: pytest.fail('unit start inside boot oneshot'))
    monkeypatch.setattr(boot_restore, '_singbox_service',
                        lambda: pytest.fail('unit start inside boot oneshot'))
    monkeypatch.setattr(boot_restore, 'run', lambda argv: order.append(tuple(argv)) or 0)
    assert boot_restore.main() == 0
    assert order[0][1] == '-f'
    assert ('/usr/sbin/sysctl', '-w', 'net.ipv4.ip_forward=1') in order
    assert order[-1] == 'ssh'


# --------------------------------------------------------------------------
# Fail-closed activation order
# --------------------------------------------------------------------------

def test_capture_and_policy_route_only_after_guard_and_readiness(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE,
                      "nftables.conf"])
    order = []
    assert _run_main(monkeypatch, tmp_path, order) == 0

    guard_nft = ("/usr/sbin/nft", "-f", str(tmp_path / GUARD))
    capture_nft = ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE))
    base_nft = ("/usr/sbin/nft", "-f", str(tmp_path / "nftables.conf"))

    # Base firewall and SSH finish before post-boot unit touches systemd.
    assert _index(order, guard_nft) < _index(order, base_nft) \
        < _index(order, "ssh") < _index(order, "dns") \
        < _index(order, "engine") < _index(order, "policy_route") \
        < _index(order, capture_nft)


def test_readiness_proven_installs_policy_route_before_capture(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE])
    order = []
    _run_main(monkeypatch, tmp_path, order)
    capture_nft = ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE))
    assert _index(order, "policy_route") < _index(order, capture_nft)


# --------------------------------------------------------------------------
# Fail closed: any readiness substep failure withholds capture
# --------------------------------------------------------------------------

def test_missing_guard_artifact_withholds_capture(monkeypatch, tmp_path):
    _write(tmp_path, [SELECTED, ORDINARY, SINGBOX, CAPTURE, "nftables.conf"])
    order = []
    assert _run_main(monkeypatch, tmp_path, order) == 0
    assert "policy_route" not in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE)) not in order
    assert "ssh" in order


def test_dns_readiness_failure_withholds_capture(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE,
                      "nftables.conf"])
    order = []
    assert _run_main(monkeypatch, tmp_path, order, dns_error=OSError("boom")) == 0
    assert "policy_route" not in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE)) not in order
    # Base services still restored.
    assert ("/usr/sbin/nft", "-f", str(tmp_path / "nftables.conf")) in order
    assert "ssh" in order


def test_engine_failure_withholds_capture_but_base_continues(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE,
                      "nftables.conf"])
    order = []
    # Engine start fails; capture must never open.
    assert _run_main(monkeypatch, tmp_path, order,
                     engine_error=subprocess.TimeoutExpired("systemctl", 15)) == 0
    assert "engine" in order
    assert "policy_route" not in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE)) not in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / "nftables.conf")) in order
    assert "ssh" in order


def test_guard_load_failure_withholds_capture(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE,
                      "nftables.conf"])
    order = []
    assert _run_main(monkeypatch, tmp_path, order, guard_rc=1) == 0
    assert "policy_route" not in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE)) not in order
    # Base product firewall still loads and SSH reopens: the panel is not
    # stranded off the box even when the TProxy guard failed.
    assert ("/usr/sbin/nft", "-f", str(tmp_path / "nftables.conf")) in order
    assert "ssh" in order


def test_policy_route_failure_withholds_capture(monkeypatch, tmp_path):
    _write(tmp_path, [GUARD, SELECTED, ORDINARY, SINGBOX, CAPTURE])
    order = []
    _run_main(monkeypatch, tmp_path, order,
              policy_error=OSError("ip rule failed"))
    assert "policy_route" in order
    assert ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE)) not in order


# --------------------------------------------------------------------------
# Inertness: no TProxy artifacts -> nothing TProxy runs
# --------------------------------------------------------------------------

def test_main_is_inert_without_tproxy_artifacts(monkeypatch, tmp_path):
    _write(tmp_path, ["nftables.conf"])
    order = []
    assert _run_main(monkeypatch, tmp_path, order) == 0
    assert "dns" not in order and "engine" not in order
    assert "policy_route" not in order
    assert not any(call[:1] == ("ip",) for call in order if isinstance(call, tuple))
    assert ("/usr/sbin/nft", "-f", str(tmp_path / "nftables.conf")) in order


# --------------------------------------------------------------------------
# Unit-level contracts of the new restore helpers
# --------------------------------------------------------------------------

def test_restore_tproxy_resolvers_reports_timeout_without_raising(monkeypatch, tmp_path):
    _write(tmp_path, [SELECTED, ORDINARY])
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))

    class Boom:
        def start(self):
            raise subprocess.TimeoutExpired("systemctl", 15)

    monkeypatch.setattr(boot_restore, "_unbound_service", lambda: Boom())
    assert boot_restore.restore_tproxy_resolvers() == 1


def test_restore_tproxy_resolvers_noop_without_split_configs(monkeypatch, tmp_path):
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    monkeypatch.setattr(boot_restore, "_unbound_service",
                        lambda: pytest.fail("must not start resolvers"))
    assert boot_restore.restore_tproxy_resolvers() == 0


def test_restore_tproxy_engine_noop_without_singbox(monkeypatch, tmp_path):
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    monkeypatch.setattr(boot_restore, "_singbox_service",
                        lambda: pytest.fail("must not start engine"))
    assert boot_restore.restore_tproxy_engine() == 0


def test_restore_tproxy_engine_starts_when_staged(monkeypatch, tmp_path):
    _write(tmp_path, [SINGBOX])
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    order = []
    monkeypatch.setattr(boot_restore, "_singbox_service",
                        lambda: FakeService("engine", order))
    assert boot_restore.restore_tproxy_engine() == 0
    assert order == ["engine"]


def test_restore_tproxy_interception_noop_without_capture(monkeypatch, tmp_path):
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    monkeypatch.setattr(boot_restore, "_policy_route_loader",
                        lambda: pytest.fail("must not install policy route"))
    monkeypatch.setattr(boot_restore, "run",
                        lambda argv: pytest.fail("must not load capture"))
    assert boot_restore.restore_tproxy_interception() == 0


def test_restore_tproxy_interception_installs_route_then_capture(monkeypatch, tmp_path):
    _write(tmp_path, [CAPTURE])
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    order = []
    monkeypatch.setattr(boot_restore, "_policy_route_loader",
                        lambda: FakePolicyRoute(order))
    monkeypatch.setattr(boot_restore, "run",
                        lambda argv: order.append(tuple(argv)) or 0)
    assert boot_restore.restore_tproxy_interception() == 0
    assert order == ["policy_route", ("/usr/sbin/nft", "-f", str(tmp_path / CAPTURE))]


def test_restore_tproxy_interception_policy_failure_returns_one(monkeypatch, tmp_path):
    _write(tmp_path, [CAPTURE])
    monkeypatch.setattr(boot_restore, "APPLIED", str(tmp_path))
    order = []
    monkeypatch.setattr(boot_restore, "_policy_route_loader",
                        lambda: FakePolicyRoute(order, OSError("ip")))
    monkeypatch.setattr(boot_restore, "run",
                        lambda argv: pytest.fail("capture must be withheld"))
    assert boot_restore.restore_tproxy_interception() == 1
