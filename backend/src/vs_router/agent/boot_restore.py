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

The gated TProxy tract is restored in front of the base product files, in the
same fail-closed order the apply contract uses (``tproxy_apply.PHASE_ORDER``):

    guards -> bounded DNS + engine readiness -> interception + policy route

The protective guards load first (:func:`restore_tproxy_protection`); the two
ADR-0014 resolvers (:func:`restore_tproxy_resolvers`) and the pinned engine
(:func:`restore_tproxy_engine`) are proven ready next; only then is the capture
table loaded and the owned policy route installed
(:func:`restore_tproxy_interception`). Traffic is therefore never captured
before the fail-closed state exists. A substep failure withholds capture (fail
closed) but is **non-fatal to the base services**: the agent/Caddy units still
come up, so a broken TProxy contour never strands the panel off the box.
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


def restore_tunnel_proxy_files() -> int:
    """Unpack files, then bring up kernel tunnels that have no daemon unit.

    systemd owns daemon startup and post-start setconf for userspace tunnels.
    In-kernel devices have no unit, so they must be created here or a reboot
    silently drops every configured tunnel.
    """
    from pathlib import Path
    from .apply import ApplyError, LocalFileSystem
    from .services import WireGuardReloader, CaddyReloader
    fs = LocalFileSystem()
    wireguard = Path(APPLIED) / 'wireguard.conf'
    if wireguard.exists():
        adapter = WireGuardReloader(filesystem=fs)
        files, _, _ = adapter.install(wireguard)
        fs.write(adapter.config_dir / 'manifest.json', files['manifest.json'])
        manifest = json.loads(files['manifest.json'])
        for iface, entry in manifest.items():
            if adapter.backend(entry['protocol']) == 'kernel':
                try:
                    adapter.configure_kernel(iface, entry)
                except (OSError, ValueError, ApplyError):
                    return 1
    caddy = Path(APPLIED) / 'caddy.conf'
    if caddy.exists():
        import grp
        adapter = CaddyReloader(filesystem=fs)
        files = adapter.install(caddy)
        gid = grp.getgrnam('caddy').gr_gid
        for target in [adapter.config_path] + [adapter.cert_dir / n for n in files if n != 'caddy.json']:
            os.chown(target, 0, gid)
            os.chmod(target, 0o640)
    return 0


def _tproxy_artifact_filenames() -> tuple[str, ...]:
    """Every applied-artifact filename owned by the gated TProxy tract."""
    from . import tproxy_apply
    return tuple(tproxy_apply.TPROXY_FILES.values())


def restore_tproxy_protection() -> int:
    """Restore the TProxy protective state *before* any capture tract opens.

    Scaffold, inert for every current configuration: the file below is only
    written by the gated-off TProxy branch (or by :func:`recover_interrupted_apply`
    as destroy-only compensation). When it exists it is loaded first, so the
    fail-closed guard tables are up before the engine/interception artifacts.
    A missing file means there is no TProxy state and this is a no-op.
    """
    from pathlib import Path
    from . import tproxy_apply
    guard = Path(APPLIED) / tproxy_apply.TPROXY_FILES['tproxy_guards']
    if not guard.exists():
        return 0
    return run(["/usr/sbin/nft", "-f", str(guard)])


def _unbound_service():
    from .apply import LocalFileSystem, SubprocessExecutor
    from .unbound_service import UnboundService
    return UnboundService(SubprocessExecutor(), LocalFileSystem())


def _singbox_service():
    from .apply import LocalFileSystem, SubprocessExecutor
    from .singbox_service import SingboxService
    return SingboxService(SubprocessExecutor(), LocalFileSystem())


def _policy_route_loader():
    from .apply import SubprocessExecutor
    from .policy_route import PolicyRouteLoader
    return PolicyRouteLoader(SubprocessExecutor())


def restore_tproxy_resolvers() -> int:
    """Start the two ADR-0014 resolvers *before* the product tract loads.

    Inert for every current configuration: it acts only when an apply staged the
    split resolver configs. Each config is re-checked by native
    ``unbound-checkconf`` inside :meth:`UnboundService.start` (fail-closed), so a
    corrupt staged config keeps the resolvers down instead of opening a listener
    on an unproven state. A missing config means there is no DNS contour and this
    is a no-op.
    """
    from pathlib import Path
    from . import tproxy_apply
    applied = Path(APPLIED)
    if not any((applied / tproxy_apply.TPROXY_FILES[name]).exists()
               for name in tproxy_apply.TPROXY_UNBOUND_FILES):
        return 0
    from .apply import ApplyError
    try:
        _unbound_service().start()
    except (OSError, ValueError, ApplyError, subprocess.SubprocessError):
        print("TProxy resolver restore failed", file=sys.stderr)
        return 1
    return 0


def restore_tproxy_engine() -> int:
    """Start the pinned engine and prove readiness *before* capture.

    Inert unless an apply staged ``singbox.json``. :meth:`SingboxService.start`
    re-verifies the pinned artifact, checks the staged config and blocks until
    ``systemctl is-active`` reports the unit up (fail-closed), so a missing or
    invalid engine keeps capture withheld. Bounded: the adapter uses fixed
    per-command timeouts and a bounded readiness loop; any timeout is reported
    as a failure instead of escaping and aborting the whole boot restore.
    """
    from pathlib import Path
    from . import tproxy_apply
    if not (Path(APPLIED) / tproxy_apply.TPROXY_FILES["singbox"]).exists():
        return 0
    from .apply import ApplyError
    try:
        _singbox_service().start()
    except (OSError, ValueError, ApplyError, subprocess.SubprocessError):
        print("TProxy engine restore failed", file=sys.stderr)
        return 1
    return 0


def restore_tproxy_interception() -> int:
    """Open the capture tract *last*, only after readiness has been proven.

    Installs the owned policy route first (so marked packets are deliverable to
    the loopback listeners) and only then loads ``tproxy-intercept.nft``, the
    same order the apply contract uses (the policy route is a readiness step
    that runs before the capture table). A missing capture artifact is a no-op.
    A policy-route failure withholds the capture entirely; either failure
    returns non-zero without leaving a half-open tract. The caller treats it as
    non-fatal to the base services and keeps the tract fail-closed.
    """
    from pathlib import Path
    from . import tproxy_apply
    capture = Path(APPLIED) / tproxy_apply.TPROXY_FILES["tproxy_interception"]
    if not capture.exists():
        return 0
    from .apply import ApplyError
    try:
        _policy_route_loader().apply()
    except (OSError, ValueError, ApplyError, subprocess.SubprocessError):
        print("TProxy policy route restore failed", file=sys.stderr)
        return 1
    return run(["/usr/sbin/nft", "-f", str(capture)])


def recover_interrupted_apply():
    """Reboot never promotes a pending/partially installed snapshot."""
    from pathlib import Path
    from .apply import ApplyEngine, CONFIRMED_DIR, FILES
    from ..schema import ConfigurationVersion
    from ..generators.nftables import generate_nftables
    engine = ApplyEngine()
    marker = engine.status()
    if not marker or marker['status'] in ('confirmed', 'rolled_back'):
        return
    try:
        backup = json.loads(engine.fs.read(CONFIRMED_DIR / 'snapshot.json'))
    except FileNotFoundError:
        return  # SSH restore rejects this failed/interrupted first apply.
    version = ConfigurationVersion.model_validate(backup['version_snapshot'])
    files = dict(backup['files'])
    files.setdefault('ssh', version.configuration.ssh.model_dump_json())
    # Old snapshots predate the dedicated SSH decision; regenerate their nft.
    from ..management import read_management
    files['nftables'] = generate_nftables(version, read_management())
    for name, filename in FILES.items():
        engine.fs.write(Path(APPLIED) / filename, files[name])
    # Additive TProxy scaffold. Inert for every current configuration: the branch
    # only runs when the confirmed target (or the interrupted marker) carries
    # TProxy artifacts, which the closed gate prevents.
    from . import tproxy_apply
    if tproxy_apply.required(version):
        for name, filename in tproxy_apply.TPROXY_FILES.items():
            content = files.get(name)
            if content is not None:
                engine.fs.write(Path(APPLIED) / filename, content)
    elif any(name in (marker.get('phases') or {}) for name in tproxy_apply.TPROXY_FILES):
        # Interrupted apply had written TProxy artifacts but the confirmed target
        # is not a TProxy state: overwrite the guard file with destroy-only text
        # so boot tears the half-open tract down instead of restoring it, and
        # drop the split resolver configs (destroy text cannot unlink a file).
        engine.fs.write(Path(APPLIED) / tproxy_apply.TPROXY_FILES['tproxy_guards'],
                        tproxy_apply.cleanup_content())
        for filename in tproxy_apply.cleanup_files():
            try:
                engine.fs.remove(Path(APPLIED) / filename)
            except OSError:
                pass
        # A resolver/engine process from the interrupted apply must not survive a
        # reboot whose confirmed target is not a TProxy state. Routed through the
        # engine's executor so no adapter bypasses the injected, typed surface.
        engine._teardown_tproxy_steps()
    engine.fs.write(Path(APPLIED) / 'snapshot.json', json.dumps(backup['version_snapshot']))
    engine.marker({'version_id': backup['version_id'], 'status': 'rolled_back',
                   'deadline': None, 'reason': 'reboot', 'phases': {'rollback': 'rolled_back'}})


def restore_ssh() -> None:
    """Reopen SSH only after the confirmed firewall and guard are restored.

    The service waits for this oneshot. SSHController queues its start rather
    than waiting for a unit whose After= dependency is this very process.
    """
    from .apply import ApplyEngine
    from .ssh import SSHController
    SSHController().restore(ApplyEngine())


def main() -> int:
    failures = 0
    # Refuse restoration before any listener or applied firewall is installed if
    # the recorded physical LAN identity no longer exists.
    from .management_console import check
    from ..management import read_management, STATE_DIR
    try:
        check()
        management = read_management()
    except (OSError, ValueError):
        print("management identity check failed; local console required", file=sys.stderr)
        return 1
    if management is not None and not os.path.exists(os.path.join(APPLIED, 'snapshot.json')):
        if run(['/usr/sbin/nft', '-f', str(STATE_DIR / 'management.nft')]):
            return 1

    try:
        recover_interrupted_apply()
    except (OSError, ValueError, KeyError):
        print("interrupted apply recovery failed", file=sys.stderr)
        return 1

    # TProxy tract, in fail-closed order: protective guards first, then the
    # bounded DNS + engine readiness, and only then the capture table and its
    # policy route. No-op for every configuration with no TProxy artifacts.
    #
    # A substep failure withholds capture (fail closed) but is deliberately
    # *not* counted in ``failures``: ``vs-router-agent.service`` (and Caddy)
    # Requires this oneshot, so failing the unit here would strand the panel off
    # the box (lab-37). Base services always continue; only the capture tract
    # stays shut.
    from .apply import ApplyError as _ApplyError
    _substep_errors = (OSError, ValueError, KeyError,
                       subprocess.SubprocessError, _ApplyError)
    tproxy_failures = 0
    guard_ok = False
    try:
        guard_ok = restore_tproxy_protection() == 0
        capture_file = os.path.join(APPLIED, 'tproxy-intercept.nft')
        guard_file = os.path.join(APPLIED, 'tproxy-guards.nft')
        if os.path.exists(capture_file) and not os.path.exists(guard_file):
            guard_ok = False
            print('TProxy guard artifact missing; capture withheld', file=sys.stderr)
    except _substep_errors as exc:
        print(f"TProxy protection restore failed: {exc}", file=sys.stderr)

    dns_ok = False
    try:
        dns_ok = restore_tproxy_resolvers() == 0
    except _substep_errors as exc:
        print(f"TProxy resolver restore failed: {exc}", file=sys.stderr)

    engine_ok = False
    try:
        engine_ok = restore_tproxy_engine() == 0
    except _substep_errors as exc:
        print(f"TProxy engine restore failed: {exc}", file=sys.stderr)

    if guard_ok and dns_ok and engine_ok:
        # Readiness proven: open the capture tract (policy route, then capture).
        try:
            if restore_tproxy_interception():
                print("TProxy capture restore failed", file=sys.stderr)
                tproxy_failures += 1
        except _substep_errors as exc:
            print(f"TProxy capture restore failed: {exc}", file=sys.stderr)
            tproxy_failures += 1
    elif any(os.path.exists(os.path.join(APPLIED, name))
             for name in _tproxy_artifact_filenames()):
        # A TProxy contour exists but readiness is not proven: never open the
        # capture tract. Guards (if loaded) keep it fail-closed.
        print("TProxy readiness incomplete; capture withheld (fail-closed)",
              file=sys.stderr)
        tproxy_failures += 1

    try:
        failures += restore_tunnel_proxy_files()
    except (OSError, ValueError, KeyError):
        print("tunnel/proxy restore failed", file=sys.stderr)
        failures += 1

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

    # Only a fully restored policy may reopen SSH. The ssh.service unit also
    # Requires this oneshot, so a failed restore keeps its listener down.
    if not failures:
        from .apply import ApplyError
        try:
            restore_ssh()
        except (OSError, ValueError, subprocess.SubprocessError, ApplyError):
            print("SSH protection restore failed", file=sys.stderr)
            failures += 1
    print("boot-restore:", "OK" if not failures else f"{failures} failures")
    if tproxy_failures:
        # Reported separately: the TProxy tract stayed fail-closed while the base
        # services were restored. The unit still exits 0 so agent/Caddy start.
        print(f"boot-restore: TProxy fail-closed "
              f"({tproxy_failures} substep failure(s))", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
