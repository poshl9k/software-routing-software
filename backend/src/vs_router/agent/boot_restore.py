#!/usr/bin/env python3
"""Restore base state and protective TProxy guards before networkd starts.

This oneshot must never synchronously start units ordered after network-online:
networkd itself waits for this unit. The separately enabled
vs-router-tproxy-postboot.service runs :func:`post_boot_tproxy` after the base
oneshot and network-online have finished. It checks live guards, starts split
DNS and the engine, then installs the policy route and capture tables. A TProxy
failure cannot hold the base agent/Caddy transaction or expose capture before
readiness. Base networkd, nft, Unbound, Kea and SSH files are restored here.
"""
import json
import os
import subprocess
import sys

APPLIED = "/etc/vs-router/applied"
NETWORK_DIR = "/etc/systemd/network"
UNBOUND_INCLUDE = "/etc/unbound/unbound.conf.d/vs-router.conf"
KEA_CONF = "/etc/kea/kea-dhcp4.conf"
PPPOE_PEERS_DIR = "/etc/ppp/peers"


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


def restore_pppoe_files(previous_bundle, confirmed_bundle, *, applied_dir=None,
                        peers_dir=None, ppp_dir=None, manifest=None):
    """Reconcile interrupted PPP credentials at boot without starting pppd.

    Starting a unit ordered After=bootrestore here would deadlock; postboot
    starts only the confirmed peers once the base oneshot has exited.
    """
    from pathlib import Path
    from .apply import LocalFileSystem
    fs = LocalFileSystem()
    from .pppoe_apply import interfaces
    applied_dir = Path(applied_dir or APPLIED)
    peers_dir = Path(peers_dir or PPPOE_PEERS_DIR)
    ppp_dir = Path(ppp_dir or '/etc/ppp')
    manifest = Path(manifest or '/etc/vs-router/pppoe-manifest.json')
    old, _ = interfaces(previous_bundle)
    desired, _ = interfaces(confirmed_bundle)
    for filename in old.keys() - desired.keys():
        target = Path(filename)
        # Never remove a path not owned by the PPP bundle.
        if (target.parent == peers_dir or target in
                (ppp_dir / 'chap-secrets', ppp_dir / 'pap-secrets')):
            target.unlink(missing_ok=True)
    for filename, content in desired.items():
        target = Path(filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        fs.write(target, content)
        target.chmod(0o600)
    fs.write(manifest, json.dumps(desired, sort_keys=True))
    manifest.chmod(0o600)
    artifact = applied_dir / 'pppoe.json'
    if desired:
        fs.write(artifact, confirmed_bundle)
        artifact.chmod(0o600)
    else:
        artifact.unlink(missing_ok=True)


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
    from .pppoe_apply import interfaces as pppoe_interfaces
    pppoe_artifact = Path(APPLIED) / 'pppoe.json'
    pppoe_manifest = Path('/etc/vs-router/pppoe-manifest.json')
    previous_pppoe = (pppoe_manifest.read_text() if pppoe_manifest.exists() else
                      pppoe_artifact.read_text() if pppoe_artifact.exists() else '{}')
    # Validate both bundles before touching private host files.
    pppoe_interfaces(previous_pppoe)
    pppoe_interfaces(files.get('pppoe', '{}'))
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
    if previous_pppoe != '{}' or 'pppoe' in files:
        restore_pppoe_files(previous_pppoe, files.get('pppoe', '{}'))
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

    # Only load guards here. Starting split resolvers from this oneshot waits
    # on network-online.target, which itself waits on networkd (ordered AFTER
    # this unit): a systemd transaction cycle. A separate post-boot unit owns
    # readiness and capture; its failure cannot block agent/Caddy.
    try:
        if restore_tproxy_protection():
            print('TProxy guards unavailable; capture withheld', file=sys.stderr)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'TProxy guards unavailable: {exc}', file=sys.stderr)
    if run(['/usr/sbin/sysctl', '-w', 'net.ipv4.ip_forward=1']):
        print('IPv4 forwarding not restored', file=sys.stderr)

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
    return 1 if failures else 0


def post_boot_tproxy() -> int:
    """Complete gated capture after networkd and base boot restore have exited."""
    from . import tproxy_apply
    from .apply import ApplyError
    from pathlib import Path
    applied = Path(APPLIED)
    capture = applied / tproxy_apply.TPROXY_FILES['tproxy_interception']
    if not capture.exists():
        return 0
    # Never trust a stale artifact or a successful oneshot status: prove all
    # protective tables are live in the current kernel before opening capture.
    if not (applied / tproxy_apply.TPROXY_FILES['tproxy_guards']).exists():
        print('TProxy guard artifact missing; capture withheld', file=sys.stderr)
        return 1


    try:
        tables = subprocess.run(['/usr/sbin/nft', 'list', 'tables'],
                                capture_output=True, text=True, timeout=15, check=True).stdout
        guard_names = tproxy_apply.owned_tables()
        capture_names = ('inet vs_router_tproxy_interception',
                         'inet vs_router_tproxy_ct_reset', 'inet vs_router_tproxy_input')
        if not all(f'table {name}' in tables.splitlines() for name in guard_names
                   if name not in capture_names):
            print('TProxy guards not loaded; capture withheld', file=sys.stderr)
            return 1
        if restore_tproxy_resolvers() or restore_tproxy_engine():
            return 1
        if restore_tproxy_interception():
            return 1
        tables = subprocess.run(['/usr/sbin/nft', 'list', 'tables'],
                                capture_output=True, text=True, timeout=15, check=True).stdout
        if not all(f'table {name}' in tables.splitlines() for name in guard_names):
            return 1
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, ApplyError) as exc:
        print(f'TProxy post-boot restore failed: {exc}', file=sys.stderr)
        return 1

def post_boot_pppoe(executor=None) -> int:
    """Start confirmed PPPoE peers after network-online, outside base bootrestore.

    The packaging unit owns ordering. Never read or print credentials here; only
    interface names from the confirmed snapshot are passed to systemctl.
    """
    from pathlib import Path
    from .apply import CONFIRMED_DIR, SubprocessExecutor

    if executor is None:
        executor = SubprocessExecutor()
    try:
        confirmed = json.loads((CONFIRMED_DIR / 'snapshot.json').read_text())
        snapshot = confirmed['version_snapshot']
        applied = json.loads((Path(APPLIED) / 'snapshot.json').read_text())
        if applied != snapshot:
            print('PPPoE confirmed snapshot mismatch; startup withheld', file=sys.stderr)
            return 1
        interfaces = snapshot['configuration']['interfaces']
    except FileNotFoundError:
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print('PPPoE confirmed snapshot unavailable', file=sys.stderr)
        return 1

    failed = False
    for interface in interfaces:
        if interface.get('addressing') != 'pppoe':
            continue
        name = interface.get('name')
        # Never let snapshot data become an arbitrary unit name or option.
        if not isinstance(name, str) or not name or len(name) > 15 or not all(
                char.isascii() and (char.isalnum() or char in '_.-') for char in name):
            print('PPPoE interface name invalid; startup withheld', file=sys.stderr)
            failed = True
            continue
        if not (Path(PPPOE_PEERS_DIR) / f'vs-router-{name}').is_file():
            print(f'PPPoE peer file missing for {name}', file=sys.stderr)
            failed = True
            continue
        try:
            result = executor.run(['systemctl', 'start', f'vs-router-pppoe@{name}.service'],
                                  timeout=30)
            if result.returncode:
                print(f'PPPoE service start failed for {name}', file=sys.stderr)
                failed = True
        except (OSError, subprocess.SubprocessError):
            print(f'PPPoE service start failed for {name}', file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(post_boot_pppoe() if sys.argv[1:] == ['pppoe-postboot'] else main())
