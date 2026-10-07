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

    # Restore the TProxy fail-closed guards before anything routes or a listener
    # opens. No-op unless a (gated-off) TProxy artifact is present.
    try:
        failures += restore_tproxy_protection()
    except (OSError, ValueError, KeyError):
        print("TProxy protection restore failed", file=sys.stderr)
        failures += 1

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


if __name__ == "__main__":
    sys.exit(main())
