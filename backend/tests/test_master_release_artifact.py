"""Host-free inventory regression for the built master release artifacts."""
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent

# Keep this deliberately limited to runtime entrypoints most likely to vanish
# unnoticed from the distributable wheel.
MASTER_WHEEL_SOURCES = {
    "vs_master/telegram_bot.py",
    "vs_master/notifications.py",
    "vs_master/worker_main.py",
    "vs_master/backup.py",
}
MASTER_MIGRATIONS = {
    "0001_master_initial.py",
    "0002_magic_login.py",
    "0003_payment_receipt.py",
    "0004_subscription_notifications.py",
}
MASTER_UNITS = {
    "vs-master-bot.service",
    "vs-master-worker.service",
    "vs-master-backup.service",
    "vs-master-backup.timer",
}


def test_master_release_artifact_inventory(tmp_path):
    """Verify the actual wheel and the host-free master release inputs."""
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required for the built-wheel artifact regression")

    out_dir = tmp_path / "wheel"
    out_dir.mkdir()
    result = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(out_dir), str(BACKEND)],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, (
        f"uv wheel build failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
    )
    wheels = list(out_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected one built wheel, found {wheels}"
    with zipfile.ZipFile(wheels[0]) as artifact:
        wheel_names = set(artifact.namelist())
    missing_sources = MASTER_WHEEL_SOURCES - wheel_names
    assert not missing_sources, f"built wheel omits master runtime sources: {sorted(missing_sources)}"

    migration_dir = BACKEND / "alembic-master" / "versions"
    actual_migrations = {path.name for path in migration_dir.glob("*.py")}
    assert MASTER_MIGRATIONS <= actual_migrations, (
        f"master migration inventory is incomplete: {sorted(MASTER_MIGRATIONS - actual_migrations)}"
    )
    packaged_migrations = {
        name for name in ("alembic.ini", "env.py", "script.py.mako")
        if (BACKEND / "alembic-master" / name).is_file()
    }
    assert {"alembic.ini", "env.py"} <= packaged_migrations
    release_script = (BACKEND / "packaging" / "make-master-release.sh").read_text(encoding="utf-8")
    assert "alembic-master" in release_script

    unit_dir = BACKEND / "packaging"
    actual_units = {path.name for path in unit_dir.glob("vs-master-*") if path.is_file()}
    assert MASTER_UNITS <= actual_units, (
        f"master unit inventory is incomplete: {sorted(MASTER_UNITS - actual_units)}"
    )
    assert all(name in release_script for name in MASTER_UNITS)

    # dist is ignored/generated; the release script builds UI into its bundle.
    assert 'VS_MASTER_STATIC_DIR="$BUNDLE/ui" npm run build' in release_script
    # A deployed directory must be able to say which commit it came from: the
    # bundle carries REVISION and the installer prints it (regression: a deploy
    # script that did `cat REVISION` under `set -e` aborted on a bundle without it).
    assert '> "$BUNDLE/REVISION"' in release_script
    installer_text = (BACKEND / "packaging" / "install-master.sh").read_text(encoding="utf-8")
    assert '"$SCRIPT_DIR/REVISION"' in installer_text
    installer = (BACKEND / "packaging" / "install-master.sh").read_text(encoding="utf-8")
    assert 'cp -a "$SCRIPT_DIR/ui"' in installer


def test_master_installer_keeps_panel_python_and_caddy_untouched():
    packaging = BACKEND / 'packaging'
    installer = (packaging / 'install-master.sh').read_text(encoding='utf-8')
    assert 'python3 -m venv "$VENV"' in installer
    assert '"$VENV/bin/python" -m pip' in installer
    assert '"$VENV/bin/python" -m alembic' in installer
    assert 'VENV=/opt/vs-master/venv' in installer
    # On a fresh master-only VPS the panel's parent directory does not exist;
    # on an existing panel it must retain its original owner/mode.
    parent_guard = 'if [ ! -d "$(dirname "$BASE")" ]; then'
    parent_create = 'install -d -m 0755 -o root -g root "$(dirname "$BASE")"'
    assert parent_guard in installer and parent_create in installer
    assert installer.index(parent_guard) < installer.index(parent_create)
    assert installer.index(parent_create) < installer.index('setfacl -m')
    assert 'setfacl -m "u:$APP_USER:--x" "$(dirname "$BASE")"' in installer
    assert 'chmod o+x' not in installer
    assert 'if [ ! -d "$ETC" ]' in installer
    assert 'master.env' in installer and 'secrets.env' not in installer
    assert 'existing master DB requires its original key' in installer
    assert installer.index('source.backup(target)') < installer.index(' -m alembic ')
    assert '/etc/caddy/Caddyfile' not in installer
    assert 'systemctl reload caddy' not in installer
    assert 'systemctl restart caddy' not in installer
    for unit in ('vs-master-web.service', 'vs-master-worker.service',
                 'vs-master-bot.service', 'vs-master-backup.service'):
        text = (packaging / unit).read_text(encoding='utf-8')
        assert 'ExecStart=/opt/vs-master/venv/bin/python' in text


def test_caddy_master_example_carries_no_fleet_hostnames():
    """The shipped example must not name a real (or excluded) fleet host."""
    example = (BACKEND / 'packaging/caddy-master.conf').read_text(encoding='utf-8')
    body = example.split('\n}\n', 1)[1]
    for host in ('62.60.247.104', '.104', 'poshl9k.ru', '85.209.159.130',
                 '92.51.36.131', '163.245.41.183', '48.103.254.105',
                 '77.221.157.30', '185.104.151.133'):
        assert host not in body, f'real host {host} must not appear in the caddy example'
    # A documented placeholder keeps the syntax valid but unbindable.
    assert '203.0.113.10.nip.io' in body and 'master.example.net' in body
    assert 'reverse_proxy 127.0.0.1:8440' in body
