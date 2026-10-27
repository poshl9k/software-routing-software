"""Execute packaging control flow with isolated files and fake host commands.

These tests never invoke host service/network/package managers.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / 'backend/packaging'


def bash(code, *, env=None):
    return subprocess.run(['bash', '-c', code], text=True, capture_output=True,
                          env=env, timeout=10)


@pytest.mark.parametrize('failure', ['false', '(exit 19)', 'false | cat', 'value=$(false)'])
def test_stage_stops_at_first_failure(failure):
    result = bash(f'''source "{PACKAGING}/bootstrap.sh"
logger() {{ :; }}
stage() {{ {failure}; echo FALSE_SUCCESS; }}
run_stage regression stage
echo CONTINUED
''')
    assert result.returncode != 0
    assert 'FALSE_SUCCESS' not in result.stdout
    assert 'CONTINUED' not in result.stdout
    assert 'Completed stage' not in result.stdout
    assert 'stage regression failed' in result.stdout


def test_build_does_not_hide_npm_failure(tmp_path):
    (tmp_path / 'frontend').mkdir()
    result = bash(f'''source "{PACKAGING}/bootstrap.sh"
logger() {{ :; }}
REPO_ROOT="{tmp_path}"
npm() {{ if [[ $1 == ci ]]; then return 9; fi; echo FALSE_BUILD; }}
run_stage build stage_build
''')
    assert result.returncode == 9
    assert 'FALSE_BUILD' not in result.stdout


def test_required_service_failure_is_fatal():
    result = bash(f'''source "{PACKAGING}/bootstrap.sh"
logger() {{ :; }}
systemctl() {{ return 7; }}
stage() {{ systemctl restart required; echo FALSE_SUCCESS; }}
run_stage services stage
''')
    assert result.returncode == 7
    assert 'FALSE_SUCCESS' not in result.stdout


def test_firstboot_explicit_retry_and_trace(tmp_path):
    state = tmp_path / 'state'
    console = tmp_path / 'console'
    log = tmp_path / 'bootstrap.log'
    bootstrap = tmp_path / 'bootstrap.sh'
    calls = tmp_path / 'calls'
    bootstrap.write_text('exit 23\n')
    script = (PACKAGING / 'firstboot-bootstrap.sh').read_text()
    for old, new in [('/var/lib/vs-router-bootstrap', state),
                     ('/opt/vs-router/backend/packaging/bootstrap.sh', bootstrap),
                     ('/root/bootstrap.log', log), ('/dev/console', console)]:
        script = script.replace(old, str(new))
    script = script.replace('systemctl disable vs-router-bootstrap-firstboot.service',
                            f'echo disabled >> "{calls}"')
    wrapper = tmp_path / 'firstboot.sh'
    wrapper.write_text(script)
    def run(*args):
        return subprocess.run(['bash', '-x', str(wrapper), *args], capture_output=True, text=True)
    assert run().returncode == 23
    assert (state / 'attempted').exists()
    assert not calls.exists()
    bootstrap.write_text('echo SOFTWARE_INSTALLED\n')
    assert run().returncode == 1  # even after reboot, no implicit rerun
    result = run('--retry')
    assert result.returncode == 0
    assert (state / 'succeeded').exists()
    assert calls.read_text().strip() == 'disabled'
    assert 'bash -x' not in script
    assert 'export HOME=/root' in script
    assert 'export GOCACHE=/root/.cache/go-build' in script
    assert log.stat().st_mode & 0o777 == 0o600


def test_firstboot_refuses_incomplete_install(tmp_path):
    """A broken install (marker present) must not silently run the bootstrap."""
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'incomplete').write_text('2026-10-05T00:00:00Z source extraction failed\n')
    console = tmp_path / 'console'
    script = (PACKAGING / 'firstboot-bootstrap.sh').read_text()
    for old, new in [('/var/lib/vs-router-bootstrap', state),
                     ('/root/bootstrap.log', tmp_path / 'bootstrap.log'),
                     ('/dev/console', console)]:
        script = script.replace(old, str(new))
    wrapper = tmp_path / 'firstboot.sh'
    wrapper.write_text(script)
    result = subprocess.run(['bash', str(wrapper)], capture_output=True, text=True)
    assert result.returncode == 1
    assert 'incomplete' in (result.stdout + result.stderr).lower()
    # The bootstrap stage must not have been attempted.
    assert not (state / 'attempted').exists()
    assert 'incomplete' in console.read_text().lower()


def test_debian_installer_sources_are_snapshot_pinned():
    expected = (
        'd-i mirror/protocol string https',
        'd-i mirror/https/hostname string snapshot.debian.org',
        'd-i mirror/https/directory string /archive/debian/20261002T000000Z',
        'd-i mirror/suite string trixie',
        'd-i mirror/udeb/suite string trixie',
        'd-i apt-setup/services-select multiselect',
        'd-i apt-setup/local0/repository string https://snapshot.debian.org/archive/debian/20261002T000000Z trixie-updates',
        'd-i apt-setup/local1/repository string https://snapshot.debian.org/archive/debian-security/20261002T000000Z trixie-security',
        'check-valid-until=no',
    )
    for path in (ROOT / 'installer/preseed.cfg', ROOT / 'installer/preseed-semiauto.cfg'):
        preseed = path.read_text()
        assert all(setting in preseed for setting in expected)
        assert 'apt-setup/security_host string security.debian.org' not in preseed
        assert 'deb.debian.org' not in preseed


def test_console_menu_replaces_tty1_getty_without_assigning_lan():
    unit = (PACKAGING / 'vs-router-console.service').read_text()
    install = (PACKAGING / 'install.sh').read_text()
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    iso = (ROOT / 'installer/make-iso.sh').read_text()

    assert 'ExecStart=/usr/bin/python3 -m vs_router.agent.console_menu' in unit
    for setting in ('User=root', 'StandardInput=tty', 'TTYPath=/dev/tty1',
                    'TTYReset=yes', 'WantedBy=multi-user.target'):
        assert setting in unit
    assert 'After=vs-router-bootstrap-firstboot.service' in unit
    assert 'Conflicts=getty@tty1.service' in unit
    assert 'systemctl mask --now getty@tty1.service' not in install
    # The router installs the unit and hands tty1 to it. Both now sit behind the
    # profile test that keeps them off a panel host (ADR-0021), so they are read
    # from the router branch rather than from the whole script.
    router_branch = install.split('if [ "$PROFILE" = router ]; then')[1].split('\nfi')[0]
    assert 'systemctl mask getty@tty1.service' in router_branch
    assert 'systemctl enable vs-router-console.service' in router_branch
    # The unit file must be installed before tty1 is handed over to it.
    assert install.index('systemctl mask getty@tty1.service') > install.index('for unit in "$packaging_dir"/*.service')
    assert 'console menu on tty1' in bootstrap
    assert '192.168.10.1' not in bootstrap
    for name in ('preseed.cfg', 'preseed-semiauto.cfg'):
        preseed = (ROOT / 'installer' / name).read_text()
        assert '192.168.10.1' not in preseed
        assert 'netcfg/get_ipaddress' not in preseed
    assert 'VS_ROUTER_UNATTENDED_LAB' in iso
    assert 'VS_ROUTER_STATIC_NET' in iso
    assert 'requires VS_ROUTER_UNATTENDED_LAB=1' in iso


def test_no_production_credentials_or_open_ssh():
    production = (ROOT / 'installer/preseed-semiauto.cfg').read_text()
    assert 'vsr-install' not in production
    assert 'NOPASSWD' not in production
    assert 'passwd/user-password password' not in production
    assert 'openssh-server' not in production
    assert 'nftables' in production
    # Self-contained installer (ADR-0008): the source is vendored into the ISO,
    # never cloned from the network at install time.
    assert 'git clone' not in production
    assert '/cdrom/vs-router/install-source.sh' in production
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert 'Environment=VS_ROUTER_KEA_API_PASSWORD=' not in bootstrap
    assert 'LoadCredential=kea-api-password:' in bootstrap
    assert 'KEA_PASSWORD' not in bootstrap
    assert 'npm ci' in bootstrap
    assert '/tmp/vs-router-bootstrap' not in bootstrap


def test_release_build_inputs_are_pinned():
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert '@latest' not in bootstrap
    assert 'go install "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}"' in bootstrap
    assert 'github.com/caddy-dns/cloudflare@${CLOUDFLARE_MODULE_VERSION}' in bootstrap
    assert 'git clone https://github.com/WireGuard/wireguard-go' not in bootstrap
    assert "GO_TOOLCHAIN_VERSION='go1.25.1'" in bootstrap
    assert "NODE_VERSION='v20.19.2'" in bootstrap
    assert "NPM_VERSION='9.2.0'" in bootstrap
    for revision in (
            '1f50ad736ecca22a9bfc7b4606805ec9ca49fe48',
            'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843',
            'ecfc5a8d54462e18e13c72173e2623d16d8e25a0'):
        assert revision in bootstrap


def test_bootstrap_apt_uses_signed_fixed_snapshot():
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    sources = (PACKAGING / 'apt-snapshot.sources').read_text()
    assert 'readonly APT_RELEASE_SOURCES="$SCRIPT_DIR/apt-snapshot.sources"' in bootstrap
    assert '@APT_SNAPSHOT_TIMESTAMP@' not in sources
    assert 'https://snapshot.debian.org/archive/debian/20261002T000000Z/' in sources
    assert 'https://snapshot.debian.org/archive/debian-security/20261002T000000Z/' in sources
    assert sources.count('Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg') == 2
    assert sources.count('Check-Valid-Until: no') == 2
    apt_stage = bootstrap[bootstrap.index('stage_apt_deps() {'):bootstrap.index('\nstage_caddy() {')]
    assert 'apt_with_release update' in apt_stage
    assert 'apt_with_release install -y' in apt_stage
    assert 'apt_with_release install -y dbus ' in apt_stage
    assert 'Dir::Etc::sourceparts=-' in bootstrap


def test_backend_wheels_use_snapshot_build_backend():
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    updater = (PACKAGING / 'update.sh').read_text()
    apt_stage = bootstrap[bootstrap.index('stage_apt_deps() {'):bootstrap.index('\nstage_caddy() {')]
    assert 'python3-setuptools python3-wheel' in apt_stage
    assert '--no-build-isolation --no-deps' in bootstrap
    assert '--no-build-isolation --no-deps' in updater


def test_runtime_dependency_lock_matches_uv_lock():
    uv_lock = tomllib.loads((ROOT / 'backend/uv.lock').read_text())
    locked = {package['name']: package for package in uv_lock['package']}
    requirements = (ROOT / 'backend/requirements-runtime.txt').read_text().splitlines()
    package = None
    version = None
    hashes = []
    seen = set()

    def verify_current():
        if package is None:
            return
        assert package['version'] == version
        artifacts = {item['hash'] for item in package.get('wheels', [])}
        if package.get('sdist'):
            artifacts.add(package['sdist']['hash'])
        assert hashes and set(hashes) <= artifacts
        seen.add(package['name'])

    for line in requirements:
        if line.startswith('#') or not line.strip():
            continue
        if not line[0].isspace():
            verify_current()
            name, version = line.split('==', 1)
            version = version.split()[0]
            package = locked[name]
            hashes = []
        else:
            assert line.strip().startswith('--hash=sha256:')
            hashes.append(line.strip().removeprefix('--hash='))
    verify_current()
    assert len(seen) == len([line for line in requirements if line and not line[0].isspace() and not line.startswith('#')])


def test_runtime_installer_cleans_pip_copies_and_uses_hash_lock():
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    updater = (PACKAGING / 'update.sh').read_text()
    helper = (PACKAGING / 'install-runtime-deps.sh').read_text()
    lock = ROOT / 'backend/requirements-runtime.txt'
    assert 'install-runtime-deps.sh' in bootstrap
    assert 'install-runtime-deps.sh' in updater
    assert str(lock.name) in bootstrap and str(lock.name) in updater
    assert 'metadata.distributions(path=' in helper
    assert "strip().lower() == 'pip'" in helper
    assert '--require-hashes' in helper


def online_installer_dry_run(tmp_path, *, packaging=None, script=None):
    """Run the real dash entry point with fake host probes; no writes occur."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    # The installer checks root even in dry-run. Only spoof that check; every
    # host-changing command remains behind run(), and service probes are fake.
    identity = bin_dir / 'id'
    identity.write_text('#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')
    identity.chmod(0o755)
    for command in ('nft', 'unbound', 'awg', 'caddy'):
        probe = bin_dir / command
        probe.write_text('#!/bin/sh\nexit 1\n' if command == 'nft' else '#!/bin/sh\nexit 0\n')
        probe.chmod(0o755)
    # nft is needed by command -v, but list-table must report no SSH lock.
    (bin_dir / 'systemctl').write_text('#!/bin/sh\nexit 0\n')
    (bin_dir / 'systemctl').chmod(0o755)
    (bin_dir / 'ss').write_text('#!/bin/sh\nprintf "LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\\n"\n')
    (bin_dir / 'ss').chmod(0o755)
    env = {**os.environ, 'PATH': f'{bin_dir}:{os.environ["PATH"]}'}
    env.pop('PACKAGING', None)
    if packaging is not None:
        env['PACKAGING'] = str(packaging)
    result = subprocess.run(
        ['sh', str(script or PACKAGING / 'online-install.sh'), '--wheel', str(tmp_path / 'fixture.whl'),
         '--ui', str(tmp_path / 'ui'), '--dry-run'],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=10,
    )
    return result


@pytest.mark.parametrize('present', [('awg',), ('awg-go',), ('awg', 'awg-go'), ()])
def test_online_installer_builds_missing_awg_binaries_independently(tmp_path, present):
    """Run the real dry-run entry point with an isolated command lookup path."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stubs = {
        'id': '#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexit 0\n',
        'nft': '#!/bin/sh\nexit 1\n',  # No SSH lock table.
        'ss': '#!/bin/sh\necho "LISTEN 0 1 0.0.0.0:22 0.0.0.0:*"\n',
        'systemctl': '#!/bin/sh\nexit 0\n',  # SSH probe succeeds.
        'unbound': '#!/bin/sh\nexit 0\n',
        'caddy': '#!/bin/sh\nexit 0\n',
        'getent': '#!/bin/sh\nexit 0\n',
        'grep': '#!/bin/sh\nwhile IFS= read -r line; do\n'
                '    case "$line" in *":22 "*) exit 0;; esac\n'
                'done\nexit 1\n',
        **{name: '#!/bin/sh\nexit 0\n' for name in present},
    }
    for name, content in stubs.items():
        stub = bin_dir / name
        stub.write_text(content)
        stub.chmod(0o755)
    # No inherited PATH: installed awg/awg-go (or other host tools) cannot
    # alter the branch. Every privileged action is printed by run().
    env = {**os.environ, 'PATH': str(bin_dir)}
    env.pop('PACKAGING', None)
    result = subprocess.run(
        ['/bin/sh', str(PACKAGING / 'online-install.sh'), '--dry-run'],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ONLINE_INSTALL_OK' in result.stdout
    actions = result.stdout.splitlines()
    go_actions = (
        '+ git -C /root/vs-router-install clone --branch v3.1.20260812 --depth 1 https://github.com/amnezia-vpn/amneziawg-go',
        '+ make -C /root/vs-router-install/amneziawg-go',
        '+ install -m 0755 /root/vs-router-install/amneziawg-go/amneziawg-go /usr/local/bin/awg-go',
    )
    tools_actions = (
        '+ git -C /root/vs-router-install clone --branch v3.1.20260812 --depth 1 https://github.com/amnezia-vpn/amneziawg-tools',
        '+ make -C /root/vs-router-install/amneziawg-tools/src PREFIX=/usr BINDIR=/usr/local/bin install',
    )
    for action in go_actions:
        assert (action in actions) == ('awg-go' not in present), action
    for action in tools_actions:
        assert (action in actions) == ('awg' not in present), action


def test_online_installer_uses_pinned_helper_not_floating_ranges(tmp_path):
    script = (PACKAGING / 'online-install.sh').read_text()
    assert 'fastapi>=' not in script
    result = online_installer_dry_run(tmp_path, packaging=PACKAGING)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    helper = next(line for line in lines if 'install-runtime-deps.sh' in line)
    assert helper == f'+ bash {PACKAGING}/install-runtime-deps.sh {ROOT}/backend/requirements-runtime.txt'
    assert lines.index(helper) < next(i for i, line in enumerate(lines) if '--force-reinstall' in line)
    assert not any('fastapi>=' in line or 'pip install --break-system-packages --ignore-installed' in line
                   for line in lines)


def test_online_installer_dry_run_resolves_lock_without_packaging(tmp_path):
    result = online_installer_dry_run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'+ bash {PACKAGING}/install-runtime-deps.sh {ROOT}/backend/requirements-runtime.txt' in result.stdout
    assert 'fastapi>=' not in result.stdout


def test_online_installer_missing_lock_fails_closed(tmp_path):
    isolated = tmp_path / 'backend/packaging'
    isolated.mkdir(parents=True)
    script = isolated / 'online-install.sh'
    shutil.copyfile(PACKAGING / 'online-install.sh', script)
    result = online_installer_dry_run(tmp_path, packaging=isolated, script=script)
    assert result.returncode != 0
    assert 'ERROR: missing runtime dependency lock (backend/requirements-runtime.txt)' in result.stderr
    assert 'install-runtime-deps.sh' not in result.stdout
    assert '--force-reinstall' not in result.stdout
    assert 'fastapi>=' not in result.stdout + result.stderr


def test_runtime_installer_removes_all_pip_versions_in_isolated_target(tmp_path):
    """Actual offline pip install over conflicting metadata and mixed package files."""
    import hashlib
    import zipfile
    from importlib import metadata

    target = tmp_path / 'site-packages'
    target.mkdir()
    wheels = tmp_path / 'wheels'
    wheels.mkdir()
    venv = tmp_path / 'venv'
    subprocess.run(['/usr/bin/python3', '-m', 'venv', '--system-site-packages',
                    '--without-pip', str(venv)], check=True)

    def stale(name, version, files):
        package = target / name
        package.mkdir(exist_ok=True)
        version_dir = package / ('release_' + version.replace('.', '_'))
        version_dir.mkdir()
        for filename in files:
            (version_dir / filename).write_text(f'{version}: {filename}\n')
        info = target / f'{name}-{version}.dist-info'
        info.mkdir()
        (info / 'METADATA').write_text(f'Name: {name}\nVersion: {version}\n')
        (info / 'INSTALLER').write_text('pip\n')
        (info / 'RECORD').write_text(''.join(
            f'{name}/{version_dir.name}/{filename},,\n' for filename in files))

    stale('fastapi', '0.156.4', ['__init__.py', 'old_one.py'])
    stale('fastapi', '0.157.0', ['__init__.py', 'old_two.py'])
    stale('click', '8.3.0', ['__init__.py', 'old_click.py'])
    stale('unrelated', '1.0', ['__init__.py', 'keep.py'])

    lock = tmp_path / 'requirements.txt'
    pins = []
    for name, version in [('fastapi', '0.116.1'), ('click', '8.3.3')]:
        filename = f'{name}-{version}-py3-none-any.whl'
        wheel = wheels / filename
        info = f'{name}-{version}.dist-info'
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr(f'{name}/__init__.py', f'PINNED = "{version}"\n')
            archive.writestr(f'{info}/METADATA', f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n')
            archive.writestr(f'{info}/WHEEL', 'Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            archive.writestr(f'{info}/RECORD', '')
        pins.append(f'{name}=={version} --hash=sha256:{hashlib.sha256(wheel.read_bytes()).hexdigest()}')
    lock.write_text('\n'.join(pins) + '\n')
    env = {**os.environ, 'PATH': f'{venv / "bin"}:{os.environ["PATH"]}',
           'VS_ROUTER_DEPS_SITE_DIRS': str(target), 'PIP_NO_INDEX': '1',
           'PIP_FIND_LINKS': str(wheels), 'PYTHONNOUSERSITE': '1'}
    env.pop('PYTHONPATH', None)
    script = PACKAGING / 'install-runtime-deps.sh'
    for _ in range(2):
        result = subprocess.run(['bash', str(script), str(lock)], env=env,
                                text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        distributions = list(metadata.distributions(path=[str(target)]))
        for name, version in [('fastapi', '0.116.1'), ('click', '8.3.3')]:
            assert [(dist.metadata['Name'], dist.version) for dist in distributions
                    if dist.metadata['Name'].lower() == name] == [(name, version)]
            assert (target / name / '__init__.py').read_text() == f'PINNED = "{version}"\n'
            assert not list((target / name).glob('release_*'))
            assert not list((target / name).rglob('old_*.py'))
        assert (target / 'unrelated/release_1_0/keep.py').read_text() == '1.0: keep.py\n'
        assert (target / 'unrelated-1.0.dist-info').is_dir()

    clean = tmp_path / 'clean-site-packages'
    clean.mkdir()
    clean_result = subprocess.run(['bash', str(script), str(lock)],
                                  env={**env, 'VS_ROUTER_DEPS_SITE_DIRS': str(clean)},
                                  text=True, capture_output=True, timeout=60)
    assert clean_result.returncode == 0, clean_result.stdout + clean_result.stderr
    assert {(dist.metadata['Name'].lower(), dist.version)
            for dist in metadata.distributions(path=[str(clean)])} == {
                ('fastapi', '0.116.1'), ('click', '8.3.3')}

    missing = subprocess.run(['bash', str(script), str(tmp_path / 'absent')],
                             env=env, text=True, capture_output=True, timeout=10)
    assert missing.returncode != 0
    assert 'Missing dependency lock' in missing.stderr


def test_iso_requires_verified_inputs(tmp_path):
    env = dict(os.environ)
    env.pop('VS_ROUTER_REVISION', None)
    result = subprocess.run(['bash', str(ROOT / 'installer/make-iso.sh'), str(tmp_path / 'iso')],
                            env=env, text=True, capture_output=True)
    assert result.returncode != 0
    assert 'full reviewed source commit' in result.stderr


@pytest.fixture
def online_update_payload(tmp_path):
    payload = tmp_path / 'payload'
    packaging = payload / 'backend/packaging'
    shutil.copytree(PACKAGING, packaging)
    # Only the copied installer is invoked, never the real privileged script.
    (packaging / 'install.sh').write_text(
        '#!/bin/sh\n[ "$VS_ROUTER_KEEP_SSH" = 1 ] && [ "$VS_ROUTER_PROFILE" = panel ]\n')
    (packaging / 'update-run.sh').chmod(0o644)
    for item in ('alembic', 'alembic.ini', 'pyproject.toml'):
        source = ROOT / 'backend' / item
        target = payload / 'backend' / item
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    (payload / 'REVISION').write_text('a' * 40 + '\n')
    wheel = payload / 'artifacts/vs_router_backend-0.1.0-py3-none-any.whl'
    wheel.parent.mkdir()
    wheel.write_bytes(b'wheel fixture: copied, never installed')
    ui = payload / 'artifacts/ui'
    ui.mkdir()
    (ui / 'index.html').write_text('<!doctype html>\n')
    return payload, tmp_path / 'opt/vs-router', wheel


def stage_online_update_tree(payload, tree, wheel, *, dry_run=False):
    source = (PACKAGING / 'online-install.sh').read_text()
    # Execute precisely the privileged-install/staging block, with its actual
    # dry-run helper; all other host-changing installer stages stay unexecuted.
    run = source[source.index('run() {'):source.index('\n[ "$(id -u)"')]
    block = source[source.index('if [ -d "${PACKAGING:-}" ]; then'):
                   source.index('if [ -n "$UI" ]; then')]
    return bash(f'set -eu\numask 022\n{run}\n{block}', env={
        **os.environ, 'PACKAGING': str(payload / 'backend/packaging'),
        'WHEEL': str(wheel), 'UI': str(payload / 'artifacts/ui'),
        'VS_ROUTER_REPO_ROOT': str(tree),
        'DRY_RUN': '1' if dry_run else '0',
    })


def test_online_installer_stages_pinned_update_tree(online_update_payload):
    payload, tree, wheel = online_update_payload
    result = stage_online_update_tree(payload, tree, wheel)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tree / 'REVISION').read_text() == 'a' * 40 + '\n'
    entry = tree / 'backend/packaging/update-run.sh'
    assert entry.read_bytes() == (payload / 'backend/packaging/update-run.sh').read_bytes()
    assert os.access(entry, os.X_OK)
    assert entry.stat().st_mode & 0o777 == 0o755
    assert (tree / 'backend/dist' / wheel.name).read_bytes() == wheel.read_bytes()
    # The rollback re-runs install.sh, which deploys the UI from frontend/dist.
    assert (tree / 'frontend/dist/index.html').read_text() == '<!doctype html>\n'
    for source in (payload / 'backend').rglob('*'):
        if source.is_file():
            dest = tree / source.relative_to(payload)
            assert dest.read_bytes() == source.read_bytes()
            assert not dest.stat().st_mode & 0o022
    assert 'Update tree staged' in result.stdout and str(tree) in result.stdout
    assert not list(tree.rglob('update.json'))


def test_online_installer_update_tree_is_idempotent(online_update_payload):
    payload, tree, wheel = online_update_payload
    first = stage_online_update_tree(payload, tree, wheel)
    assert first.returncode == 0, first.stderr

    def snapshot():
        return {str(p.relative_to(tree)): (p.read_bytes(), p.stat().st_mode)
                for p in tree.rglob('*') if p.is_file()}

    before = snapshot()
    second = stage_online_update_tree(payload, tree, wheel)
    assert second.returncode == 0, second.stderr
    assert snapshot() == before


def test_online_installer_without_revision_stages_nothing(online_update_payload):
    payload, tree, wheel = online_update_payload
    (payload / 'REVISION').unlink()
    result = stage_online_update_tree(payload, tree, wheel)
    assert result.returncode == 0, result.stderr
    assert not tree.exists()
    assert 'WARNING' in result.stderr and 'no REVISION' in result.stderr
    assert 'Update tree staged' not in result.stdout


def test_online_installer_failed_install_stages_nothing(online_update_payload):
    payload, tree, wheel = online_update_payload
    (payload / 'backend/packaging/install.sh').write_text('exit 19\n')
    result = stage_online_update_tree(payload, tree, wheel)
    assert result.returncode == 19
    assert not tree.exists()


def test_online_installer_update_staging_dry_run(online_update_payload):
    payload, tree, wheel = online_update_payload
    result = stage_online_update_tree(payload, tree, wheel, dry_run=True)
    assert result.returncode == 0, result.stderr
    assert not tree.exists()
    assert '+ install ' in result.stdout


def test_online_installer_update_staging_without_optional_metadata(online_update_payload):
    payload, tree, wheel = online_update_payload
    shutil.rmtree(payload / 'backend/alembic')
    (payload / 'backend/alembic.ini').unlink()
    (payload / 'backend/pyproject.toml').unlink()
    result = stage_online_update_tree(payload, tree, wheel)
    assert result.returncode == 0, result.stderr
    assert (tree / 'backend/packaging/update-run.sh').is_file()
    assert (tree / 'backend/dist' / wheel.name).is_file()
    assert not (tree / 'backend/alembic').exists()


def test_shell_syntax():
    for script in [*PACKAGING.glob('*.sh'), ROOT / 'installer/make-iso.sh']:
        subprocess.run(['bash', '-n', str(script)], check=True)


def test_install_singbox_pins_match_agent_adapter():
    """The delivery script's pinned values must equal the adapter's (ADR-0012):
    a diverging archive/binary hash, version or provenance would install a
    binary the agent's fail-closed verification rejects."""
    from vs_router.agent import singbox_service as sb
    script = (PACKAGING / 'install-singbox.sh').read_text()
    assert f"SINGBOX_VERSION='{sb.SINGBOX_VERSION}'" in script
    assert f"SINGBOX_ARCHIVE_SHA256='{sb.SINGBOX_ARCHIVE_SHA256}'" in script
    assert f"SINGBOX_BINARY_SHA256='{sb.SINGBOX_BINARY_SHA256}'" in script
    assert f"SINGBOX_PROVENANCE_REVISION='{sb.SINGBOX_PROVENANCE_REVISION}'" in script
    assert 'https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_TAG}/' in script
    assert 'sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz' in script
    assert f"SINGBOX_TAG='v{sb.SINGBOX_VERSION}'" in script
    # The destination is the fixed absolute path the adapter runs.
    assert sb.SINGBOX_BINARY in script


def test_install_singbox_delivery_is_hash_anchored_and_fail_closed():
    script = (PACKAGING / 'install-singbox.sh').read_text()
    # https-only download; integrity is mandatory for archive *and* binary.
    assert "curl --fail --location --silent --show-error --proto '=https' --tlsv1.2" in script
    assert script.count('sha256sum -c -') >= 2
    assert 'grep -qx "sing-box version' in script
    assert 'Revision: ${SINGBOX_PROVENANCE_REVISION}' in script
    assert 'contains unsafe paths' in script
    assert 'install -m 0755 -o root -g root' in script
    assert 'eval' not in script
    # Executable-standalone guard so tests can source it without side effects.
    assert 'if [[ ${BASH_SOURCE[0]} == "$0" ]]' in script


def test_bootstrap_delivers_the_pinned_singbox_binary():
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert "run_stage 'singbox' stage_singbox" in bootstrap
    assert 'install-singbox.sh' in bootstrap


def test_install_singbox_keeps_verified_binary_without_download(tmp_path):
    """Idempotency: an already-correct pinned binary is kept and the network is
    never touched (no curl call)."""
    from vs_router.agent import singbox_service as sb
    dest = tmp_path / 'sing-box'
    (tmp_path / 'libcronet.so').write_text('pinned library')
    dest.write_text('#!/bin/sh\n'
                    f'printf "%s\\n" "sing-box version {sb.SINGBOX_VERSION}"\n'
                    f'printf "%s\\n" "Revision: {sb.SINGBOX_PROVENANCE_REVISION}"\n')
    dest.chmod(0o755)
    code = f'''source "{PACKAGING}/install-singbox.sh"
sha256sum() {{ if [[ $1 == *libcronet.so ]]; then echo "{sb.SINGBOX_LIBCRONET_SHA256}  $1"; else echo "{sb.SINGBOX_BINARY_SHA256}  $1"; fi; }}
curl() {{ echo CURL_CALLED; return 1; }}
main
'''
    result = bash(code, env={**os.environ, 'VS_ROUTER_SINGBOX_DEST': str(dest)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'CURL_CALLED' not in result.stdout + result.stderr
    assert 'already present' in result.stdout


def test_install_singbox_rejects_wrong_archive_hash(tmp_path):
    """A downloaded archive whose SHA-256 is not the pin fails closed and
    installs nothing."""
    dest = tmp_path / 'sing-box'
    code = f'''source "{PACKAGING}/install-singbox.sh"
curl() {{ local out=''; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out=$2; shift; done; printf 'not the pinned archive' > "$out"; return 0; }}
main
'''
    result = bash(code, env={**os.environ, 'VS_ROUTER_SINGBOX_DEST': str(dest)})
    assert result.returncode != 0
    assert 'does not match' in result.stdout + result.stderr
    assert not dest.exists()


@pytest.mark.parametrize('corrupt_pin', [False, True])
def test_install_singbox_extracts_verified_libcronet_next_to_binary(tmp_path, corrupt_pin):
    """Exercise real tar/hash/install flow, with root ownership flags removed only
    in the unprivileged fixture. A wrong library pin must leave both absent."""
    import hashlib
    import tarfile

    from vs_router.agent import singbox_service as sb

    payload = tmp_path / f'sing-box-{sb.SINGBOX_VERSION}-linux-amd64'
    payload.mkdir()
    binary = payload / 'sing-box'
    binary.write_text('#!/bin/sh\n'
                      f'printf "%s\\n" "sing-box version {sb.SINGBOX_VERSION}"\n'
                      f'printf "%s\\n" "Revision: {sb.SINGBOX_PROVENANCE_REVISION}"\n')
    binary.chmod(0o755)
    library = payload / 'libcronet.so'
    library.write_bytes(b'fixture library, not a release artifact')
    archive = tmp_path / 'fixture.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        tar.add(payload, arcname=payload.name)

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    source = (PACKAGING / 'install-singbox.sh').read_text()
    source = source.replace(sb.SINGBOX_ARCHIVE_SHA256, digest(archive))
    source = source.replace(sb.SINGBOX_BINARY_SHA256, digest(binary))
    source = source.replace(' -o root -g root ', ' ')
    script = tmp_path / 'fixture-install.sh'
    script.write_text(source)
    manifest = tmp_path / 'library.sha256'
    manifest.write_text(('0' * 64 if corrupt_pin else digest(library)) + '\n')
    dest = tmp_path / 'installed/sing-box'
    result = subprocess.run(['bash', str(script)], capture_output=True, text=True,
                            env={**os.environ, 'VS_ROUTER_SINGBOX_ARCHIVE': str(archive),
                                 'VS_ROUTER_SINGBOX_DEST': str(dest),
                                 'VS_ROUTER_SINGBOX_LIBCRONET_MANIFEST': str(manifest)},
                            timeout=20)
    if corrupt_pin:
        assert result.returncode != 0
        assert 'extracted libcronet SHA-256 does not match' in result.stderr
        assert not dest.exists()
        assert not dest.with_name('libcronet.so').exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert dest.read_bytes() == binary.read_bytes()
        assert dest.with_name('libcronet.so').read_bytes() == library.read_bytes()


def test_unbound_apparmor_override_is_installed_and_enabled(tmp_path):
    """install.sh creates the local override granting /etc/vs-router/applied/**
    to the confined unbound and reloads the profile. The stock profile already
    contains the active `#include <local/usr.sbin.unbound>` directive, so the
    local file must exist for the reload to succeed; the profile text itself is
    left untouched and the rule is not duplicated on rerun."""
    source = (PACKAGING / 'install.sh').read_text()
    block = source[source.index('# Allow the included configuration through Unbound'):
                   source.index('# Web UI static bundle')]
    etc = tmp_path / 'etc'
    (etc / 'apparmor.d/local').mkdir(parents=True)
    profile = etc / 'apparmor.d/usr.sbin.unbound'
    original_profile = ('profile usr.sbin.unbound flags=(attach_disconnected) {\n'
                        '  #include <local/usr.sbin.unbound>\n}\n')
    profile.write_text(original_profile)
    block = block.replace('/etc/', str(etc) + '/')
    code = f'''set -eu
apparmor_parser() {{ echo "PARSER $*"; }}
{block}
'''
    for _ in range(2):  # rerun must stay idempotent (no duplicate rule)
        result = bash(code)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'PARSER -r' in result.stdout
    local_profile = (etc / 'apparmor.d/local/usr.sbin.unbound').read_text()
    assert local_profile.count('/etc/vs-router/applied/** r,') == 1
    # The active include directive must not be rewritten into a plain rule.
    assert profile.read_text() == original_profile


def test_web_trusts_https_proxy_headers_only_on_restricted_unix_socket():
    unit = (PACKAGING / 'vs-router-web.service').read_text()
    command = next(line for line in unit.splitlines() if line.startswith('ExecStart='))
    assert '--uds /run/vs-router/web/web.sock' in command
    assert '--proxy-headers' in command
    assert '--forwarded-allow-ips="*"' in command
    assert '--host ' not in command and '--port ' not in command
    assert 'UMask=0007' in unit


@pytest.mark.parametrize('failure', ['bus', 'systemctl', 'networkctl', 'wait_online', 'lease', 'dns', None])
def test_network_migration_requires_working_networkd(tmp_path, failure):
    from vs_router.generators.networkd import deserialize_networkd
    script = (PACKAGING / 'bootstrap.sh').read_text()
    # Rewrite every absolute host path touched by this stage into the sandbox.
    for prefix in ('/etc/', '/sys/', '/run/', '/var/lib/'):
        script = script.replace(prefix, str(tmp_path) + prefix)
    script = script.replace('/usr/lib/systemd/systemd-networkd-wait-online', 'wait_online')
    source = tmp_path / 'bootstrap.sh'
    source.write_text(script)
    (tmp_path / 'var/lib/vs-router-bootstrap').mkdir(parents=True)
    (tmp_path / 'var/lib/vs-router-bootstrap/installer-uplink').write_text('eth0 00:11:22:33:44:55\n')
    (tmp_path / 'etc/network').mkdir(parents=True)
    (tmp_path / 'etc/network/interfaces').write_text('auto eth0\niface eth0 inet dhcp\n')
    for iface in ('eth0', 'eth1'):
        base = tmp_path / 'sys/class/net' / iface
        (base / 'device').mkdir(parents=True)
        (base / 'address').write_text('00:11:22:33:44:55\n')
        (base / 'ifindex').write_text('2\n')
    (tmp_path / 'run/systemd/netif/leases').mkdir(parents=True)
    if failure != 'lease':
        (tmp_path / 'run/systemd/netif/leases/2').write_text('ADDRESS=192.0.2.2\n')
    code = f'''source "{source}"
logger() {{ :; }}
systemctl() {{ echo "systemctl $*"; if [[ $* == 'start dbus.socket' ]]; then [[ "{failure}" != bus ]]; else [[ "{failure}" != systemctl ]]; fi; }}
networkctl() {{ [[ "{failure}" != networkctl ]]; }}
wait_online() {{ [[ "{failure}" != wait_online ]]; }}
ip() {{ echo 'default via 192.0.2.1 dev eth0'; }}
getent() {{ [[ "{failure}" != dns ]]; }}
run_stage networkd stage_networkd
'''
    result = bash(code)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
    assert 'systemctl start dbus.socket' in result.stdout
    if failure != 'bus':
        assert result.stdout.index('systemctl start dbus.socket') < result.stdout.index('systemctl enable --now systemd-networkd.service')
    assert ('systemctl disable networking.service' in result.stdout) == (failure is None)
    files = list((tmp_path / 'etc/systemd/network').glob('*'))
    assert [p.name for p in files] == ['10-vs-router-eth0.network']
    manifest = (tmp_path / 'etc/vs-router/networkd-manifest.conf').read_text()
    assert deserialize_networkd(manifest) == {files[0].name: files[0].read_text()}
    if failure is None:
        # A rerun must preserve the configuration and avoid network changes.
        assert 'systemctl' not in bash(code).stdout
    else:
        # Retrying a failed staged configuration is supported.
        retry = bash(code.replace(f'"{failure}" !=', '"recovered" !='))
        if failure != 'lease':
            assert retry.returncode == 0, retry.stdout + retry.stderr


def secret_key_install_prefix(tmp_path):
    """Run the real installer prefix, stopping before any host-service changes."""
    source = (PACKAGING / 'install.sh').read_text()
    prefix = source[:source.index('# Listener remains closed')]
    assert 'Fernet.generate_key()' in prefix
    # Real install/chmod/rename and real Fernet; only root ownership is elided.
    assert 'install -m 0600 -o root -g root /dev/null' in prefix
    prefix = prefix.replace(' -o root -g root ', ' ')
    prefix = prefix.replace('/etc/', str(tmp_path / 'etc') + '/')
    return 'pppd() { :; }\n' + prefix + '\necho INSTALL_CONTINUED\n'


def assert_installed_secret_key(tmp_path, result):
    from cryptography.fernet import Fernet

    assert result.returncode == 0, result.stdout + result.stderr
    target = tmp_path / 'etc/vs-router/secrets.env'
    content = target.read_text()
    assert content.startswith('VS_ROUTER_SECRET_KEY=')
    assert content.endswith('\n') and len(content.splitlines()) == 1
    key = content.strip().split('=', 1)[1]
    cipher = Fernet(key.encode())
    assert cipher.decrypt(cipher.encrypt(b'installer regression')) == b'installer regression'
    assert target.stat().st_mode & 0o777 == 0o600
    assert key not in result.stdout + result.stderr
    assert not list(target.parent.glob('.secrets.env.*'))
    return target


@pytest.mark.parametrize('shell', ['sh', 'bash'])
def test_secret_key_criterion_1_missing_file_is_created_privately(tmp_path, shell):
    result = subprocess.run(
        [shell, '-xc', secret_key_install_prefix(tmp_path)],
        env={**os.environ, 'VS_ROUTER_PROFILE': 'panel'},
        text=True, capture_output=True, timeout=10,
    )
    target = assert_installed_secret_key(tmp_path, result)
    assert target.parent.stat().st_mode & 0o777 == 0o700
    assert 'Secret-encryption key: created' in result.stdout
    assert 'INSTALL_CONTINUED' in result.stdout


def test_secret_key_criterion_2_update_keeps_existing_bytes(tmp_path):
    target = tmp_path / 'etc/vs-router/secrets.env'
    target.parent.mkdir(parents=True)
    # Arbitrary non-empty contents must be preserved, not "repaired"/rotated.
    original = b'# retained environment\nVS_ROUTER_SECRET_KEY=existing-test-value\nEXTRA=kept\n'
    target.write_bytes(original)
    target.chmod(0o600)
    before = target.stat()
    code = 'python3() { echo GENERATOR_CALLED; return 19; }\n' + secret_key_install_prefix(tmp_path)
    result = bash('set -x\n' + code)
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.read_bytes() == original
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    assert target.stat().st_mode == before.st_mode
    assert 'Secret-encryption key: kept existing' in result.stdout
    assert 'GENERATOR_CALLED' not in result.stdout + result.stderr
    assert 'existing-test-value' not in result.stdout + result.stderr


def test_secret_key_criterion_3_empty_file_is_filled(tmp_path):
    target = tmp_path / 'etc/vs-router/secrets.env'
    target.parent.mkdir(parents=True)
    target.touch(mode=0o644)
    result = bash('set -x\n' + secret_key_install_prefix(tmp_path))
    assert_installed_secret_key(tmp_path, result)
    assert 'Secret-encryption key: created' in result.stdout


@pytest.mark.parametrize('generator', [
    'printf partial-output-must-not-be-published; return 19',
    'return 0',  # Even a successful process must not publish an empty key.
])
def test_secret_key_criterion_4_generator_failure_is_fatal(tmp_path, generator):
    code = f'python3() {{ {generator}; }}\n' + secret_key_install_prefix(tmp_path)
    result = bash('set -x\n' + code)
    assert result.returncode != 0
    assert not (tmp_path / 'etc/vs-router/secrets.env').exists()
    assert not list((tmp_path / 'etc/vs-router').glob('.secrets.env.*'))
    assert 'Secret-encryption key: created' not in result.stdout
    assert 'INSTALL_CONTINUED' not in result.stdout
    assert 'partial-output-must-not-be-published' not in result.stdout + result.stderr


@pytest.mark.parametrize('generator_fails', [False, True])
def test_secret_key_criterion_5_iso_uses_shared_installer(tmp_path, generator_fails):
    script = (PACKAGING / 'bootstrap.sh').read_text()
    assert 'Fernet.generate_key()' not in script
    for prefix in ('/etc/', '/var/lib/'):
        script = script.replace(prefix, str(tmp_path) + prefix)
    source = tmp_path / 'bootstrap.sh'
    source.write_text(script)
    # Bootstrap invokes this real prefix, not a mocked key-producing installer.
    (tmp_path / 'install.sh').write_text(secret_key_install_prefix(tmp_path))
    (tmp_path / 'backend/dist').mkdir(parents=True)
    (tmp_path / 'backend/dist/backend.whl').touch()
    (tmp_path / 'etc/kea').mkdir(parents=True)
    (tmp_path / 'etc/kea/kea-api-password').write_text('kea fixture\n')
    code = f'''set -x
source "{source}"
REPO_ROOT="{tmp_path}"
logger() {{ :; }}
python3() {{
    if [[ $1 == -m && $2 == pip ]]; then return 0; fi
    if [[ "{generator_fails}" == True && $1 == -c && $2 == *Fernet* ]]; then return 19; fi
    command python3 "$@"
}}
export -f python3
bash() {{
    case "$1" in
        "$SCRIPT_DIR/install.sh") command bash "$@" ;;
        "$SCRIPT_DIR/install-runtime-deps.sh") : ;;
        *) return 99 ;;
    esac
}}
chown() {{ :; }}
systemctl() {{
    if [[ $1 == restart && "$*" == *vs-router-* ]]; then
        test -s "{tmp_path}/etc/vs-router/secrets.env"
        echo SERVICES_RESTARTED_WITH_KEY
    fi
}}
runuser() {{ :; }}
curl() {{ :; }}
run_stage install stage_install
'''
    result = bash(code)
    if generator_fails:
        assert result.returncode != 0
        assert not (tmp_path / 'etc/vs-router/secrets.env').exists()
        assert 'SERVICES_RESTARTED_WITH_KEY' not in result.stdout
    else:
        assert_installed_secret_key(tmp_path, result)
        assert 'Secret-encryption key: created' in result.stdout
        assert 'SERVICES_RESTARTED_WITH_KEY' in result.stdout


def test_kea_secret_never_enters_trace_or_unit(tmp_path):
    source = tmp_path / 'bootstrap.sh'
    script = (PACKAGING / 'bootstrap.sh').read_text()
    for prefix in ('/etc/', '/var/lib/'):
        script = script.replace(prefix, str(tmp_path) + prefix)
    source.write_text(script)
    (tmp_path / 'backend/dist').mkdir(parents=True)
    (tmp_path / 'backend/dist/backend.whl').touch()
    (tmp_path / 'etc/kea').mkdir(parents=True)
    fixture = 'kea fixture value'
    password = tmp_path / 'etc/kea/kea-api-password'
    password.write_text(fixture + '\n')
    (tmp_path / 'etc/vs-router').mkdir()
    (tmp_path / 'etc/vs-router/secrets.env').write_text('EXISTING_KEY=unchanged\n')
    code = f'''set -x
source "{source}"
REPO_ROOT="{tmp_path}"
logger() {{ :; }}
python3() {{ [[ $1 == -m && $2 == pip ]]; }}
bash() {{ :; }}
chown() {{ :; }}
systemctl() {{ :; }}
runuser() {{ :; }}
curl() {{ :; }}
run_stage install stage_install
'''
    for _ in range(2):
        result = bash(code)
        assert result.returncode == 0, result.stdout + result.stderr
        assert fixture not in result.stdout + result.stderr
        assert password.read_text() == fixture + '\n'
    dropin = (tmp_path / 'etc/systemd/system/vs-router-web.service.d/kea-api.conf').read_text()
    assert fixture not in dropin
    assert 'LoadCredential=' in dropin
    assert password.stat().st_mode & 0o777 == 0o640


@pytest.mark.parametrize('lab', [False, True])
def test_iso_staged_contents(tmp_path, lab):
    import hashlib
    import json
    if not Path('/usr/lib/ISOLINUX/isohdpfx.bin').exists():
        pytest.skip('ISO builder requires isolinux boot files')
    fakebin = tmp_path / 'bin'
    fakebin.mkdir()
    xorriso = fakebin / 'xorriso'
    xorriso.write_text('''#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
args=sys.argv[1:]
if '-extract' in args:
    root=Path(args[-1])
    files={'.disk/info':'Debian GNU/Linux 13.1.0 amd64',
           'boot/grub/grub.cfg':"menuentry 'Install' {\\n linux /install.amd/vmlinuz --- quiet\\n initrd /install.amd/initrd.gz\\n}\\n",
           'boot/grub/efi.img':'',
           'isolinux/txt.cfg':'label install\\n menu label Install\\n kernel /install.amd/vmlinuz\\n append initrd=/install.amd/initrd.gz --- quiet\\n',
           'isolinux/spkgtk.cfg':'label installspk\\n ontimeout /install.amd/vmlinuz vga=788 initrd=/install.amd/gtk/initrd.gz speakup.synth=soft --- quiet\\n'}
    for name,content in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
else:
    root=Path('iso')
    data={}
    for p in root.rglob('*'):
        if p.is_file():
            rel=str(p.relative_to(root))
            try:
                data[rel]=p.read_text()
            except UnicodeDecodeError:
                data[rel]='<binary:%d>'%p.stat().st_size
    Path(os.environ['CAPTURE']).write_text(json.dumps(data))
''')
    xorriso.chmod(0o755)
    iso = tmp_path / 'input.iso'
    iso.write_bytes(b'isolated ISO fixture')
    capture = tmp_path / 'capture.json'
    revision = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=True).stdout.strip()
    env = dict(os.environ, PATH=f'{fakebin}:{os.environ["PATH"]}',
               CAPTURE=str(capture), OUT=str(tmp_path / 'output.iso'),
               VS_ROUTER_ISO_SHA256=hashlib.sha256(iso.read_bytes()).hexdigest(),
               VS_ROUTER_REVISION=revision, VS_ROUTER_UNATTENDED_LAB='1' if lab else '0')
    env.pop('VS_ROUTER_TEST_POWER_OFF', None)
    if lab:
        env['VS_ROUTER_TEST_POWER_OFF'] = '1'
    result = subprocess.run(['bash', str(ROOT / 'installer/make-iso.sh'), str(iso)],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    staged = json.loads(capture.read_text())
    assert ('vsr-install' in staged['preseed.cfg']) == lab
    assert ('debian-installer/exit/poweroff boolean true' in staged['preseed.cfg']) == lab
    # The pinned release source is vendored into the image, with integrity data.
    assert staged['vs-router/source.tar.gz'].startswith('<binary:')
    assert staged['vs-router/sha256.txt'].split()[1] == 'source.tar.gz'
    assert staged['vs-router/REVISION'].strip() == revision
    assert '/cdrom/vs-router/install-source.sh' in staged['preseed.cfg']
    assert '/cdrom/vs-router/install-source.sh' in staged['preseed-semiauto.cfg']
    assert 'git clone' not in staged['preseed.cfg']
    assert 'git clone' not in staged['preseed-semiauto.cfg']
    assert 'vsr-install' not in staged['preseed-semiauto.cfg']
    assert ('auto=true' in staged['isolinux/spkgtk.cfg']) == lab
    assert ('locale=en_US.UTF-8' in staged['isolinux/spkgtk.cfg']) == lab
    assert 'preseed/file=/cdrom/preseed.cfg' in staged['isolinux/spkgtk.cfg']
    assert 'NOPASSWD' not in ''.join(staged.values())
    assert '@VS_ROUTER_REVISION@' not in ''.join(staged.values())
    for menu in ('boot/grub/grub.cfg', 'isolinux/txt.cfg'):
        assert 'priority=high' in staged[menu]
        assert ('auto=true' in staged[menu]) == lab
        assert ('locale=en_US.UTF-8' in staged[menu]) == lab


def test_installed_db_migrates_on_rerun(tmp_path):
    import sqlite3
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    db = tmp_path / 'installed.db'
    # An existing DB must not skip migrations. An unrelated table models data
    # that must survive both initial migration and subsequent installation.
    with sqlite3.connect(db) as conn:
        conn.execute('create table retained (value text)')
        conn.execute("insert into retained values ('preserved')")
    script = (PACKAGING / 'install.sh').read_text()
    block = script[script.index('DB=/var/lib/'):script.index('# AppArmor:')]
    block = block.replace('/var/lib/vs-router/vs-router.db', str(db))
    # The block invokes the ambient `python3`; pin the interpreter that runs the
    # suite, so the test does not depend on which python3 the developer's PATH
    # happens to shadow (install.sh installs alembic for the system python).
    import sys
    block = block.replace('python3 -m alembic', f'"{sys.executable}" -m alembic')
    code = f'''set -eu
packaging_dir="{PACKAGING}"
systemctl() {{ echo "$*"; }}
chown() {{ :; }}
{block}
'''
    for _ in range(2):
        result = bash(code)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'stop vs-router-web.service vs-router-agent.service' in result.stdout
        with sqlite3.connect(db) as conn:
            assert conn.execute('select value from retained').fetchone() == ('preserved',)
            revision = conn.execute('select version_num from alembic_version').fetchone()[0]
        expected = ScriptDirectory.from_config(Config(str(ROOT / 'backend/alembic.ini'))).get_current_head()
        assert revision == expected


def test_unbound_include_waits_for_first_applied_config(tmp_path):
    source = (PACKAGING / 'install.sh').read_text()
    block = source[source.index('if [ -d /etc/unbound ]; then'):
                   source.index('# Allow the included configuration through Unbound')]
    unbound = tmp_path / 'etc/unbound'
    applied = tmp_path / 'etc/vs-router/applied'
    unbound.mkdir(parents=True)
    applied.mkdir(parents=True)
    block = block.replace('/etc/unbound', str(unbound))
    block = block.replace('/etc/vs-router/applied', str(applied))
    include = unbound / 'unbound.conf.d/vs-router.conf'
    result = bash(block)
    assert result.returncode == 0, result.stderr
    assert not include.exists()
    (applied / 'unbound.conf').write_text('server:\n')
    result = bash(block)
    assert result.returncode == 0, result.stderr
    assert include.read_text() == f'include: "{applied}/unbound.conf"\n'


@pytest.mark.parametrize('identity,expected', [
    ('ID=debian\nVERSION_ID=13\n', 0),
    ('ID=debian\nVERSION_ID=12\n', 1),
    ('ID=ubuntu\nVERSION_ID=13\n', 1),
])
def test_platform_validation(tmp_path, identity, expected):
    release = tmp_path / 'os-release'
    release.write_text(identity)
    script = (PACKAGING / 'bootstrap.sh').read_text()
    script = script.replace('/etc/os-release', str(release)).replace('${EUID} -ne 0', '0 -ne 0')
    source = tmp_path / 'bootstrap.sh'
    source.write_text(script)
    result = bash(f'source "{source}"; logger() {{ :; }}; run_stage platform stage_check_root')
    assert result.returncode == expected


def test_updater_downloads_a_verified_pinned_release():
    """ADR-0010: the updater downloads a manifest-pinned artifact, verifies its
    SHA-256 and its REVISION, and never fetches a git branch/`latest` (a
    self-contained ISO tree has no `.git`, ADR-0008)."""
    updater = (PACKAGING / 'update.sh').read_text()
    assert not re.search(r'^\s*git\s+(fetch|pull|checkout)\b', updater, re.M)
    assert '--release' in updater
    assert '--manifest' in updater and '--manifest-url' in updater
    assert 'VS_ROUTER_UPDATE_MANIFEST_URL' in updater
    assert 'source_sha256' in updater
    assert 'sha256sum -c' in updater
    assert 'REVISION' in updater
    # A malformed release id or manifest digest must be rejected.
    assert '^[0-9a-f]{40}$' in updater
    assert '^[0-9a-f]{64}$' in updater
    # Downloads are https-only; integrity verification is mandatory.
    assert "--proto '=https'" in updater
    # A failed install step must be fatal, never a warning that still reports
    # success (a broken migration or restart silently leaves stale code).
    assert "|| fail 'alembic upgrade failed" in updater
    assert "|| warn 'alembic upgrade failed" not in updater
    # The restart is fatal too, and now takes the previous release back with it
    # (ADR-0021): the failure branch must end in `fail`, and must roll back.
    # vs-router-web-internal is included: it holds the schema in memory, and a
    # restart skipped there keeps validating new fields with the old model.
    restart = updater.split('if ! systemctl restart vs-router-agent vs-router-web vs-router-web-internal; then')[1]
    restart = restart.split('\n    fi')[0]
    assert 'rollback_update' in restart
    assert 'fail ' in restart
    assert 'warn ' not in restart.replace('warn \'the runtime services did not restart\'', '')


def test_install_records_release_identity(tmp_path):
    """install.sh records commit+semver+source for GET /api/release."""
    source = (PACKAGING / 'install.sh').read_text()
    assert '/etc/vs-router/version.json' in source
    assert 'VS_ROUTER_RELEASE_SOURCE' in source
    assert 'REVISION' in source  # fallback for a vendored, git-less tree
    # Exercise the identity block against a fake repo with a REVISION file.
    block = source[source.index('# Record the installed release identity'):
                   source.index('chmod 0644 /etc/vs-router/version.json') + len(
                       'chmod 0644 /etc/vs-router/version.json')]
    repo = tmp_path / 'repo'
    (repo / 'backend').mkdir(parents=True)
    (repo / 'backend/pyproject.toml').write_text('[project]\nversion = "1.2.3"\n')
    (repo / 'REVISION').write_text('a' * 40 + '\n')
    out = tmp_path / 'etc/vs-router'
    out.mkdir(parents=True)
    block = block.replace('/etc/vs-router/version.json', str(out / 'version.json'))
    block = block.replace('$(dirname -- "$packaging_dir")/..', str(repo))
    result = bash(block, env={**os.environ, 'VS_ROUTER_RELEASE_SOURCE': 'online'})
    assert result.returncode == 0, result.stderr
    import json
    recorded = json.loads((out / 'version.json').read_text())
    assert recorded['commit'] == 'a' * 40
    assert recorded['semver'] == '1.2.3'
    assert recorded['source'] == 'online'
    assert recorded['installed_at'].endswith('Z')


def test_make_release_builds_a_verified_manifest(tmp_path):
    """ADR-0010: the release artifact is the pinned commit's tree plus REVISION,
    and release.json carries a SHA-256 that matches the artifact."""
    import hashlib
    import json
    out = tmp_path / 'release'
    revision = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=True).stdout.strip()
    result = subprocess.run(
        ['bash', str(PACKAGING / 'make-release.sh'), revision, '--skip-build'],
        env={**os.environ, 'VS_ROUTER_RELEASE_OUT': str(out),
             'VS_ROUTER_RELEASE_BASE_URL': 'https://example.invalid/download/vs-router-x'},
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((out / 'release.json').read_text())
    artifact = out / manifest['source_url'].rsplit('/', 1)[-1]
    assert manifest['commit'] == revision
    assert manifest['semver'] and manifest['min_os'] == 'debian-13'
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == manifest['source_sha256']
    assert (out / 'get.sh').is_file()
    # REVISION is inside the archive and equals the commit the manifest names.
    revision_in_tar = subprocess.run(['tar', '-xzOf', str(artifact), './REVISION'],
                                     capture_output=True, text=True, check=True).stdout.strip()
    assert revision_in_tar == revision
    # A malformed commit id is rejected before anything is written.
    bad = subprocess.run(['bash', str(PACKAGING / 'make-release.sh'), 'not-a-commit'],
                         env={**os.environ, 'VS_ROUTER_RELEASE_OUT': str(out)},
                         capture_output=True, text=True)
    assert bad.returncode != 0
    assert 'full 40-character commit id' in bad.stdout + bad.stderr


def test_make_release_never_uses_a_branch_or_latest_ref():
    maker = (PACKAGING / 'make-release.sh').read_text()
    assert not re.search(r'^\s*git\s+(fetch|pull|checkout)\b', maker, re.M)
    assert '^[0-9a-f]{40}$' in maker
    assert 'git archive' in maker


def test_release_consumers_reuse_the_prebuilt_bundle():
    """update.sh and install-release.sh skip the host build when the release
    archive ships the prebuilt wheel + frontend/dist (make-release.sh default)."""
    updater = (PACKAGING / 'update.sh').read_text()
    wrapper = (PACKAGING / 'install-release.sh').read_text()
    for text, name in ((updater, 'update.sh'), (wrapper, 'install-release.sh')):
        assert 'Release ships prebuilt artifacts' in text, name
        assert 'backend/dist' in text, name
        assert 'frontend/dist/index.html' in text, name


def test_libcronet_manifest_and_install_placement():
    from vs_router.agent import singbox_service as sb
    manifest = (PACKAGING / 'singbox-libcronet.sha256').read_text().strip()
    script = (PACKAGING / 'install-singbox.sh').read_text()
    install = (PACKAGING / 'install.sh').read_text()
    assert manifest == sb.SINGBOX_LIBCRONET_SHA256
    assert 'VS_ROUTER_SINGBOX_LIBCRONET_MANIFEST' in script
    assert '"$LIBCRONET_DEST"' in script
    assert 'install -m 0644 -o root -g root "$libcronet"' in script
    assert 'bash "$packaging_dir/install-singbox.sh"' in install
