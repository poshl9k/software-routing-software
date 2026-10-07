"""Execute packaging control flow with isolated files and fake host commands.

These tests never invoke host service/network/package managers.
"""
import os
from pathlib import Path
import re
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
    assert "installer.strip().lower() == 'pip'" in helper
    assert "'pip', 'uninstall', '--break-system-packages', '--yes'" in helper
    assert '--require-hashes' in helper


def test_iso_requires_verified_inputs(tmp_path):
    env = dict(os.environ)
    env.pop('VS_ROUTER_REVISION', None)
    result = subprocess.run(['bash', str(ROOT / 'installer/make-iso.sh'), str(tmp_path / 'iso')],
                            env=env, text=True, capture_output=True)
    assert result.returncode != 0
    assert 'full reviewed source commit' in result.stderr


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
    dest.write_text('#!/bin/sh\n'
                    f'printf "%s\\n" "sing-box version {sb.SINGBOX_VERSION}"\n'
                    f'printf "%s\\n" "Revision: {sb.SINGBOX_PROVENANCE_REVISION}"\n')
    dest.chmod(0o755)
    code = f'''source "{PACKAGING}/install-singbox.sh"
sha256sum() {{ echo "{sb.SINGBOX_BINARY_SHA256}  $1"; }}
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
    assert "|| fail 'one or more runtime services failed to restart" in updater
    assert "|| warn 'alembic upgrade failed" not in updater


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
        ['bash', str(PACKAGING / 'make-release.sh'), revision],
        env={**os.environ, 'VS_ROUTER_RELEASE_OUT': str(out),
             'VS_ROUTER_RELEASE_BASE_URL': 'https://example.invalid/download/vs-router-x'},
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads((out / 'release.json').read_text())
    artifact = out / manifest['source_url'].rsplit('/', 1)[-1]
    assert manifest['commit'] == revision
    assert manifest['semver'] and manifest['min_os'] == 'debian-13'
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == manifest['source_sha256']
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
