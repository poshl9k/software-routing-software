"""Execute packaging control flow with isolated files and fake host commands.

These tests never invoke host service/network/package managers.
"""
import os
from pathlib import Path
import subprocess

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
    assert log.stat().st_mode & 0o777 == 0o600


def test_no_production_credentials_or_open_ssh():
    production = (ROOT / 'installer/preseed-semiauto.cfg').read_text()
    assert 'vsr-install' not in production
    assert 'NOPASSWD' not in production
    assert 'passwd/user-password password' not in production
    assert 'openssh-server' not in production
    assert 'nftables' in production
    assert '@VS_ROUTER_REVISION@' in production
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert 'Environment=VS_ROUTER_KEA_API_PASSWORD=' not in bootstrap
    assert 'LoadCredential=kea-api-password:' in bootstrap
    assert 'KEA_PASSWORD' not in bootstrap
    assert 'npm ci' in bootstrap
    assert '/tmp/vs-router-bootstrap' not in bootstrap


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


@pytest.mark.parametrize('failure', ['systemctl', 'networkctl', 'wait_online', 'lease', 'dns', None])
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
    (tmp_path / 'etc/vs-router').mkdir(parents=True)
    (tmp_path / 'etc/network').mkdir()
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
systemctl() {{ echo "systemctl $*"; [[ "{failure}" != systemctl ]]; }}
networkctl() {{ [[ "{failure}" != networkctl ]]; }}
wait_online() {{ [[ "{failure}" != wait_online ]]; }}
ip() {{ echo 'default via 192.0.2.1 dev eth0'; }}
getent() {{ [[ "{failure}" != dns ]]; }}
run_stage networkd stage_networkd
'''
    result = bash(code)
    assert (result.returncode == 0) == (failure is None), result.stdout + result.stderr
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
           'isolinux/txt.cfg':'label install\\n menu label Install\\n kernel /install.amd/vmlinuz\\n append initrd=/install.amd/initrd.gz --- quiet\\n'}
    for name,content in files.items():
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
else:
    root=Path('iso')
    Path(os.environ['CAPTURE']).write_text(json.dumps({str(p.relative_to(root)):p.read_text() for p in root.rglob('*') if p.is_file()}))
''')
    xorriso.chmod(0o755)
    iso = tmp_path / 'input.iso'
    iso.write_bytes(b'isolated ISO fixture')
    capture = tmp_path / 'capture.json'
    env = dict(os.environ, PATH=f'{fakebin}:{os.environ["PATH"]}',
               CAPTURE=str(capture), OUT=str(tmp_path / 'output.iso'),
               VS_ROUTER_ISO_SHA256=hashlib.sha256(iso.read_bytes()).hexdigest(),
               VS_ROUTER_REVISION='a' * 40, VS_ROUTER_UNATTENDED_LAB='1' if lab else '0')
    result = subprocess.run(['bash', str(ROOT / 'installer/make-iso.sh'), str(iso)],
                            env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    staged = json.loads(capture.read_text())
    assert ('vsr-install' in staged['preseed.cfg']) == lab
    assert 'vsr-install' not in staged['preseed-semiauto.cfg']
    assert 'NOPASSWD' not in ''.join(staged.values())
    assert '@VS_ROUTER_REVISION@' not in ''.join(staged.values())
    for menu in ('boot/grub/grub.cfg', 'isolinux/txt.cfg'):
        assert 'priority=high' in staged[menu]
        assert ('auto=true' in staged[menu]) == lab


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
