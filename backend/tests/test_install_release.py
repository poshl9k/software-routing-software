"""Isolated contract tests for the source/build panel install wrapper.

Only fixture trees and a fake PATH are executable; never run the real installer.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'backend/packaging/install-release.sh'
COMMIT = 'a' * 40
WHEEL = 'vs_router_backend-0.1.0-py3-none-any.whl'


@pytest.fixture
def rig(tmp_path):
    source = tmp_path / 'source with spaces'
    packaging = source / 'backend/packaging'
    packaging.mkdir(parents=True)
    (packaging / 'install.sh').write_text('#!/bin/sh\nexit 98\n')
    (packaging / 'online-install.sh').write_text(
        '#!/bin/sh\n'
        'printf "PACKAGING=%s\\n" "$PACKAGING" >> "$CALLS"\n'
        'printf "ARG=%s\\n" "$@" >> "$CALLS"\n'
        'if [ "${CHILD_FAIL:-0}" = 1 ]; then exit 37; fi\n'
        'printf "FALSE_SUCCESS\\n" >> "$CALLS"\n')
    (source / 'backend/pyproject.toml').write_text('[project]\nname="vs-router-backend"\n')
    (source / 'frontend').mkdir()
    (source / 'frontend/package.json').write_text('{}\n')
    (source / 'REVISION').write_text(COMMIT + '\n')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    # No host PATH fallback: missing node/npm/uv must really be missing.
    for name in ('bash', 'sh', 'env', 'dirname', 'pwd', 'mkdir', 'rm', 'cp', 'mv',
                 'sha256sum', 'tar', 'grep', 'sed', 'awk', 'tr', 'cat', 'readlink',
                 'stat', 'realpath', 'mktemp', 'head', 'sort', 'find', 'install'):
        actual = shutil.which(name)
        assert actual, name
        (bin_dir / name).symlink_to(actual)
    calls = tmp_path / 'calls'
    def fake(name, text):
        p = bin_dir / name
        p.write_text('#!/bin/sh\n' + text)
        p.chmod(0o755)
        return p
    fake('id', 'printf "ID %s\\n" "$*" >> "$CALLS"; echo "${FAKE_UID:-0}"\n')
    fake('apt-get', 'printf "APT %s\\n" "$*" >> "$CALLS"\n')
    fake('systemctl', 'echo DANGEROUS_SYSTEMCTL >> "$CALLS"; exit 99\n')
    fake('nft', 'echo DANGEROUS_NFT >> "$CALLS"; exit 99\n')
    fake('npm', 'printf "NPM %s\\n" "$*" >> "$CALLS"\n'
         '[ "${NPM_FAIL:-0}" = 1 ] && exit 19\n'
         'if [ "$1" = run ]; then mkdir -p dist; printf UI > dist/index.html; fi\n')
    fake('node', 'printf "NODE %s\\n" "$*" >> "$CALLS"; echo "${NODE_VERSION:-v22.12.0}"\n')
    fake('uv', 'printf "UV %s\\n" "$*" >> "$CALLS"\n'
         '[ "${UV_FAIL:-0}" = 1 ] && exit 21\n'
         'mkdir -p dist; printf WHEEL > "dist/' + WHEEL + '"\n')
    fake('python3', 'printf "PYTHON %s\\n" "$*" >> "$CALLS"\n'
         '# The wrapper calls `python3 - <https-url> [dest]` when curl is absent.\n'
         'if [ "$1" = - ] && [ "${2#https://}" != "$2" ]; then\n'
         '  cat >/dev/null\n'
         '  case "$2" in\n'
         '    *release.json) [ -n "${MANIFEST_FIXTURE:-}" ] || exit 71; cp "$MANIFEST_FIXTURE" "${3:?}" ;;\n'
         '    *source.tar.gz) [ -n "${ARCHIVE_FIXTURE:-}" ] || exit 72; cp "$ARCHIVE_FIXTURE" "${3:?}" ;;\n'
         '    *api.ipify.org*) printf %s "${IPIFY:-198.51.100.42}" ;;\n'
         '    *) exit 73 ;;\n'
         '  esac\n'
         '  exit 0\n'
         'fi\n'
         'if [ "$1" = -m ] && [ "$2" = pip ]; then\n'
         '  [ "$3" = --version ] && exit 0\n'
         '  printf "PIP %s\\n" "$*" >> "$CALLS"\n'
         '  [ "${PIP_FAIL:-0}" = 1 ] && exit 22\n'
         '  out=dist; prev=; for a in "$@"; do [ "$prev" = -w ] && out=$a; prev=$a; done\n'
         '  mkdir -p "$out"; printf WHEEL > "$out/' + WHEEL + '"; exit 0\n'
         'fi\nexec "${REAL_PYTHON}" "$@"\n')
    fake('curl', 'printf "CURL %s\\n" "$*" >> "$CALLS"\n'
         'out=; url=; prev=; for a in "$@"; do\n'
         '  [ "$prev" = -o ] && out=$a; url=$a; prev=$a; done\n'
         'case "$url" in\n'
         '  *api.ipify.org) printf "%s" "${IPIFY:-198.51.100.42}" ;;\n'
         '  *release.json) cp "$MANIFEST_FIXTURE" "$out" ;;\n'
         '  *source.tar.gz) cp "$ARCHIVE_FIXTURE" "$out" ;;\n'
         '  *) exit 66 ;;\n'
         'esac\n')
    fake('ip', 'printf "IP %s\\n" "$*" >> "$CALLS"\n'
         'case "$*" in\n'
         '  *"route get"*) printf "%s\\n" "${IP_ROUTE:-}" ;;\n'
         '  *"route show"*) printf "%s\\n" "${IP_DEFAULT:-}" ;;\n'
         '  *"addr show"*) printf "%s\\n" "${IP_ADDR:-}" ;;\n'
         'esac\n')
    os_release = tmp_path / 'os-release'
    os_release.write_text('ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian GNU/Linux 13"\n')
    env = {**os.environ, 'PATH': str(bin_dir), 'CALLS': str(calls),
           'REAL_PYTHON': shutil.which('python3'),
           'VS_ROUTER_INSTALL_OS_RELEASE': str(os_release),
           'VS_ROUTER_UPDATE_CONFIG': str(tmp_path / 'missing-update.json'),
           'VS_ROUTER_INSTALL_WORK': str(tmp_path / 'work')}
    env.update(HOME=str(tmp_path), TMPDIR=str(tmp_path), XDG_CACHE_HOME=str(tmp_path / 'cache'))
    for key in ('VS_ROUTER_INSTALL_MANIFEST_URL', 'VS_ROUTER_PROFILE', 'VS_ROUTER_INSTALL_SOURCE', 'BASH_ENV', 'ENV'):
        env.pop(key, None)
    def run(*args, script=SCRIPT, **overrides):
        result = subprocess.run(['bash', '-c', 'exec bash "$@"', 'bash', str(script), *map(str, args)],
                                env={**env, **{k: str(v) for k, v in overrides.items()}},
                                capture_output=True, text=True, timeout=60, cwd=source)
        return result
    def events():
        return calls.read_text().splitlines() if calls.exists() else []
    return source, tmp_path, env, run, events, bin_dir


def built(source):
    wheel = source / 'backend/dist' / WHEEL
    wheel.parent.mkdir(exist_ok=True)
    wheel.write_text('wheel fixture')
    ui = source / 'frontend/dist'
    ui.mkdir(exist_ok=True)
    (ui / 'index.html').write_text('UI fixture')
    return wheel


def release(rig, *, revision=COMMIT, member=None):
    source, tmp, env, _, _, _ = rig
    archive = tmp / 'source.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for p in source.rglob('*'):
            if p.is_file() and p.relative_to(source).as_posix() != 'REVISION':
                tar.add(p, arcname=p.relative_to(source).as_posix())
        content = (revision + '\n').encode()
        info = tarfile.TarInfo('REVISION')
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
        if member:
            info = tarfile.TarInfo(member)
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
    manifest = tmp / 'release.json'
    manifest.write_text(json.dumps({'commit': COMMIT, 'source_url': 'https://example.invalid/source.tar.gz',
                                    'source_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}))
    env.update(MANIFEST_FIXTURE=str(manifest), ARCHIVE_FIXTURE=str(archive))
    return manifest, archive


def assert_blocked(result, events):
    assert result.returncode != 0, result.stdout + result.stderr
    assert not any(x.startswith(('APT ', 'UV ', 'PIP ', 'NPM ', 'PACKAGING=')) for x in events())
    assert 'FALSE_SUCCESS' not in events()


def test_criterion_1_root_and_debian_warning(rig):
    source, tmp, env, run, events, _ = rig
    result = run('--source', source, FAKE_UID='1000')
    assert_blocked(result, events)
    assert not (tmp / 'work').exists()
    assert events() == ['ID -u']
    assert 'root' in result.stderr
    built(source)
    (tmp / 'os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04"\n')
    result = run('--source', source, '--skip-build', '--hostname', 'panel.example', '--dry-run')
    assert result.returncode == 0, result.stderr
    assert 'FALSE_SUCCESS' in events()
    assert 'WARNING' in result.stderr and 'Ubuntu 24.04' in result.stderr


@pytest.mark.parametrize('bad', ['not-a-commit', 'A' * 40, 'a' * 39, 'a' * 41])
def test_criterion_2_invalid_release_before_download(rig, bad):
    _, _, _, run, events, _ = rig
    assert_blocked(run('--release', bad), events)
    assert events() == ['ID -u']


@pytest.mark.parametrize('change', ['commit', 'sha', 'revision', 'manifest_http', 'artifact_http', 'malformed_sha', 'escape'])
def test_criterion_2_integrity_fails_before_build(rig, change):
    _, _, env, run, events, _ = rig
    manifest, archive = release(rig, revision='b' * 40 if change == 'revision' else COMMIT,
                                member='../escape' if change == 'escape' else None)
    data = json.loads(manifest.read_text())
    if change == 'commit':
        data['commit'] = 'b' * 40
    elif change == 'sha':
        data['source_sha256'] = 'f' * 64
    elif change == 'manifest_http':
        pass
    elif change == 'artifact_http':
        data['source_url'] = 'http://example.invalid/source.tar.gz'
    elif change == 'malformed_sha':
        data['source_sha256'] = 'oops'
    manifest.write_text(json.dumps(data))
    url = 'http://example.invalid/release.json' if change == 'manifest_http' else 'https://example.invalid/release.json'
    result = run('--manifest', url, '--release', COMMIT)
    assert_blocked(result, events)
    for call in (x for x in events() if x.startswith('CURL ') and 'release.json' in x):
        for option in ('--fail', '--location', '--silent', '--show-error', "--proto =https", '--tlsv1.2'):
            assert option in call
    if change == 'manifest_http':
        assert not any(x.startswith('CURL ') for x in events())
    assert not (env['VS_ROUTER_INSTALL_WORK'] and (Path(env['VS_ROUTER_INSTALL_WORK']) / 'escape').exists())


def test_criterion_2_manifest_precedence_and_cached_verification(rig):
    _, _, env, run, events, _ = rig
    manifest, archive = release(rig)
    env['VS_ROUTER_INSTALL_MANIFEST_URL'] = 'https://example.invalid/release.json'
    config = Path(env['VS_ROUTER_UPDATE_CONFIG'])
    config.write_text(json.dumps({'manifest_url': 'https://other.invalid/release.json'}))
    for args, expected_url in (
            (('--manifest', 'https://explicit.invalid/release.json'), 'https://explicit.invalid/release.json'),
            (('--release', COMMIT), 'https://example.invalid/release.json'),
            (('--release', COMMIT, '--manifest', 'https://explicit.invalid/release.json'),
             'https://explicit.invalid/release.json')):
        before = len(events())
        result = run(*args, '--skip-build', '--dry-run')
        # No built outputs is a valid reason for --skip-build failure; acquisition happened first.
        assert any(x.startswith('CURL ') and x.endswith(expected_url) for x in events()[before:]), result.stderr
    env.pop('VS_ROUTER_INSTALL_MANIFEST_URL')
    before = len(events())
    result = run('--release', COMMIT, '--skip-build', '--dry-run')
    assert any(x.startswith('CURL ') and x.endswith('https://other.invalid/release.json')
               for x in events()[before:]), result.stderr
    config.unlink()
    assert_missing_url(run('--release', COMMIT))


def test_criterion_2_cached_archive_is_rechecked(rig):
    _, _, env, run, events, _ = rig
    release(rig)
    args = ('--manifest', 'https://example.invalid/release.json',
            '--hostname', 'reserve.example', '--dry-run')
    first = run(*args)
    assert first.returncode == 0, first.stdout + first.stderr
    cache = [p for p in Path(env['VS_ROUTER_INSTALL_WORK']).rglob('*')
             if p.is_file() and p.name.endswith('.tar.gz')]
    assert cache, 'release archive was not retained for idempotent reruns'
    before = len(events())
    second = run(*args)
    assert second.returncode == 0, second.stdout + second.stderr
    assert not any('source.tar.gz' in x and x.startswith('CURL ') for x in events()[before:])
    cache[0].write_bytes(b'corrupted cached artifact')
    before = len(events())
    result = run(*args)
    assert_blocked(result, lambda: events()[before:])
    assert not any('source.tar.gz' in x and x.startswith('CURL ') for x in events()[before:])


def test_criterion_2_symlink_escape_is_rejected(rig):
    source, tmp, env, run, events, _ = rig
    release(rig)
    unsafe = tmp / 'unsafe.tar.gz'
    with tarfile.open(unsafe, 'w:gz') as tar:
        for p in source.rglob('*'):
            if p.is_file() and p.name != 'online-install.sh':
                tar.add(p, arcname=p.relative_to(source).as_posix())
        info = tarfile.TarInfo('backend/packaging/online-install.sh')
        info.type = tarfile.SYMTYPE
        info.linkname = '../../../../outside'
        tar.addfile(info)
    env['ARCHIVE_FIXTURE'] = str(unsafe)
    manifest = Path(env['MANIFEST_FIXTURE'])
    data = json.loads(manifest.read_text())
    data['source_sha256'] = hashlib.sha256(unsafe.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(data))
    assert_blocked(run('--manifest', 'https://example.invalid/release.json'), events)
    assert not (tmp / 'outside').exists()


def assert_missing_url(result):
    assert result.returncode != 0
    assert 'manifest' in result.stderr.lower()


def test_criterion_3_source_tree_requires_all_inputs(rig):
    source, _, _, run, events, _ = rig
    for rel in ('backend/packaging/install.sh', 'backend/packaging/online-install.sh',
                'backend/pyproject.toml', 'frontend/package.json'):
        target = source / rel
        content = target.read_bytes()
        target.unlink()
        assert_blocked(run('--source', source, '--hostname', 'panel.example'), events)
        target.write_bytes(content)


@pytest.mark.parametrize('failure', ['UV_FAIL', 'NPM_FAIL', 'missing_wheel', 'missing_ui', 'ambiguous'])
def test_criterion_4_build_fail_closed(rig, failure):
    source, _, _, run, events, bin_dir = rig
    if failure == 'missing_wheel':
        (bin_dir / 'uv').write_text('#!/bin/sh\necho UV_NO_WHEEL >> "$CALLS"\n')
    if failure == 'missing_ui':
        (bin_dir / 'npm').write_text('#!/bin/sh\necho NPM_NO_UI >> "$CALLS"\n')
    if failure == 'ambiguous':
        built(source)
        (source / 'backend/dist/other.whl').write_text('stale')
    result = run('--source', source, '--hostname', 'panel.example', **{failure: '1'} if failure.endswith('_FAIL') else {})
    assert result.returncode != 0, result.stdout + result.stderr
    assert not any(x.startswith('PACKAGING=') for x in events())
    assert 'FALSE_SUCCESS' not in events()
    if failure == 'UV_FAIL':
        assert not any(x.startswith('NPM ') for x in events())
    if failure == 'NPM_FAIL':
        assert 'NPM run build' not in events()


def test_criterion_4_pip_fallback_and_skip_build(rig):
    source, _, _, run, events, bin_dir = rig
    (bin_dir / 'uv').unlink()
    result = run('--source', source, '--hostname', 'panel.example')
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(x.startswith('PIP -m pip wheel ') for x in events())
    assert any(x == 'NPM ci' for x in events())
    assert any(x == 'NPM run build' for x in events())
    assert (source / 'backend/dist' / WHEEL).is_file()
    before = len(events())
    result = run('--source', source, '--hostname', 'panel.example', '--skip-build')
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(x.startswith(('PIP ', 'UV ', 'NPM ')) for x in events()[before:])


@pytest.mark.parametrize('tool', ['node', 'npm'])
def test_criterion_5_missing_node_or_npm_after_prerequisites(rig, tool):
    source, _, _, run, events, bin_dir = rig
    (bin_dir / tool).unlink()
    result = run('--source', source, '--hostname', 'panel.example')
    assert result.returncode != 0, result.stderr
    assert not any(x.startswith(('PIP ', 'UV ', 'NPM ', 'PACKAGING=')) for x in events())


@pytest.mark.parametrize('tool', ['node', 'npm'])
def test_criterion_5_skip_build_does_not_require_node(rig, tool):
    """--skip-build reuses existing artifacts, so a host without node is fine.

    Requirement 5 keeps an absent node/npm fatal for the BUILD path only; the
    reuse path must not demand a toolchain it never runs.
    """
    source, _, _, run, events, bin_dir = rig
    (bin_dir / tool).unlink()
    built(source)
    result = run('--source', source, '--skip-build', '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(x.startswith('PACKAGING=') for x in events())
    assert not any(x.startswith(('NPM ', 'UV ', 'PIP ')) for x in events())


@pytest.mark.parametrize('tool', ['node', 'npm'])
def test_criterion_5_dry_run_reports_missing_toolchain_as_a_plan(rig, tool):
    """A dry run must not fail on a toolchain it says it would install."""
    source, _, _, run, events, bin_dir = rig
    (bin_dir / tool).unlink()
    result = run('--source', source, '--hostname', 'reserve.example', '--dry-run')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Would install nodejs and npm' in result.stderr
    assert not any(x.startswith(('NPM ', 'UV ', 'PIP ')) for x in events())


def test_criterion_5_old_node_warns_with_version(rig):
    source, _, _, run, events, _ = rig
    result = run('--source', source, '--hostname', 'panel.example', NODE_VERSION='v20.19.2')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'v20.19.2' in result.stderr and 'WARNING' in result.stderr
    assert 'v20.19.2' in result.stderr.split('Panel URL:')[1]


@pytest.mark.parametrize('route,default,addr,ipify,expected', [
    ('1.1.1.1 via 203.0.113.1 dev eth0 src 8.8.8.8', '', '', '', '8.8.8.8'),
    ('1.1.1.1 dev eth0 src 10.1.1.1', 'default via 1.1.1.1 dev eth0',
     'inet 9.9.9.9/24 scope global eth0', '', '9.9.9.9'),
    ('', '', '', '8.8.4.4', '8.8.4.4'),
    ('1.1.1.1 src 127.0.0.1', '', '', '10.1.1.1', None),
    ('1.1.1.1 src 224.0.0.1', '', '', 'not-an-address', None),
])
def test_criterion_6_reserve_derivation(rig, route, default, addr, ipify, expected):
    source, _, _, run, events, _ = rig
    built(source)
    result = run('--source', source, '--skip-build', IP_ROUTE=route, IP_DEFAULT=default,
                 IP_ADDR=addr, IPIFY=ipify)
    if expected:
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'ARG=' + expected + '.nip.io' in events()
        if expected in ('8.8.8.8', '9.9.9.9'):
            assert not any('api.ipify.org' in x for x in events())
        else:
            network = [x for x in events() if x.startswith(('IP ', 'CURL '))]
            assert network[0] == 'IP -4 route get 1.1.1.1'
            assert network[-1] == 'CURL -fsS --max-time 10 https://api.ipify.org'
    else:
        assert result.returncode != 0
        assert 'pass --hostname <ip>.nip.io' in result.stderr
        assert not any(x.startswith('PACKAGING=') for x in events())


def test_criterion_6_custom_hostname_does_not_replace_reserve(rig):
    source, _, _, run, events, _ = rig
    built(source)
    result = run('--source', source, '--skip-build', '--custom-hostname', 'custom.example', IPIFY='8.8.4.4')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ARG=8.8.4.4.nip.io' in events()
    assert 'ARG=custom.example' in events()


def test_criterion_7_exact_composition_and_child_failure(rig):
    source, _, _, run, events, _ = rig
    wheel = built(source)
    flags = ('--hostname', 'reserve.example', '--custom-hostname', 'custom.example',
             '--path-prefix', '/secret', '--address', '8.8.8.8/32', '--ssh-port', '2222')
    result = run('--source', source, '--skip-build', *flags)
    assert result.returncode == 0, result.stdout + result.stderr
    assert [x for x in events() if x.startswith(('PACKAGING=', 'ARG='))] == [f'PACKAGING={source / "backend/packaging"}',
                            'ARG=--wheel', f'ARG={wheel}', 'ARG=--ui',
                            f'ARG={source / "frontend/dist"}',
                            *[f'ARG={x}' for x in flags]]
    assert 'https://reserve.example/secret' in result.stderr + result.stdout
    before = len(events())
    result = run('--source', source, '--skip-build', '--hostname', 'reserve.example', CHILD_FAIL='1')
    assert result.returncode == 37
    assert 'https://reserve.example/' not in result.stdout + result.stderr
    assert 'FALSE_SUCCESS' not in events()[before:]
    before = len(events())
    result = run('--source', source, '--skip-build', '--hostname', 'reserve.example')
    assert result.returncode == 0
    assert 'ARG=--ssh-port' not in events()[before:]


def test_criterion_8_no_host_ownership_intrusion():
    text = SCRIPT.read_text()
    executable = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    for forbidden in ('VS_ROUTER_PROFILE=', '/etc/vs-router/profile', 'LAB_MODE',
                      'systemctl mask', 'ssh.service.d', 'nft -f', '/etc/vs-router-ssh'):
        assert forbidden not in executable
    assert re.search(r'PACKAGING=.*online-install\.sh', executable, re.S)


def test_criterion_9_dry_run_has_no_build_or_apt(rig):
    source, _, env, run, events, _ = rig
    result = run('--source', source, '--hostname', 'reserve.example', '--dry-run')
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(x.startswith(('APT ', 'PIP ', 'UV ', 'NPM ')) for x in events())
    assert 'ARG=--dry-run' in events()
    assert not (source / 'backend/dist').exists()
    assert not (source / 'frontend/dist').exists()


def test_criterion_10_fresh_safety_and_rerun(rig):
    source, tmp, env, run, events, _ = rig
    built(source)
    work = tmp / 'selected-work'
    work.mkdir()
    sentinel = work / 'old'
    sentinel.write_text('old')
    for unsafe in ('/', str(source), str(source.parent), str(ROOT)):
        result = run('--source', source, '--work', unsafe, '--fresh', '--skip-build',
                     '--hostname', 'reserve.example')
        assert result.returncode != 0, result.stderr
        assert sentinel.read_text() == 'old'
    result = run('--source', source, '--work', work, '--fresh', '--skip-build', '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stdout + result.stderr
    assert not sentinel.exists()
    result = run('--source', source, '--work', work, '--skip-build', '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stdout + result.stderr
    assert '[vs-router-install]' in result.stderr


def test_mode_and_help_and_environment_overrides(rig):
    text = SCRIPT.read_text()
    assert SCRIPT.stat().st_mode & 0o777 == 0o755
    for name in ('VS_ROUTER_INSTALL_WORK', 'VS_ROUTER_INSTALL_OS_RELEASE',
                 'VS_ROUTER_UPDATE_CONFIG', 'VS_ROUTER_INSTALL_MANIFEST_URL'):
        assert name in text
    _, _, _, run, _, _ = rig
    result = run('--help', FAKE_UID='1000')
    assert result.returncode == 0
    for flag in ('--release', '--manifest', '--source', '--hostname', '--custom-hostname',
                 '--path-prefix', '--address', '--ssh-port', '--work', '--fresh',
                 '--skip-build', '--dry-run'):
        assert flag in result.stdout + result.stderr


def test_fetch_fallback_refuses_non_https():
    """The python3 fallback enforces the scheme it is trusted for."""
    text = SCRIPT.read_text()
    assert text.count('refusing a non-https URL') >= 2


def test_curl_absent_probe_uses_python3_and_warns_about_nat(rig):
    """A bare Debian has python3 but no curl; the reserve name must still resolve.

    The value comes from an external echo service, whose answer is the EGRESS
    address — behind NAT it may not be the address that reaches this host, so the
    run must warn instead of publishing a name silently.
    """
    source, _, _, run, events, bin_dir = rig
    (bin_dir / 'curl').unlink()
    built(source)
    result = run('--source', source, '--skip-build',
                 IP_ROUTE='1.1.1.1 via 10.15.15.1 dev ens192 src 10.15.15.15',
                 IPIFY='8.8.4.4')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'ARG=8.8.4.4.nip.io' in events()
    assert any(x.startswith('PYTHON - https://api.ipify.org') for x in events())
    assert not any(x.startswith('CURL ') for x in events())
    assert 'egress address can differ' in result.stderr


def test_curl_absent_release_download_uses_python3(rig):
    _, _, _, run, events, bin_dir = rig
    release(rig)
    (bin_dir / 'curl').unlink()
    result = run('--manifest', 'https://example.invalid/release.json',
                 '--hostname', 'reserve.example', '--dry-run')
    assert result.returncode == 0, result.stdout + result.stderr
    assert any('PYTHON - https://example.invalid/release.json' in x for x in events())
    assert any('source.tar.gz' in x for x in events())
    assert not any(x.startswith('CURL ') for x in events())


def test_composed_call_text_keeps_packaging_and_installer_profile():
    text = SCRIPT.read_text()
    assert 'env PACKAGING=' in text
    assert 'VS_ROUTER_PROFILE=router' not in text
    for literal in ("--proto '=https'", '--tlsv1.2', '--fail', 'manifest_field()', 'update.sh'):
        assert literal in text


def test_criterion_4_default_source_is_script_tree(rig):
    source, _, _, run, events, _ = rig
    copied = source / 'backend/packaging/install-release.sh'
    shutil.copy2(SCRIPT, copied)
    result = run('--hostname', 'reserve.example', script=copied)
    assert result.returncode == 0, result.stderr
    assert f'PACKAGING={source / "backend/packaging"}' in events()
    assert any(x.startswith('UV build') for x in events())
    assert 'NPM ci' in events() and 'NPM run build' in events()


@pytest.mark.parametrize('missing', ['wheel', 'ui'])
def test_criterion_4_skip_build_requires_both_outputs(rig, missing):
    source, _, _, run, events, _ = rig
    wheel = built(source)
    (wheel if missing == 'wheel' else source / 'frontend/dist/index.html').unlink()
    result = run('--source', source, '--skip-build', '--hostname', 'reserve.example')
    assert_blocked(result, events)


@pytest.mark.parametrize('failure', ['pip', 'npm_build'])
def test_criterion_4_other_build_failures_stop_install(rig, failure):
    source, _, _, run, events, bin_dir = rig
    if failure == 'pip':
        (bin_dir / 'uv').unlink()
        result = run('--source', source, '--hostname', 'reserve.example', PIP_FAIL='1')
        assert result.returncode == 22
        assert 'NPM ci' not in events()
    else:
        (bin_dir / 'npm').write_text(
            '#!/bin/sh\nprintf "NPM %s\\n" "$*" >> "$CALLS"\n'
            'if [ "$1" = run ]; then exit 23; fi\n')
        result = run('--source', source, '--hostname', 'reserve.example')
        assert result.returncode == 23
        assert 'NPM ci' in events() and 'NPM run build' in events()
    assert not any(x.startswith('PACKAGING=') for x in events())
    assert 'FALSE_SUCCESS' not in events()


@pytest.mark.parametrize('absent', ['backend/packaging/install.sh', 'backend/pyproject.toml', 'frontend/package.json'])
def test_criterion_3_extracted_tree_is_checked(rig, absent):
    source, _, _, run, events, _ = rig
    (source / absent).unlink()
    release(rig)
    result = run('--manifest', 'https://example.invalid/release.json', '--hostname', 'reserve.example')
    assert_blocked(result, events)


def test_criterion_10_fresh_redownloads_verified_artifact(rig):
    _, _, _, run, events, _ = rig
    release(rig)
    args = ('--manifest', 'https://example.invalid/release.json',
            '--hostname', 'reserve.example', '--dry-run')
    for extra, downloads in (((), 1), ((), 0), (('--fresh',), 1)):
        before = len(events())
        result = run(*args, *extra)
        assert result.returncode == 0, result.stderr
        assert sum(x.startswith('CURL ') and x.endswith('/source.tar.gz')
                   for x in events()[before:]) == downloads
        assert all(line.startswith('[vs-router-install]') for line in result.stderr.splitlines())


def test_criterion_10_work_symlink_cannot_delete_external_tree(rig):
    source, tmp, _, run, events, _ = rig
    outside = tmp / 'outside'
    outside.mkdir()
    marker = outside / 'retained'
    marker.write_text('retained')
    work = tmp / 'linked-work'
    work.symlink_to(outside, target_is_directory=True)
    result = run('--source', source, '--work', work, '--fresh', '--hostname', 'reserve.example')
    assert_blocked(result, events)
    assert marker.read_text() == 'retained'


def test_criterion_9_dry_run_release_writes_only_work(rig):
    source, tmp, _, run, events, _ = rig
    release(rig)
    before = {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
    work = tmp / 'dry-work'
    result = run('--manifest', 'https://example.invalid/release.json', '--work', work,
                 '--hostname', 'reserve.example', '--dry-run')
    assert result.returncode == 0, result.stderr
    assert before == {p.relative_to(source): p.read_bytes() for p in source.rglob('*') if p.is_file()}
    assert not any(x.startswith(('APT ', 'PIP ', 'UV ', 'NPM ')) for x in events())
    assert 'ARG=--dry-run' in events()
    assert any(p.name == 'REVISION' for p in work.rglob('*'))
    assert 'Would build' in result.stderr


def test_criterion_4_missing_build_tools_are_prepared_once(rig):
    source, _, _, run, events, bin_dir = rig
    for tool in ('node', 'npm'):
        (bin_dir / tool).rename(bin_dir / (tool + '.saved'))
    (bin_dir / 'apt-get').write_text(
        '#!/bin/sh\nprintf "APT %s\\n" "$*" >> "$CALLS"\n'
        'if [ "$1" = install ]; then\n'
        '  cp "$(dirname "$0")/node.saved" "$(dirname "$0")/node"\n'
        '  cp "$(dirname "$0")/npm.saved" "$(dirname "$0")/npm"\nfi\n')
    result = run('--source', source, '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stderr
    assert 'APT update -y' in events()
    assert any(x.startswith('APT install -y ') and 'python3-setuptools python3-wheel' in x for x in events())
    assert events().index('APT update -y') < next(i for i, x in enumerate(events()) if x.startswith('UV '))
    before = len(events())
    result = run('--source', source, '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stderr
    assert not any(x.startswith('APT ') for x in events()[before:])


def test_criterion_11_release_install_records_the_update_channel(rig):
    """ADR-0010: a release install leaves the host's update channel configured,
    so the panel can check and apply later releases without hand-editing
    /etc/vs-router/update.json. A pinned GitHub release URL is rewritten to the
    stable latest/download channel, never frozen on the installed release."""
    source, tmp, _, run, events, _ = rig
    release(rig)
    config = tmp / 'missing-update.json'
    url = f'https://github.com/owner/repo/releases/download/vs-router-{COMMIT}/release.json'
    result = run('--manifest', url, '--release', COMMIT, '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stderr
    assert json.loads(config.read_text())['manifest_url'] == \
        'https://github.com/owner/repo/releases/latest/download/release.json'


def test_criterion_11_dry_run_does_not_touch_the_update_channel(rig):
    source, tmp, _, run, events, _ = rig
    release(rig)
    config = tmp / 'missing-update.json'
    result = run('--manifest', 'https://example.invalid/release.json', '--release', COMMIT,
                 '--hostname', 'reserve.example', '--dry-run')
    assert result.returncode == 0, result.stderr
    assert not config.exists()

