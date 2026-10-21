"""Isolated release entry and builder contracts: no host install or network."""
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / 'backend/packaging'
TEMPLATE = PACKAGING / 'get.sh'
MAKER = PACKAGING / 'make-release.sh'
COMMIT = 'a' * 40
BASE = f'https://example.invalid/releases/download/vs-router-{COMMIT}'
MEMBER = 'backend/packaging/install-release.sh'
TOKENS = ('__VS_ROUTER_COMMIT__', '__VS_ROUTER_BASE_URL__', '__VS_ROUTER_SOURCE_SHA256__')
WRAPPER = ('#!/usr/bin/env bash\n'
           '[[ ${BASH_SOURCE[0]} == "$0" ]] || exit 91\n'
           'printf "EXEC=%s\\n" "$0" >> "$CALLS"\n'
           'printf "ARG=%s\\n" "$@" >> "$CALLS"\n')


def archive_at(path, *, kind='regular', member=MEMBER, extra=False):
    with tarfile.open(path, 'w:gz') as tar:
        info = tarfile.TarInfo(member)
        if kind == 'symlink':
            info.type = tarfile.SYMTYPE
            info.linkname = '../../outside'
            tar.addfile(info)
        elif kind == 'hardlink':
            info.type = tarfile.LNKTYPE
            info.linkname = '../../outside'
            tar.addfile(info)
        elif kind == 'directory':
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        else:
            content = WRAPPER.encode()
            info.size = len(content)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(content))
        if kind == 'duplicate':
            info = tarfile.TarInfo(member)
            content = WRAPPER.encode()
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        if extra:
            info = tarfile.TarInfo('backend/packaging/decoy.sh')
            content = b'never extracted\n'
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def rig(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('sh', 'bash', 'dirname', 'mkdir', 'chmod', 'rm', 'mv', 'cp', 'cat', 'sed', 'grep', 'awk', 'mktemp', 'pwd', 'install'):
        actual = shutil.which(name)
        assert actual, name
        (bin_dir / name).symlink_to(actual)
    calls = tmp_path / 'calls'

    def fake(name, body):
        target = bin_dir / name
        target.write_text('#!/bin/sh\n' + body)
        target.chmod(0o755)

    fake('id', 'printf "ID %s\\n" "$*" >> "$CALLS"\nprintf "%s\\n" "${FAKE_UID:-0}"\n')
    # Real digest, but instrument invocations; no fake success for integrity.
    fake('sha256sum', 'printf "SHA %s\\n" "$*" >> "$CALLS"\nexec "$REAL_SHA" "$@"\n')
    fake('curl', 'printf "CURL %s\\n" "$*" >> "$CALLS"\n'
         'out=; url=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; url=$a; prev=$a; done\n'
         '[ "$url" = "$ARTIFACT_URL" ] || exit 67\ncp "$ARCHIVE_FIXTURE" "$out"\n')
    fake('python3', 'printf "PYTHON %s\\n" "$*" >> "$CALLS"\n'
         'if [ "$1" = - ] && [ "${2#https://}" != "$2" ]; then\n'
         '  cat >/dev/null\n'
         '  [ "$2" = "$ARTIFACT_URL" ] || exit 68\n'
         '  cp "$ARCHIVE_FIXTURE" "${3:?}"\n'
         '  exit 0\n'
         'fi\nexec "$REAL_PYTHON" "$@"\n')
    os_release = tmp_path / 'os-release'
    os_release.write_text('ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian GNU/Linux 13"\n')
    fetch = tmp_path / 'fetch'
    fixture = tmp_path / 'fixture.tar.gz'
    digest = archive_at(fixture)
    env = {**os.environ, 'PATH': str(bin_dir), 'CALLS': str(calls),
           'REAL_SHA': shutil.which('sha256sum'), 'REAL_PYTHON': shutil.which('python3'),
           'ARTIFACT_URL': f'{BASE}/vs-router-{COMMIT}.tar.gz',
           'ARCHIVE_FIXTURE': str(fixture), 'VS_ROUTER_FETCH_DIR': str(fetch),
           'VS_ROUTER_FETCH_OS_RELEASE': str(os_release),
           'HOME': str(tmp_path), 'TMPDIR': str(tmp_path)}
    for key in ('BASH_ENV', 'ENV', 'PYTHONPATH'):
        env.pop(key, None)

    def generated(commit=COMMIT, base=BASE, sha=digest):
        text = TEMPLATE.read_text()
        for token, value in zip(TOKENS, (commit, base, sha)):
            assert text.count(token) == 1, (token, text.count(token))
            text = text.replace(token, value)
        script = tmp_path / 'get-fixture.sh'
        script.write_text(text)
        return script

    def run(script=None, *args, **overrides):
        return subprocess.run(['sh', str(script or generated()), *map(str, args)],
                              env={**env, **{k: str(v) for k, v in overrides.items()}},
                              cwd=tmp_path, capture_output=True, text=True, timeout=30)

    def events():
        return calls.read_text().splitlines() if calls.exists() else []

    return tmp_path, env, bin_dir, fetch, fixture, generated, run, events


def blocked(result, events):
    assert result.returncode != 0, result.stdout + result.stderr
    assert not any(x.startswith(('EXEC=', 'ARG=')) for x in events())


def download_events(events):
    return [x for x in events if x.startswith(('CURL ', 'PYTHON - https://'))]


def extraction_events(events):
    return [x for x in events if x.startswith('PYTHON ') and 'wrapper/backend/packaging/install-release.sh' in x]


def assert_exec(events, fetch):
    assert [x for x in events if x.startswith(('EXEC=', 'ARG='))] == [
        f'EXEC={fetch}/wrapper/backend/packaging/install-release.sh',
        'ARG=--release', f'ARG={COMMIT}', 'ARG=--manifest',
        f'ARG={BASE}/release.json', 'ARG=--hostname', 'ARG=reserve.example']


def test_criterion_1_unreplaced_template_refused(rig):
    _, _, _, fetch, _, _, run, events = rig
    result = run(TEMPLATE)
    blocked(result, events)
    assert 'release' in result.stderr.lower() and 'asset' in result.stderr.lower()
    assert not download_events(events()) and not fetch.exists()


def test_criterion_2_root_only_and_debian_warning(rig):
    tmp, _, _, _, _, _, run, events = rig
    result = run(None, FAKE_UID='1000')
    blocked(result, events)
    assert 'root' in result.stderr.lower()
    assert not download_events(events())
    other = tmp / 'ubuntu-release'
    other.write_text('ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME="Ubuntu 24.04"\n')
    result = run(None, '--hostname', 'reserve.example', VS_ROUTER_FETCH_OS_RELEASE=other)
    assert result.returncode == 0, result.stderr
    assert 'WARNING' in result.stderr and 'Ubuntu 24.04' in result.stderr


@pytest.mark.parametrize('commit,base', [('bad', BASE), ('g' * 40, BASE), ('a' * 39, BASE),
                                         (COMMIT, 'http://example.invalid'), (COMMIT, 'example.invalid')])
def test_criterion_3_pins_before_download_or_python(rig, commit, base):
    _, _, _, _, _, generated, run, events = rig
    blocked(run(generated(commit=commit, base=base)), events)
    assert not any(x.startswith(('CURL ', 'PYTHON ')) for x in events())


def test_criterion_4_hash_mismatch_stops_before_extraction(rig):
    _, _, _, fetch, _, generated, run, events = rig
    blocked(run(generated(sha='f' * 64)), events)
    assert any(x.startswith('SHA ') for x in events())
    assert not extraction_events(events())
    assert not (fetch / 'wrapper/backend/packaging/install-release.sh').exists()


def test_criterion_5_extraction_layout_spares_the_wrapper_repo_root():
    """The wrapper's repo root (dirname/../..) must not contain the work directory.

    Live failure: extracted at <fetch>/bootstrap/, the wrapper's root resolved to
    the fetch directory's parent — `/root` in production — which contains the
    default work directory `/root/vs-router-install`, so the wrapper's own guard
    refused the whole run with "unsafe --work path". Keeping the archive's
    backend/packaging layout under a wrapper/ root fixes the geometry, and this
    test pins the geometry itself rather than a string.
    """
    text = TEMPLATE.read_text()
    assert 'wrapper/backend/packaging/install-release.sh' in text
    assert 'bootstrap/install-release.sh' not in text

    fetch = Path('/root/vs-router-bootstrap')
    work = Path('/root/vs-router-install')

    def overlaps(root, path):
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    old = (fetch / 'bootstrap/install-release.sh').parent.parent.parent
    new = (fetch / 'wrapper/backend/packaging/install-release.sh').parent.parent.parent
    assert old == Path('/root')
    assert overlaps(old, work)  # the defect this test exists for
    assert not overlaps(new, work)


def test_criterion_5_curl_https_hash_extraction_and_shebang(rig):
    _, _, _, fetch, fixture, generated, run, events = rig
    digest = archive_at(fixture, extra=True)
    result = run(generated(sha=digest), '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stdout + result.stderr
    log = events()
    assert len(download_events(log)) == 1
    curl = download_events(log)[0]
    assert curl.endswith(f'{BASE}/vs-router-{COMMIT}.tar.gz')
    for flag in ('--fail', '--location', '--silent', '--show-error', '--proto =https', '--tlsv1.2'):
        assert flag in curl
    sha_index = next(i for i, x in enumerate(log) if x.startswith('SHA '))
    extraction = extraction_events(log)
    assert len(extraction) == 1
    assert log.index(curl) < sha_index < log.index(extraction[0])
    assert log.index(extraction[0]) < log.index(f'EXEC={fetch}/wrapper/backend/packaging/install-release.sh')
    assert fetch.joinpath('wrapper/backend/packaging/install-release.sh').read_text() == WRAPPER
    assert {p.relative_to(fetch).as_posix() for p in fetch.rglob('*') if p.is_file()} == {
        f'vs-router-{COMMIT}.tar.gz', 'wrapper/backend/packaging/install-release.sh'}
    assert fetch.joinpath('wrapper/backend/packaging/install-release.sh').stat().st_mode & 0o777 == 0o755
    assert_exec(log, fetch)
    assert '[vs-router-get]' in result.stderr and COMMIT in result.stderr


def test_criterion_5_arguments_are_forwarded_verbatim(rig):
    _, _, _, _, _, _, run, events = rig
    forwarded = ('--hostname', 'reserve.example', '--path-prefix', '/with spaces/*',
                 '--custom-hostname', '', '--work', 'work with spaces', '--fresh')
    result = run(None, *forwarded)
    assert result.returncode == 0, result.stderr
    assert [line for line in events() if line.startswith('ARG=')] == [
        'ARG=--release', f'ARG={COMMIT}', 'ARG=--manifest', f'ARG={BASE}/release.json',
        *['ARG=' + value for value in forwarded]]


def test_criterion_6_python_download_body_and_https_guard(tmp_path, monkeypatch):
    """Exercise the actual fallback body; only the network transport is replaced."""
    import sys
    import urllib.request

    body = TEMPLATE.read_text().split('import sys, urllib.request\n', 1)[1].split('\nPY', 1)[0]
    body = 'import sys, urllib.request\n' + body
    dest = tmp_path / 'download'
    observed = []

    class Transport:
        def open(self, request, *, timeout):
            observed.append((request.full_url, timeout))
            return io.BytesIO(b'fixture response')

    handlers = []

    def opener(handler):
        handlers.append(handler)
        return Transport()

    monkeypatch.setattr(urllib.request, 'build_opener', opener)
    monkeypatch.setattr(sys, 'argv', ['-', BASE + '/source.tar.gz', str(dest)])
    exec(compile(body, str(TEMPLATE), 'exec'), {})
    assert dest.read_bytes() == b'fixture response'
    assert observed == [(BASE + '/source.tar.gz', 120)]
    with pytest.raises(ValueError, match='non-https redirect'):
        handlers[0].redirect_request(None, None, 302, '', {}, 'http://example.invalid')
    observed.clear()
    monkeypatch.setattr(sys, 'argv', ['-', 'http://example.invalid', str(dest)])
    with pytest.raises(SystemExit, match='non-https URL'):
        exec(compile(body, str(TEMPLATE), 'exec'), {})
    assert observed == []


def test_criterion_6_python_fallback_without_curl(rig):
    _, _, bin_dir, fetch, _, _, run, events = rig
    (bin_dir / 'curl').unlink()
    result = run(None, '--hostname', 'reserve.example')
    assert result.returncode == 0, result.stdout + result.stderr
    log = events()
    assert any(x.startswith('PYTHON - https://') and f'{BASE}/vs-router-{COMMIT}.tar.gz' in x for x in log)
    assert not any(x.startswith('CURL ') for x in log)
    assert_exec(log, fetch)


@pytest.mark.parametrize('kind,member', [
    ('symlink', MEMBER), ('hardlink', MEMBER), ('directory', MEMBER),
    ('duplicate', MEMBER), ('regular', '../' + MEMBER),
    ('regular', '/' + MEMBER), ('regular', 'backend\\packaging/install-release.sh'),
    ('regular', './backend/../backend/packaging/install-release.sh'),
])
def test_criterion_7_unsafe_member_rejected(rig, kind, member):
    tmp, _, _, fetch, fixture, generated, run, events = rig
    digest = archive_at(fixture, kind=kind, member=member)
    result = run(generated(sha=digest))
    blocked(result, events)
    assert not (tmp / 'outside').exists()
    assert not (fetch / 'wrapper/backend/packaging/install-release.sh').exists()
    assert any(x.startswith('PYTHON ') for x in events())


def test_criterion_8_cached_archive_reused_then_corrupt_redownloaded(rig):
    _, _, _, fetch, _, _, run, events = rig
    args = ('--hostname', 'reserve.example')
    for expected in (1, 0, 1):
        before = len(events())
        result = run(None, *args)
        assert result.returncode == 0, result.stdout + result.stderr
        assert len(download_events(events()[before:])) == expected
        if expected == 0:
            cache = list(fetch.rglob(f'vs-router-{COMMIT}.tar.gz'))
            assert len(cache) == 1
            cache[0].write_bytes(b'corrupted archive')


def scratch_builder(tmp_path, *, template=None):
    repo = tmp_path / 'repo'
    packaging = repo / 'backend/packaging'
    packaging.mkdir(parents=True)
    shutil.copy2(MAKER, packaging / 'make-release.sh')
    (packaging / 'get.sh').write_text(TEMPLATE.read_text() if template is None else template)
    (packaging / 'install-release.sh').write_text(WRAPPER)
    (repo / 'backend/pyproject.toml').write_text('[project]\nversion = "1.2.3"\n')
    env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    def git(*args):
        return subprocess.run(['git', '-C', str(repo), *args], env=env,
                              capture_output=True, text=True, check=True).stdout.strip()
    git('init', '-q')
    git('add', '.')
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'],
                   env=env, check=True, capture_output=True)
    commit = git('rev-parse', 'HEAD')
    base = f'https://example.invalid/releases/download/vs-router-{commit}'
    out = tmp_path / 'output'
    env.update(VS_ROUTER_RELEASE_OUT=str(out), VS_ROUTER_RELEASE_BASE_URL=base + '/')
    def build(*args, extra_env=None):
        return subprocess.run(['bash', str(packaging / 'make-release.sh'), commit, *args],
                              env={**env, **(extra_env or {})}, cwd=repo,
                              capture_output=True, text=True, timeout=40)
    return repo, packaging, out, commit, base, build


def test_criterion_9_builder_generates_pinned_posix_entry(tmp_path):
    _, _, out, commit, base, build = scratch_builder(tmp_path)
    result = build()
    assert result.returncode == 0, result.stdout + result.stderr
    script = out / 'get.sh'
    assert script.is_file() and str(script) in result.stdout
    text = script.read_text()
    assert '__VS_ROUTER_' not in text
    archive = out / f'vs-router-{commit}.tar.gz'
    assert f"VS_ROUTER_COMMIT='{commit}'" in text
    assert f"VS_ROUTER_BASE_URL='{base}'" in text
    assert hashlib.sha256(archive.read_bytes()).hexdigest() in text
    syntax = subprocess.run(['sh', '-n', str(script)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    for bashism in ('[[', 'local ', 'shopt', 'BASH_SOURCE'):
        assert bashism not in text
    with tarfile.open(archive, 'r:gz') as tar:
        assert './backend/pyproject.toml' in tar.getnames()


def test_criterion_9_real_builder_archive_extracts_dot_backend_member(rig):
    tmp, _, _, fetch, _, _, run, events = rig
    _, _, out, commit, base, build = scratch_builder(tmp / 'builder')
    result = build()
    assert result.returncode == 0, result.stdout + result.stderr
    archive = out / f'vs-router-{commit}.tar.gz'
    with tarfile.open(archive, 'r:gz') as tar:
        assert './backend/packaging/install-release.sh' in tar.getnames()
    result = run(out / 'get.sh', '--hostname', 'reserve.example',
                 ARCHIVE_FIXTURE=archive,
                 ARTIFACT_URL=f'{base}/vs-router-{commit}.tar.gz')
    assert result.returncode == 0, result.stdout + result.stderr
    assert extraction_events(events())
    assert (fetch / 'wrapper/backend/packaging/install-release.sh').read_text() == WRAPPER
    assert [x for x in events() if x.startswith('ARG=')] == [
        'ARG=--release', f'ARG={commit}', 'ARG=--manifest',
        f'ARG={base}/release.json', 'ARG=--hostname', 'ARG=reserve.example']


def test_criterion_9_missing_bash_refused_before_exec(rig):
    _, _, bin_dir, _, _, _, run, events = rig
    (bin_dir / 'bash').unlink()
    result = run()
    blocked(result, events)
    assert 'bash' in result.stderr.lower()
    assert not download_events(events())


@pytest.mark.parametrize('token', TOKENS)
@pytest.mark.parametrize('change', ['missing', 'duplicate'])
def test_criterion_9_builder_rejects_bad_template(tmp_path, token, change):
    text = TEMPLATE.read_text()
    assert text.count(token) == 1
    if change == 'missing':
        text = text.replace(token, '')
    else:
        text += '\n# ' + token + '\n'
    _, _, out, _, _, build = scratch_builder(tmp_path, template=text)
    result = build()
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (out / 'get.sh').exists()


@pytest.mark.parametrize('empty', ['base', 'sha'])
def test_criterion_9_builder_rejects_empty_pins(tmp_path, empty):
    _, _, out, _, _, build = scratch_builder(tmp_path)
    overrides = {}
    if empty == 'base':
        overrides['VS_ROUTER_RELEASE_BASE_URL'] = ''
    else:
        fakebin = tmp_path / 'bin'
        fakebin.mkdir()
        fake = fakebin / 'sha256sum'
        fake.write_text('#!/bin/sh\nexit 0\n')
        fake.chmod(0o755)
        overrides['PATH'] = f'{fakebin}:{os.environ["PATH"]}'
    result = build(extra_env=overrides)
    assert result.returncode != 0, result.stdout + result.stderr
    assert ('VS_ROUTER_BASE_URL is empty' if empty == 'base' else 'sha256sum failed') in result.stderr
    assert not (out / 'get.sh').exists()


@pytest.mark.parametrize('existing', [False, True])
def test_criterion_9_uploads_third_asset_in_both_branches(tmp_path, existing):
    _, _, out, commit, _, build = scratch_builder(tmp_path)
    fakebin = tmp_path / 'bin'
    fakebin.mkdir()
    log = tmp_path / 'gh-calls'
    gh = fakebin / 'gh'
    gh.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$GH_CALLS"\n'
                  'case "$1 $2" in "release view") [ "$EXISTING" = 1 ] ;; esac\n')
    gh.chmod(0o755)
    result = build('--upload', extra_env={'PATH': f'{fakebin}:{os.environ["PATH"]}',
                                          'GH_CALLS': str(log), 'EXISTING': '1' if existing else '0'})
    assert result.returncode == 0, result.stdout + result.stderr
    calls = log.read_text().splitlines()
    action = next(x for x in calls if x.startswith('release upload ' if existing else 'release create '))
    assert str(out / 'get.sh') in action
    assert str(out / 'release.json') in action
    assert str(out / f'vs-router-{commit}.tar.gz') in action
    if existing:
        assert '--clobber' in action


def test_criterion_10_no_moving_refs_in_entry_or_builder(tmp_path):
    _, _, out, commit, base, build = scratch_builder(tmp_path)
    result = build()
    assert result.returncode == 0, result.stdout + result.stderr
    text = (out / 'get.sh').read_text()
    executable = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
    exec_lines = [line for line in executable.splitlines() if re.search(r'\bexec\b', line)]
    assert exec_lines
    for value in (*exec_lines, base, executable):
        assert 'raw.githubusercontent.com' not in value
        assert not re.search(r'\b(latest|refs/heads|main|master)\b', value, re.I)
    assert not re.search(r'^\s*git\s+(fetch|pull|checkout)\b', MAKER.read_text(), re.M)
