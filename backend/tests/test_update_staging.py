"""Drives update.sh's staged-release path with a stub fetch() and a synthetic
artifact, without root, network or systemd."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / 'backend/packaging'


def bash(code):
    return subprocess.run(['bash', '-c', code], text=True, capture_output=True, timeout=30)


def _build_artifact(tmp_path, commit, *, revision=None, unsafe=False, name='artifact.tar.gz'):
    """A minimal vs-router-shaped release tar.gz (tree + REVISION)."""
    members = {
        'REVISION': (revision if revision is not None else commit) + '\n',
        'backend/pyproject.toml': '[project]\nversion = "9.9.9"\n',
        'backend/packaging/install.sh': '#!/bin/sh\ntrue\n',
        'backend/packaging/update.sh': '#!/bin/sh\necho STAGED_OK\n',
        'frontend/index.html': '<!doctype html>\n',
    }
    artifact = tmp_path / name
    with tarfile.open(artifact, 'w:gz') as tar:
        for path, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if unsafe:
            info = tarfile.TarInfo('../evil')
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / 'release.json'
    manifest.write_text(json.dumps({
        'commit': commit,
        'semver': '9.9.9',
        'source_url': 'https://example.invalid/vs-router-test.tar.gz',
        'source_sha256': sha,
        'min_os': 'debian-13',
    }))
    return artifact, manifest, sha


def _stage(tmp_path, artifact, manifest, *, repo=None):
    current = repo or (tmp_path / 'current')
    current.mkdir(parents=True, exist_ok=True)
    marker = current / 'previous-tree.txt'
    if not marker.exists():
        marker.write_text('old tree\n')
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
REPO_ROOT="{current}"
MANIFEST="https://example.invalid/release.json"
SKIP_BUILD=0
fetch() {{ case "$1" in *release.json) cp "{manifest}" "$2";; *) cp "{artifact}" "$2";; esac; }}
stage_release
'''
    return current, bash(code)


def test_stage_release_swaps_in_the_verified_tree(tmp_path):
    """A correct artifact is extracted, REVISION-checked and swapped in, and the
    previous tree is kept for rollback (ADR-0010)."""
    commit = 'a' * 40
    artifact, manifest, _ = _build_artifact(tmp_path, commit)
    current, result = _stage(tmp_path, artifact, manifest)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'STAGED_OK' in result.stdout  # re-exec into the new tree's update.sh
    assert (current / 'REVISION').read_text().strip() == commit
    assert (current / 'backend/packaging/update.sh').exists()
    prev = tmp_path / 'current.prev'
    assert prev.is_dir() and (prev / 'previous-tree.txt').read_text() == 'old tree\n'


def test_stage_release_rejects_a_tampered_artifact(tmp_path):
    """A SHA-256 mismatch aborts before the running tree is touched."""
    commit = 'b' * 40
    artifact, manifest, _ = _build_artifact(tmp_path, commit)
    data = json.loads(manifest.read_text())
    data['source_sha256'] = 'c' * 64  # not the artifact's real digest
    manifest.write_text(json.dumps(data))
    current, result = _stage(tmp_path, artifact, manifest)
    assert result.returncode != 0
    assert 'SHA-256 does not match' in result.stdout + result.stderr
    assert (current / 'previous-tree.txt').exists()  # tree untouched
    assert not (tmp_path / 'current.prev').exists()


def test_stage_release_rejects_a_revision_mismatch(tmp_path):
    """The REVISION inside the archive must equal the manifest commit."""
    commit = 'd' * 40
    artifact, manifest, sha = _build_artifact(tmp_path, commit, revision='e' * 40)
    data = json.loads(manifest.read_text())
    data['source_sha256'] = sha  # digest is valid; only REVISION disagrees
    manifest.write_text(json.dumps(data))
    current, result = _stage(tmp_path, artifact, manifest)
    assert result.returncode != 0
    assert 'does not match manifest commit' in result.stdout + result.stderr
    assert (current / 'previous-tree.txt').exists()


def test_stage_release_rejects_unsafe_paths(tmp_path):
    commit = 'f' * 40
    artifact, manifest, _ = _build_artifact(tmp_path, commit, unsafe=True)
    current, result = _stage(tmp_path, artifact, manifest)
    assert result.returncode != 0
    assert 'unsafe paths' in result.stdout + result.stderr
    assert (current / 'previous-tree.txt').exists()


def test_stage_release_requires_https_manifest(tmp_path):
    commit = '1' * 40
    artifact, manifest, _ = _build_artifact(tmp_path, commit)
    current = tmp_path / 'current'
    current.mkdir()
    (current / 'previous-tree.txt').write_text('old tree\n')
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
REPO_ROOT="{current}"
MANIFEST="http://example.invalid/release.json"
SKIP_BUILD=0
fetch() {{ cp "{manifest}" "$2"; }}
stage_release
'''
    result = bash(code)
    assert result.returncode != 0
    assert 'must be https' in result.stdout + result.stderr


def _profile(tmp_path, marker_text=None, *, env=None, marker='marker'):
    """Source update.sh and resolve the profile the way main() does."""
    path = tmp_path / marker
    if marker_text is not None:
        path.write_text(marker_text)
    prefix = ''.join(f'export {key}={value}\n' for key, value in (env or {}).items())
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
VS_ROUTER_PROFILE_MARKER="{path}"
{prefix}resolve_profile
printf 'profile=[%s]' "$VS_ROUTER_PROFILE"
'''
    return bash(code)


def test_update_carries_the_hosts_profile_into_install(tmp_path):
    """An update must not relabel the host (ADR-0026).

    install.sh derives the profile from VS_ROUTER_PROFILE and writes the marker,
    so an update that passed nothing would turn a panel into a router and its own
    stored documents would then fail the profile check at the next apply.
    """
    result = _profile(tmp_path, 'panel\n')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'profile=[panel]' in result.stdout
    # Exported, not merely set: install.sh is a child process.
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
VS_ROUTER_PROFILE_MARKER="{tmp_path / 'marker'}"
resolve_profile
bash -c 'printf "child=[%s]" "${{VS_ROUTER_PROFILE:-unset}}"'
'''
    child = bash(code)
    assert child.returncode == 0, child.stdout + child.stderr
    assert 'child=[panel]' in child.stdout


def test_update_keeps_the_router_profile(tmp_path):
    result = _profile(tmp_path, 'router')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'profile=[router]' in result.stdout


def test_update_without_a_marker_leaves_the_decision_to_install(tmp_path):
    """No marker: nothing is claimed, and install.sh's own default still stands."""
    result = _profile(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'profile=[]' in result.stdout
    install = (PACKAGING / 'install.sh').read_text()
    assert 'PROFILE=${VS_ROUTER_PROFILE:-router}' in install


def test_an_empty_marker_is_a_warning_not_a_silent_router(tmp_path):
    result = _profile(tmp_path, '  \n')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'profile=[]' in result.stdout
    assert 'is empty' in result.stderr


def test_a_marker_that_is_not_a_profile_stops_the_update(tmp_path):
    """Guessing here would write a wrong identity; refuse instead."""
    result = _profile(tmp_path, 'router\npanel\n')
    assert result.returncode != 0
    assert 'not a known profile' in result.stderr
    assert 'profile=[' not in result.stdout


def test_an_explicit_profile_wins_over_the_marker(tmp_path):
    result = _profile(tmp_path, 'panel\n', env={'VS_ROUTER_PROFILE': 'router'})
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'profile=[router]' in result.stdout


# --- post-update verification and rollback (ADR-0021) ----------------------
def _fake_bin(tmp_path, *, curl_code='200', active=0,
              ss_output='LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*'):
    """A PATH with fake curl/systemctl/ss: the probes must not touch the host."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    for name, body in {
        'curl': f'#!/bin/sh\nprintf %s {curl_code}\n',
        'systemctl': f'#!/bin/sh\n[ "$1" = is-active ] && exit {active}\nexit 0\n',
        'ss': f'#!/bin/sh\nprintf %s\\n "{ss_output}"\n',
    }.items():
        path = bin_dir / name
        path.write_text(body)
        path.chmod(0o755)
    return bin_dir


def _web_socket(tmp_path):
    """A real listening UNIX socket: the probe checks that the socket exists."""
    import socket
    import sys
    import time

    path = tmp_path / 'web.sock'
    code = f'import socket,time; s=socket.socket(socket.AF_UNIX); s.bind("{path}"); time.sleep(60)'
    holder = subprocess.Popen([sys.executable, '-c', code])
    for _ in range(100):
        if path.exists():
            break
        time.sleep(0.02)
    assert path.exists(), 'the fake web socket was not created'
    return path, holder


def _probe(tmp_path, bin_dir, *, socket_path, body):
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
export PATH="{bin_dir}:$PATH"
VS_ROUTER_WEB_SOCKET="{socket_path}"
{body}
'''
    return bash(code)


def test_the_panel_probe_asks_the_web_app_itself(tmp_path):
    """A healthy panel answers /health on its own socket."""
    socket_path, holder = _web_socket(tmp_path)
    try:
        ok = _probe(tmp_path, _fake_bin(tmp_path, curl_code='200'), socket_path=socket_path,
                    body='panel_answers && echo PANEL_OK || echo PANEL_DOWN')
        assert 'PANEL_OK' in ok.stdout, ok.stdout + ok.stderr

        bad = _probe(tmp_path, _fake_bin(tmp_path, curl_code='503', ss_output='x'),
                     socket_path=socket_path,
                     body='panel_answers && echo PANEL_OK || echo PANEL_DOWN')
        assert 'PANEL_DOWN' in bad.stdout, bad.stdout + bad.stderr
    finally:
        holder.terminate()


def test_a_missing_web_socket_is_not_a_working_panel(tmp_path):
    result = _probe(tmp_path, _fake_bin(tmp_path), socket_path=tmp_path / 'absent.sock',
                    body='panel_answers && echo PANEL_OK || echo PANEL_DOWN')
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PANEL_DOWN' in result.stdout


def test_the_ssh_probe_needs_a_running_unit_and_a_listening_port(tmp_path):
    socket_path, holder = _web_socket(tmp_path)
    try:
        up = _probe(tmp_path, _fake_bin(tmp_path, active=0), socket_path=socket_path,
                    body='ssh_answers && echo SSH_OK || echo SSH_DOWN')
        assert 'SSH_OK' in up.stdout, up.stdout + up.stderr

        unit_dead = _probe(tmp_path, _fake_bin(tmp_path, active=1), socket_path=socket_path,
                           body='ssh_answers && echo SSH_OK || echo SSH_DOWN')
        assert 'SSH_DOWN' in unit_dead.stdout, unit_dead.stdout + unit_dead.stderr

        # The unit is up but nothing listens on the port: that is a lockout too.
        no_port = _probe(tmp_path, _fake_bin(tmp_path, ss_output='LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*'),
                         socket_path=socket_path,
                         body='ssh_answers && echo SSH_OK || echo SSH_DOWN')
        assert 'SSH_DOWN' in no_port.stdout, no_port.stdout + no_port.stderr
    finally:
        holder.terminate()


def test_verification_fails_when_either_way_in_is_gone(tmp_path):
    socket_path, holder = _web_socket(tmp_path)
    try:
        healthy = _probe(tmp_path, _fake_bin(tmp_path), socket_path=socket_path,
                         body='PROBE_ATTEMPTS=1 PROBE_INTERVAL=0\nverify_update && echo VERIFIED || echo UNVERIFIED')
        assert 'VERIFIED' in healthy.stdout, healthy.stdout + healthy.stderr

        broken = _probe(tmp_path, _fake_bin(tmp_path, curl_code='000'), socket_path=socket_path,
                        body='PROBE_ATTEMPTS=1 PROBE_INTERVAL=0\nverify_update && echo VERIFIED || echo UNVERIFIED')
        assert 'UNVERIFIED' in broken.stdout, broken.stdout + broken.stderr
    finally:
        holder.terminate()


def test_rollback_restores_the_previous_tree_and_runs_its_installer(tmp_path):
    """The tree update.sh kept at .prev goes back, and its installer deploys it."""
    bin_dir = _fake_bin(tmp_path)
    current = tmp_path / 'tree'
    previous = tmp_path / 'tree.prev'
    current.mkdir()
    (current / 'state.txt').write_text('new release\n')
    (previous / 'backend/packaging').mkdir(parents=True)
    (previous / 'state.txt').write_text('previous release\n')
    # No wheel and no backend/dist in the previous tree: the rollback then warns
    # instead of reinstalling a Python package it does not have.
    (previous / 'backend/packaging/install.sh').write_text('#!/bin/sh\necho PREV_INSTALL_RAN\n')

    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
export PATH="{bin_dir}:$PATH"
REPO_ROOT="{current}"
rollback_update
'''
    result = bash(code)
    assert result.returncode == 0, result.stdout + result.stderr
    # The previous tree is live again, with its own installer having run...
    assert (current / 'state.txt').read_text() == 'previous release\n'
    assert 'PREV_INSTALL_RAN' in result.stdout + result.stderr
    # ...and the tree that failed is kept, not deleted.
    assert (tmp_path / 'tree.broken' / 'state.txt').read_text() == 'new release\n'
    assert not previous.exists()


def test_rollback_without_a_previous_tree_reports_instead_of_guessing(tmp_path):
    bin_dir = _fake_bin(tmp_path)
    current = tmp_path / 'tree'
    current.mkdir()
    (current / 'state.txt').write_text('only tree\n')
    code = f'''set -euo pipefail
source "{PACKAGING}/update.sh"
export PATH="{bin_dir}:$PATH"
REPO_ROOT="{current}"
rollback_update && echo ROLLED_BACK || echo NOTHING_TO_ROLL_BACK
'''
    result = bash(code)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'NOTHING_TO_ROLL_BACK' in result.stdout
    assert (current / 'state.txt').read_text() == 'only tree\n'
