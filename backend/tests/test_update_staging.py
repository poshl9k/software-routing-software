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
