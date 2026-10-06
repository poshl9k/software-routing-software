"""Online release update: read-only status and a privileged apply (ADR-0010).

The panel never mutates the host itself. `status` fetches the host-configured
release manifest and compares it with the recorded installed release (read-only).
`apply_update` verifies the requested commit against that manifest and starts a
detached `systemd-run` unit wrapping `backend/packaging/update-run.sh`, so the
request cannot install arbitrary code and never blocks the agent's RPC loop.

The manifest URL is host-owned configuration (`/etc/vs-router/update.json`, or
`$VS_ROUTER_UPDATE_MANIFEST_URL`), never a panel-supplied value.
"""
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path
from typing import Callable

from .apply import ApplyError
from ..api.release import read_release

CONFIG_FILE = Path(os.environ.get('VS_ROUTER_UPDATE_CONFIG', '/etc/vs-router/update.json'))
STATE_FILE = Path(os.environ.get('VS_ROUTER_UPDATE_STATE', '/run/vs-router/update-state.json'))
REPO_ROOT = Path(os.environ.get('VS_ROUTER_REPO_ROOT', '/opt/vs-router'))
UNIT = 'vs-router-update.service'
MANIFEST_TIMEOUT = 10

COMMIT = re.compile(r'^[0-9a-f]{40}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')


def read_config(path=None) -> dict:
    """Host-owned update configuration; always returns a dict-shaped result."""
    manifest_url = os.environ.get('VS_ROUTER_UPDATE_MANIFEST_URL')
    if not manifest_url:
        try:
            data = json.loads(Path(CONFIG_FILE if path is None else path).read_text())
            candidate = data.get('manifest_url') if isinstance(data, dict) else None
            manifest_url = candidate if isinstance(candidate, str) else None
        except (OSError, ValueError):
            manifest_url = None
    return {'manifest_url': manifest_url or None}


def _default_opener(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (https enforced)
        return response.read().decode('utf-8')


def fetch_manifest(url: str, opener: Callable[[str, int], str] | None = None,
                   timeout: int = MANIFEST_TIMEOUT) -> dict:
    """Download and validate a release manifest; https-only, fail-closed."""
    if not isinstance(url, str) or not url.startswith('https://'):
        raise ApplyError('update.manifest_invalid')
    opener = _default_opener if opener is None else opener
    try:
        payload = opener(url, timeout)
        data = json.loads(payload)
    except ApplyError:
        raise
    except Exception:
        raise ApplyError('update.manifest_unavailable') from None
    if not isinstance(data, dict):
        raise ApplyError('update.manifest_invalid')
    commit, semver = data.get('commit'), data.get('semver')
    source_url, source_sha256 = data.get('source_url'), data.get('source_sha256')
    if not (isinstance(commit, str) and COMMIT.fullmatch(commit)):
        raise ApplyError('update.manifest_invalid')
    if not (isinstance(source_url, str) and source_url.startswith('https://')):
        raise ApplyError('update.manifest_invalid')
    if not (isinstance(source_sha256, str) and SHA256.fullmatch(source_sha256)):
        raise ApplyError('update.manifest_invalid')
    return {
        'commit': commit,
        'semver': semver if isinstance(semver, str) else 'unknown',
        'source_url': source_url,
        'source_sha256': source_sha256,
    }


def read_state(path=None) -> dict | None:
    """Outcome of the last detached update, written by update-run.sh."""
    try:
        data = json.loads(Path(STATE_FILE if path is None else path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get('status') not in ('running', 'success', 'failed'):
        return None
    return {
        'status': data['status'],
        'release': data.get('release') if isinstance(data.get('release'), str) else None,
        'started_at': data.get('started_at') if isinstance(data.get('started_at'), str) else None,
        'finished_at': data.get('finished_at') if isinstance(data.get('finished_at'), str) else None,
        'exit_code': data.get('exit_code') if isinstance(data.get('exit_code'), int) else None,
    }


def unit_is_active() -> bool:
    """Whether the detached update unit is currently running."""
    try:
        result = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], timeout=5)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def release_status(config_path=None, state_path=None, *, opener=None,
                   unit_active: bool | None = None) -> dict:
    """Read-only comparison of the installed release with the published one."""
    manifest_url = read_config(config_path)['manifest_url']
    current = read_release()
    status = {
        'configured': bool(manifest_url),
        'manifest_url': manifest_url,
        'current': current,
        'available': None,
        'update_available': False,
        'running': unit_is_active() if unit_active is None else unit_active,
        'last': read_state(state_path),
        'error': None,
    }
    if not manifest_url:
        return status
    try:
        manifest = fetch_manifest(manifest_url, opener=opener)
    except ApplyError as exc:
        status['error'] = exc.code
        return status
    status['available'] = {'commit': manifest['commit'], 'semver': manifest['semver']}
    status['update_available'] = manifest['commit'] != current['commit']
    return status


def _spawn(release: str, manifest_url: str) -> None:
    """Start the detached updater; never block the RPC loop on the build."""
    script = str(REPO_ROOT / 'backend/packaging/update-run.sh')
    args = ['/bin/bash', script, '--release', release, '--manifest-url', manifest_url]
    systemd_run = ['systemd-run', f'--unit={UNIT.removesuffix(".service")}', '--collect', '--']
    try:
        subprocess.run([*systemd_run, *args], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        # Fallback for a host without systemd-run: detach a session of our own.
        subprocess.Popen(args, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def apply_update(release: str, *, opener=None, unit_active: bool | None = None,
                 spawn: Callable[[str, str], None] | None = None) -> dict:
    """Verify the requested commit against the manifest, then start the update."""
    if not isinstance(release, str) or not COMMIT.fullmatch(release):
        raise ApplyError('update.invalid_release')
    manifest_url = read_config()['manifest_url']
    if not manifest_url:
        raise ApplyError('update.not_configured')
    running = unit_is_active() if unit_active is None else unit_active
    if running:
        raise ApplyError('update.already_running')
    manifest = fetch_manifest(manifest_url, opener=opener)
    if manifest['commit'] != release:
        raise ApplyError('update.release_mismatch')
    (spawn or _spawn)(release, manifest_url)
    return {'started': True, 'release': release}
