"""Read-only identity of the installed release.

Distinct from configuration versions (`/api/versions`): this describes the
product build (pinned commit + semantic version) recorded at install time, so
the panel can compare the running release against a published one before
offering an online update. Never mutates anything.
"""
import json
import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from .auth import current_user

router = APIRouter(dependencies=[Depends(current_user)])

VERSION_FILE = Path(os.environ.get('VS_ROUTER_VERSION_FILE', '/etc/vs-router/version.json'))
COMMIT = re.compile(r'^[0-9a-f]{40}$')
SEMVER = re.compile(r'^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')
SOURCES = ('iso', 'online', 'unknown')
UNKNOWN = {'commit': None, 'semver': None, 'installed_at': None, 'source': 'unknown'}


def read_release(path=None) -> dict:
    """Parse the recorded release; a missing or malformed file is 'unknown'."""
    path = VERSION_FILE if path is None else path
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return dict(UNKNOWN)
    if not isinstance(data, dict):
        return dict(UNKNOWN)
    commit = data.get('commit')
    semver = data.get('semver')
    installed_at = data.get('installed_at')
    source = data.get('source')
    return {
        'commit': commit if isinstance(commit, str) and COMMIT.fullmatch(commit) else None,
        'semver': semver if isinstance(semver, str) and SEMVER.fullmatch(semver) else None,
        'installed_at': installed_at if isinstance(installed_at, str) else None,
        'source': source if source in SOURCES else 'unknown',
    }


@router.get('/release')
def release() -> dict:
    return read_release()
