"""Release identity: distinct from configuration versions, read-only."""
import json
import re
from pathlib import Path

import pytest

from vs_router.api import release as release_module
from vs_router.api.release import read_release
from test_api import api, sign_in

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


COMMIT = 'c574b4c14917405809eb4f6ac6e89d1676edc9a3'
UNKNOWN = {'commit': None, 'semver': None, 'installed_at': None,
           'source': 'unknown'}


def test_reads_a_recorded_release(tmp_path):
    path = tmp_path / 'version.json'
    path.write_text(json.dumps({'commit': COMMIT, 'semver': '0.1.0',
                                'installed_at': '2026-10-05T21:00:00Z',
                                'source': 'iso'}))
    assert read_release(path) == {'commit': COMMIT, 'semver': '0.1.0',
                                  'installed_at': '2026-10-05T21:00:00Z',
                                  'source': 'iso'}


@pytest.mark.parametrize('content', [None, '', 'not json', '[]', '{}'])
def test_missing_or_malformed_is_unknown(tmp_path, content):
    path = tmp_path / 'version.json'
    if content is not None:
        path.write_text(content)
    assert read_release(path) == UNKNOWN


@pytest.mark.parametrize('commit,semver,source', [
    ('not-a-commit', '0.1.0', 'iso'),
    (COMMIT, 'v0.1.0', 'iso'),
    (COMMIT, '0.1.0', 'tarball'),
    # Recorded by the installers, so they must survive the read.
    (COMMIT, '0.1.0', 'git'),
    (COMMIT, '0.1.0', 'wheel'),
])
def test_invalid_fields_become_null(tmp_path, commit, semver, source):
    path = tmp_path / 'version.json'
    path.write_text(json.dumps({'commit': commit, 'semver': semver,
                                'installed_at': '2026-01-01T00:00:00Z',
                                'source': source}))
    result = read_release(path)
    assert result['commit'] == (commit if commit == COMMIT else None)
    assert result['semver'] == (semver if semver == '0.1.0' else None)
    assert result['source'] == (source if source in release_module.SOURCES else 'unknown')


def test_every_source_the_installers_write_is_accepted():
    """The API must not turn a recorded fact into 'unknown' (found on the panel).

    A wheel install wrote source=wheel, the endpoint answered 'unknown', and the
    panel lost the only honest answer to "how was this host installed".
    """
    packaging = Path(__file__).resolve().parents[1] / 'packaging'
    written = set()
    for name in ('install.sh', 'bootstrap.sh', 'update.sh', 'online-install.sh'):
        text = (packaging / name).read_text(encoding='utf-8')
        written |= set(re.findall(r'VS_ROUTER_RELEASE_SOURCE=([A-Za-z0-9_-]+)', text))
        written |= set(re.findall(r'source=([a-z]+)\n', text))
    assert written, 'no source literals found: the check would be vacuous'
    assert 'git' in written and 'wheel' in written  # the ones the panel reported wrong
    missing = written - set(release_module.SOURCES)
    assert not missing, f'the installers record sources the API rejects: {sorted(missing)}'


async def test_release_endpoint_requires_auth(api, tmp_path, monkeypatch):
    client, _, _ = api
    assert (await client.get('/api/release')).status_code == 401
    await sign_in(client)
    path = tmp_path / 'release.json'
    path.write_text(json.dumps({'commit': COMMIT, 'semver': '0.1.0',
                                'installed_at': '2026-10-05T21:00:00Z',
                                'source': 'online'}))
    monkeypatch.setattr(release_module, 'VERSION_FILE', path)
    response = await client.get('/api/release')
    assert response.status_code == 200
    assert response.json() == {'commit': COMMIT, 'semver': '0.1.0',
                               'installed_at': '2026-10-05T21:00:00Z',
                               'source': 'online'}
