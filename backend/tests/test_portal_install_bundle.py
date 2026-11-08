"""Panel releases must include and install the subscriber portal UI."""
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from vs_portal.app import create_app
from vs_portal.models import Base, make_engine

PACKAGING = Path(__file__).parents[1] / 'packaging'


def test_panel_installer_deploys_portal_ui_before_service_start():
    script = (PACKAGING / 'install.sh').read_text()
    assert 'frontend-portal/dist' in script
    assert '/var/lib/vs-router/portal/ui' in script
    assert script.index('frontend-portal/dist') < script.index('systemctl restart vs-router-portal.service')


def test_release_build_and_install_keep_portal_ui():
    for name in ('make-release.sh', 'install-release.sh', 'update.sh', 'online-install.sh'):
        assert 'frontend-portal/dist' in (PACKAGING / name).read_text(), name


@pytest.mark.anyio
async def test_portal_serves_installed_shell_and_invite_route(tmp_path, monkeypatch):
    ui = tmp_path / 'ui'
    (ui / 'assets').mkdir(parents=True)
    (ui / 'index.html').write_text('<!doctype html><title>Portal</title>')
    (ui / 'assets' / 'app.js').write_text('console.log("portal")')
    monkeypatch.setenv('VS_PORTAL_STATIC_DIR', str(ui))
    engine = make_engine(f'sqlite:///{tmp_path / "portal.db"}')
    Base.metadata.create_all(engine)
    try:
        async with AsyncClient(transport=ASGITransport(app=create_app(engine)),
                               base_url='https://portal.test') as client:
            for path in ('/', '/invite/test-token'):
                response = await client.get(path)
                assert response.status_code == 200
                assert '<title>Portal</title>' in response.text
            assert (await client.get('/assets/app.js')).status_code == 200
            assert (await client.get('/health')).json() == {'status': 'ok'}
    finally:
        engine.dispose()
