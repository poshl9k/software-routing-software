"""Read-only service status: RPC boundaries, agent probes, and HTTP exposure."""
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine

from vs_router.agent.apply import ApplyEngine
from vs_router.agent.daemon import dispatch, make_handlers
from vs_router.agent.rpc import EmptyParams, build_request
from vs_router.app import create_app


class FakeFiles:
    def __init__(self, manifest=None):
        self.manifest = manifest
        self.reads = []

    def read(self, path):
        self.reads.append(Path(path))
        if Path(path).name == 'manifest.json' and self.manifest is not None:
            return json.dumps(self.manifest)
        raise FileNotFoundError(path)


class FakeExecutor:
    def __init__(self, codes=None, errors=None):
        self.codes = codes or {}
        self.errors = errors or {}
        self.calls = []

    def run(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        unit = argv[-1]
        if unit in self.errors:
            raise self.errors[unit]
        return SimpleNamespace(returncode=self.codes.get(unit, 0))


def _status(engine, database):
    request = build_request('service_status', EmptyParams(), request_id='status-1')
    response = dispatch(request.model_dump_json().encode(), make_handlers(engine, database))
    assert response.error is None, response.error
    return response.result


def test_rpc_accepts_only_empty_service_status_params():
    request = build_request('service_status', EmptyParams(), request_id=7)
    assert request.params == {}
    for params in ({'unit': 'ssh.service'}, {'command': 'sh -c true'},
                   {'service': 'kea'}, {'argv': ['systemctl', 'stop', 'caddy']}):
        with pytest.raises(ValueError):
            build_request('service_status', params)


def test_fixed_services_are_probed_with_injected_executor():
    executor = FakeExecutor(codes={'unbound.service': 3, 'caddy.service': 4})
    result = _status(ApplyEngine(executor=executor, filesystem=FakeFiles()), None)
    services = {item['name']: item for item in result['services']}
    assert datetime.fromisoformat(result['generated_at']).tzinfo is not None
    assert all(set(item) == {'name', 'state', 'detail'} for item in result['services'])
    assert set(services) == {'kea', 'unbound', 'caddy', 'tproxy', 'ddns'}
    assert services['kea']['state'] == 'running'
    assert services['unbound']['state'] == 'stopped'
    assert services['caddy']['state'] == 'unknown'
    assert services['tproxy']['state'] == 'running'
    assert services['ddns']['state'] == 'unknown'
    assert executor.calls == [
        (['systemctl', 'is-active', 'kea-dhcp4-server.service'], 5),
        (['systemctl', 'is-active', 'unbound.service'], 5),
        (['systemctl', 'is-active', 'caddy.service'], 5),
        (['systemctl', 'is-active', 'vs-router-singbox.service'], 5),
    ]


def test_tunnels_come_only_from_installed_manifest():
    manifest = {
        'wg0': {'protocol': 'wg', 'file': 'wg0.conf', 'addresses': [], 'routes': []},
        'awg1': {'protocol': 'awg', 'file': 'awg1.conf', 'addresses': [], 'routes': []},
        'bad;touch /tmp/oops': {'protocol': 'wg'},
        'wg2': {'protocol': 'wg; systemctl stop caddy'},
    }
    executor = FakeExecutor(codes={'vs-router-awg@awg1.service': 3})
    result = _status(ApplyEngine(executor=executor, filesystem=FakeFiles(manifest)), None)
    services = {item['name']: item for item in result['services']}
    assert services['tunnel:wg0']['state'] == 'running'
    assert services['tunnel:awg1']['state'] == 'unknown'
    assert set(services) == {'kea', 'unbound', 'caddy', 'tproxy', 'ddns',
                             'tunnel:wg0', 'tunnel:awg1'}
    assert executor.calls[-2:] == [
        (['systemctl', 'is-active', 'vs-router-awg@awg1.service'], 5),
        (['systemctl', 'is-active', 'vs-router-wg@wg0.service'], 5),
    ]
    assert 'private_key' not in json.dumps(result)


def test_probe_error_does_not_claim_running():
    executor = FakeExecutor(errors={'caddy.service': OSError('systemd unavailable')})
    result = _status(ApplyEngine(executor=executor, filesystem=FakeFiles()), None)
    services = {item['name']: item for item in result['services']}
    assert services['caddy']['state'] == 'unknown'
    assert services['kea']['state'] == 'running'


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def api(tmp_path):
    url = f"sqlite:///{tmp_path / 'status.db'}"
    config = Config(str(Path(__file__).parents[1] / 'alembic.ini'))
    config.set_main_option('sqlalchemy.url', url)
    command.upgrade(config, 'head')
    engine = create_engine(url, connect_args={'check_same_thread': False})
    async with AsyncClient(transport=ASGITransport(app=create_app(engine)),
                           base_url='https://router.test') as client:
        yield client
    engine.dispose()


async def _sign_in(client):
    creds = {'username': 'admin', 'password': 'correct-password'}
    assert (await client.post('/api/setup', json=creds)).status_code == 201
    assert (await client.post('/api/auth/login', json=creds)).status_code == 200


@pytest.mark.anyio
async def test_http_status_requires_session_and_disables_cache(api, monkeypatch):
    from vs_router.api import status
    assert (await api.get('/api/status/services')).status_code == 401
    await _sign_in(api)
    calls = []
    payload = {'generated_at': '2026-01-01T00:00:00+00:00',
               'services': [{'name': 'kea', 'state': 'running', 'detail': None}]}
    monkeypatch.setattr(status, 'agent_call', lambda method, body:
                        calls.append((method, body.model_dump())) or payload)
    response = await api.get('/api/status/services')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == payload
    assert calls == [('service_status', {})]


@pytest.mark.anyio
async def test_http_status_reports_agent_unavailable(api, monkeypatch):
    from vs_router.api import status
    from vs_router.api.errors import APIError
    await _sign_in(api)

    def unavailable(method, body):
        assert method == 'service_status'
        raise APIError(503, 'agent.unavailable')

    monkeypatch.setattr(status, 'agent_call', unavailable)
    response = await api.get('/api/status/services')
    assert response.status_code == 503
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == {'code': 'agent.unavailable',
                               'message': 'agent.unavailable', 'details': []}


@pytest.mark.anyio
async def test_missing_agent_socket_returns_503(api, monkeypatch, tmp_path):
    await _sign_in(api)
    monkeypatch.setenv('VS_ROUTER_AGENT_SOCKET', str(tmp_path / 'missing.sock'))
    response = await api.get('/api/status/services')
    assert response.status_code == 503
    assert response.headers['cache-control'] == 'no-store'
    assert response.json()['code'] == 'agent.unavailable'
