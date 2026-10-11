import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from vs_router.app import create_app
from vs_router.db import Base
from vs_router.api.auth import current_user
from vs_router.api.errors import APIError
from vs_router.api import runtime


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.mark.anyio
async def test_runtime_routes_auth_validation_no_store(monkeypatch):
    db = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(db)
    app = create_app(db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://router.test') as client:
        assert (await client.get('/api/runtime/engine')).status_code == 401
        app.dependency_overrides[current_user] = lambda: object()
        calls = []
        def agent_call(method, params):
            calls.append((method, params.model_dump()))
            return {'ok': True}
        monkeypatch.setattr(runtime, 'agent_call', agent_call)
        routes = [('get', '/api/runtime/engine', None, 'engine_status', {}),
                  ('post', '/api/runtime/engine/restart', None, 'engine_control', {'action': 'restart'}),
                  ('get', '/api/runtime/connections', None, 'clash_connections', {}),
                  ('post', '/api/runtime/connections/abc/close', None, 'clash_close', {'id': 'abc'}),
                  ('get', '/api/runtime/logs?level=warning&limit=3', None, 'clash_logs',
                   {'level': 'warning', 'limit': 3}),
                  ('get', '/api/runtime/proxies', None, 'clash_proxies', {}),
                  ('post', '/api/runtime/proxies/group/select', {'name': 'node'}, 'clash_select',
                   {'group': 'group', 'name': 'node'}),
                  ('get', '/api/runtime/proxies/node/delay?url=https%3A%2F%2Fexample.com%2F204&timeout_ms=3000',
                   None, 'clash_delay', {'tag': 'node', 'url': 'https://example.com/204', 'timeout_ms': 3000})]
        for verb, path, body, method, params in routes:
            response = await getattr(client, verb)(path, json=body) if body else await getattr(client, verb)(path)
            assert response.status_code == 200, (path, response.text)
            assert response.headers['cache-control'] == 'no-store'
            assert calls[-1] == (method, params)
        count = len(calls)
        assert (await client.post('/api/runtime/engine/install')).status_code == 422
        assert (await client.post('/api/runtime/connections/../close')).status_code != 200
        invalid = await client.get('/api/runtime/logs?limit=9999')
        assert invalid.status_code == 422
        assert invalid.headers['cache-control'] == 'no-store'
        assert len(calls) == count
        def unavailable(method, params):
            raise APIError(409, 'clash.unavailable')
        monkeypatch.setattr(runtime, 'agent_call', unavailable)
        failed = await client.get('/api/runtime/connections')
        assert failed.status_code == 503
        assert failed.headers['cache-control'] == 'no-store'
        assert failed.json()['code'] == 'clash.unavailable'
    db.dispose()
