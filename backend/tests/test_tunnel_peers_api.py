"""Saving the draft programs a running server tunnel's peers, without an apply."""
import base64

import pytest
from cryptography.fernet import Fernet

from test_api import api, sign_in  # noqa: F401  (fixtures used by name)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


KEY = base64.b64encode(b't' * 32).decode()
PEER = base64.b64encode(b'q' * 32).decode()


def tunnel_config(peers=None):
    return {
        'interfaces': [{'name': 'tun0', 'type': 'physical', 'zone': 'lan',
                        'addressing': 'static', 'addresses': ['10.66.66.1/24']}],
        'tunnels': [{'name': 'vpn', 'interface': 'tun0', 'role': 'server', 'protocol': 'wg',
                     'private_key': {'plaintext': KEY}, 'listen_port': 51820,
                     'peers': [{'name': 'phone', 'public_key': PEER,
                                'allowed_ips': ['10.66.66.2/32']}] if peers is None else peers}],
    }


def only_agent(monkeypatch, result=None, failure=None):
    """Capture agent RPC calls made by the draft endpoints."""
    calls = []

    def call(method, body):
        calls.append((method, body))
        if failure is not None:
            raise failure
        return result if result is not None else {'added': [], 'removed': [], 'unchanged': []}
    monkeypatch.setattr('vs_router.api.versions.agent_call', call)
    return calls


async def test_saving_the_draft_programs_the_peers_on_the_running_tunnel(api, monkeypatch):
    client = api[0]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    calls = only_agent(monkeypatch, {'added': [PEER], 'removed': [], 'unchanged': []})
    await sign_in(client)
    assert (await client.post('/api/draft', json={})).status_code == 201
    response = await client.put('/api/draft', json=tunnel_config())
    assert response.status_code == 200, response.text
    assert calls == [('tunnel_peers_sync', {
        'interface': 'tun0',
        'peers': [{'public_key': PEER, 'allowed_ips': ['10.66.66.2/32'],
                   'preshared_key': None}]})]
    # The version payload stays exactly the stored configuration.
    assert 'live_peers' not in response.json()


async def test_an_unchanged_peer_set_does_not_touch_the_agent(api, monkeypatch):
    client = api[0]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    await sign_in(client)
    await client.post('/api/draft', json=tunnel_config())
    calls = only_agent(monkeypatch)
    assert (await client.put('/api/draft', json={'panel_port': 8443})).status_code == 200
    assert calls == []


async def test_a_tunnel_that_is_not_applied_still_saves(api, monkeypatch):
    from vs_router.api.errors import APIError

    client = api[0]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    calls = only_agent(monkeypatch, failure=APIError(409, 'tunnel.not_applied'))
    await sign_in(client)
    assert (await client.post('/api/draft', json={})).status_code == 201
    response = await client.put('/api/draft', json=tunnel_config())
    # A tunnel that is not applied yet: the agent refuses, the save still lands.
    assert response.status_code == 200, response.text
    assert calls == [('tunnel_peers_sync', {'interface': 'tun0', 'peers': [
        {'public_key': PEER, 'allowed_ips': ['10.66.66.2/32'], 'preshared_key': None}]})]


async def test_an_unusable_peer_never_programs_a_partial_set(api, monkeypatch):
    """A hand-typed key must not make the sync deprogram the peers it does know."""
    client = api[0]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    await sign_in(client)
    calls = only_agent(monkeypatch)
    typed = tunnel_config(peers=[{'name': 'phone', 'public_key': 'as-typed-by-hand',
                                  'allowed_ips': ['10.66.66.2/32']}])
    response = await client.post('/api/draft', json=typed)
    assert response.status_code == 201, response.text
    assert calls == []


async def test_removing_every_peer_clears_the_running_device(api, monkeypatch):
    client = api[0]
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    await sign_in(client)
    await client.post('/api/draft', json=tunnel_config())
    calls = only_agent(monkeypatch, {'added': [], 'removed': [PEER], 'unchanged': []})
    assert (await client.put('/api/draft', json=tunnel_config(peers=[]))).status_code == 200
    assert calls == [('tunnel_peers_sync', {'interface': 'tun0', 'peers': []})]
