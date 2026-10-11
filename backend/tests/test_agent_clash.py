import io
import json
from urllib.error import URLError

import pytest

from vs_router.agent.apply import ApplyError
from vs_router.agent.clash import ClashClient


class Response:
    def __init__(self, payload=b'', status=200):
        self.stream = io.BytesIO(payload)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, size):
        return self.stream.read(size)

    def readline(self, size):
        return self.stream.readline(size)


class Transport:
    def __init__(self, payload=b'{}', status=200):
        self.payload = payload
        self.status = status
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((request, timeout))
        return Response(self.payload, self.status)


def test_status_and_proxy_operations():
    transport = Transport(json.dumps({'server': 'hidden.example', 'version': '1'}).encode())
    client = ClashClient(transport, port=9191)
    assert client.version() == {'server': '[redacted]', 'version': '1'}
    assert client.connections()['server'] == '[redacted]'
    assert client.proxies()['version'] == '1'
    client.close_connection('id/1')
    client.select_proxy('group one', 'node')
    client.proxy_delay('node', 'https://example.com/test', 500)
    assert [call[0].get_method() for call in transport.calls] == [
        'GET', 'GET', 'GET', 'DELETE', 'PUT', 'GET']
    assert all(call[0].full_url.startswith('http://127.0.0.1:9191/') for call in transport.calls)
    assert '/connections/id%2F1' in transport.calls[3][0].full_url
    assert transport.calls[4][0].data == b'{"name": "node"}'
    assert 'url=https%3A%2F%2Fexample.com%2Ftest' in transport.calls[5][0].full_url


@pytest.mark.parametrize('transport', [
    lambda *_, **__: (_ for _ in ()).throw(URLError('secret endpoint')),
    Transport(status=503), Transport(b'x' * (1024 * 1024 + 1)), Transport(b'{broken'),
])
def test_failures_have_stable_code(transport):
    with pytest.raises(ApplyError) as error:
        ClashClient(transport).version()
    assert error.value.code == 'clash.unavailable'
    assert 'secret' not in str(error.value)


@pytest.mark.parametrize('url', [
    'http://127.0.0.1/', 'http://10.0.0.1/', 'http://[::1]/',
    'http://localhost/', 'http://service.local/', 'http://user@example.com/',
    'file:///etc/passwd', 'https://example.com/#fragment', 'http://1234/',
    'https://untrusted.example.org/check',
])
def test_delay_rejects_unsafe_urls(url):
    transport = Transport()
    with pytest.raises(ApplyError, match='clash.invalid_input'):
        ClashClient(transport).proxy_delay('node', url, 100)
    assert not transport.calls


def test_logs_stop_at_limit_and_deadline():
    transport = Transport(b'{"type":"info","server":"remote.example"}\n' * 10)
    client = ClashClient(transport)
    assert client.logs(limit=2) == [
        {'type': 'info', 'server': '[redacted]'}] * 2
    ticks = iter([0, 0, 6])
    assert ClashClient(transport, clock=lambda: next(ticks)).logs(limit=10) == [
        {'type': 'info', 'server': '[redacted]'}]
    assert transport.calls[0][1] == 5


def test_logs_redact_embedded_credentials():
    payload = b'{"type":"info","payload":"password=hunter2 https://user:pass@example.com/x","token":"abc"}\n'
    assert ClashClient(Transport(payload)).logs(limit=1) == [
        {'type': 'info', 'payload': '[redacted] [redacted]', 'token': '[redacted]'}]


def test_logs_bound_line_and_invalid_inputs():
    with pytest.raises(ApplyError, match='clash.unavailable'):
        ClashClient(Transport(b'x' * 20000)).logs()
    client = ClashClient(Transport())
    for action in (lambda: client.logs(limit=0), lambda: client.logs(level='trace'),
                   lambda: client.select_proxy('group', ''),
                   lambda: client.proxy_delay('node', 'https://example.com', 0)):
        with pytest.raises(ApplyError, match='clash.invalid_input'):
            action()
