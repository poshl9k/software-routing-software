"""Tunnel endpoints must resolve even when the host has no resolver.

A router whose management link carries no DHCP ends up with an empty
/etc/resolv.conf. Endpoint names were resolved with the host resolver only, so
every tunnel apply failed with ``wireguard.endpoint_unresolved`` on a host that
is otherwise perfectly configured — the panel knows which resolvers it trusts,
and asking them is the honest fallback.
"""
from __future__ import annotations

import socket
import struct
import threading

import pytest

from vs_router.agent import services
from vs_router.schema import Configuration

Reloader = services.WireGuardReloader


def _answer(host, address, qtype=1):
    """A minimal DNS response carrying one record of ``qtype``."""
    packet = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
    for label in host.split('.'):
        packet += bytes([len(label)]) + label.encode()
    packet += bytes([0]) + struct.pack('!HH', qtype, 1)
    rdata = socket.inet_aton(address) if qtype == 1 else socket.inet_pton(socket.AF_INET6, address)
    packet += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(rdata)) + rdata
    return packet


class FakeServer:
    def __init__(self, response):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.response = response
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            _, peer = self.sock.recvfrom(2048)
            self.sock.sendto(self.response, peer)
        except OSError:
            pass

    def close(self):
        self.sock.close()


def test_a_plain_udp_query_parses_an_answer():
    server = FakeServer(_answer('tunnel.example', '203.0.113.7'))
    try:
        found = Reloader._dns_query('127.0.0.1', 'tunnel.example', 1, 2, server.port)
    finally:
        server.close()
    assert [str(item) for item in found] == ['203.0.113.7']


def test_an_empty_answer_is_not_an_address():
    server = FakeServer(struct.pack('!HHHHHH', 0x1234, 0x8183, 1, 0, 0, 0))
    try:
        assert Reloader._dns_query('127.0.0.1', 'tunnel.example', 1, 2, server.port) == []
    finally:
        server.close()


def test_the_configured_resolver_is_used_when_the_host_has_none(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError('no resolver')

    monkeypatch.setattr(services.socket, 'getaddrinfo', broken)
    reloader = Reloader(dns_servers=('192.0.2.53',))
    monkeypatch.setattr(Reloader, '_dns_query',
                        staticmethod(lambda server, host, qtype=1, timeout=2, port=53:
                                     [services.ip_address('198.51.100.9')] if qtype == 1 else []))
    assert [str(item) for item in reloader.resolve_endpoint('tunnel.example')] == ['198.51.100.9']


def test_without_any_resolver_the_error_still_says_what_happened(monkeypatch):
    def broken(*args, **kwargs):
        raise OSError('no resolver')

    from vs_router.agent.apply import ApplyError

    monkeypatch.setattr(services.socket, 'getaddrinfo', broken)
    monkeypatch.setattr(Reloader, '_dns_query',
                        staticmethod(lambda *args, **kwargs: []))
    with pytest.raises(ApplyError) as caught:
        Reloader().resolve_endpoint('tunnel.example')
    assert caught.value.code == 'wireguard.endpoint_unresolved'


def test_only_plain_udp_upstreams_become_endpoint_resolvers():
    from vs_router.agent.apply import _endpoint_resolvers

    configuration = Configuration.model_validate({
        'dns': {'upstreams': [{'address': '192.0.2.1'}, {'address': '', 'mode': 'https',
                                                         'doh_server': 'cloudflare'}]},
    })
    assert _endpoint_resolvers(configuration) == ['192.0.2.1']
