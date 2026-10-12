"""Offline packet-level checks for the stdlib bootstrap DNS client."""
import ipaddress
import socket
import struct

import pytest

from vs_router.agent import bootstrap_dns


class FakeSocket:
    def __init__(self, answers):
        self.answers = answers
        self.sent = None
        self.peer = None
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, peer):
        self.peer = peer

    def sendall(self, packet):
        self.sent = packet

    def recv(self, limit):
        assert limit == bootstrap_dns.MAX_PACKET
        assert self.sent is not None
        ident = self.sent[:2]
        question = self.sent[12:]
        qtype = struct.unpack('!H', question[-4:-2])[0]
        addresses = self.answers.get(qtype, ())
        records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 60, len(ipaddress.ip_address(ip).packed))
                           + ipaddress.ip_address(ip).packed for ip in addresses)
        return ident + struct.pack('!HHHHH', 0x8180, 1, len(addresses), 0, 0) + question + records


def test_queries_a_and_aaaa_against_literal_server(monkeypatch):
    sockets = []

    def factory(family, kind):
        assert family == socket.AF_INET and kind == socket.SOCK_DGRAM
        result = FakeSocket({1: ['93.184.216.34'], 28: ['2606:4700:4700::1111']})
        sockets.append(result)
        return result

    monkeypatch.setattr(bootstrap_dns.socket, 'socket', factory)
    monkeypatch.setenv(bootstrap_dns.SERVER_ENV, '9.9.9.9')
    assert bootstrap_dns.resolve('example.org') == ['2606:4700:4700::1111', '93.184.216.34']
    assert len(sockets) == 2
    assert all(s.sent is not None for s in sockets)
    assert all(s.peer == ('9.9.9.9', 53) and s.timeout == bootstrap_dns.TIMEOUT for s in sockets)
    assert [struct.unpack('!H', s.sent[-4:-2])[0] for s in sockets] == [1, 28]


def test_server_must_be_ip_literal(monkeypatch):
    monkeypatch.setenv(bootstrap_dns.SERVER_ENV, 'dns.example.org')
    with pytest.raises(OSError, match='IP literal'):
        bootstrap_dns.resolve('example.org')
