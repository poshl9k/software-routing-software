"""Small bounded UDP DNS client used only when the OS resolver has no answer.

The server must be an IP literal: resolving a DNS server by name would recreate
exactly the bootstrap dependency this module avoids. No subprocesses or extra deps.
"""
from __future__ import annotations

import ipaddress
import os
import secrets
import socket
import struct

DEFAULT_SERVER = '1.1.1.1'
SERVER_ENV = 'VS_ROUTER_BOOTSTRAP_DNS'
TIMEOUT = 2.0
MAX_PACKET = 4096


def _skip_name(packet: bytes, offset: int) -> int:
    """Skip a wire-format name (including compression), without following pointers."""
    for _ in range(128):
        if offset >= len(packet):
            raise OSError('truncated DNS name')
        length = packet[offset]
        offset += 1
        if length == 0:
            return offset
        if length & 0xc0 == 0xc0:
            if offset >= len(packet):
                raise OSError('truncated DNS pointer')
            return offset + 1
        if length & 0xc0 or length > 63 or offset + length > len(packet):
            raise OSError('invalid DNS name')
        offset += length
    raise OSError('DNS name too long')


def _query(host: str, server: ipaddress.IPv4Address | ipaddress.IPv6Address,
           qtype: int) -> list[str]:
    labels = host.rstrip('.').encode('idna').split(b'.')
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise OSError('invalid DNS hostname')
    name = b''.join(bytes((len(label),)) + label for label in labels) + b'\0'
    if len(name) > 255:
        raise OSError('DNS hostname too long')
    identifier = secrets.randbits(16)
    question = name + struct.pack('!HH', qtype, 1)
    request = struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + question
    family = socket.AF_INET6 if server.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((str(server), 53))
        sock.sendall(request)
        reply = sock.recv(MAX_PACKET)
    if len(reply) < 12:
        raise OSError('truncated DNS response')
    reply_id, flags, qdcount, ancount, _, _ = struct.unpack_from('!HHHHHH', reply)
    if reply_id != identifier or flags & 0x8000 == 0 or flags & 0x0200 or flags & 0x7800:
        raise OSError('invalid DNS response header')
    if flags & 0x000f not in (0, 3) or qdcount != 1:
        raise OSError('DNS lookup failed')
    offset = _skip_name(reply, 12)
    if offset + 4 > len(reply) or reply[12:offset].lower() != name.lower() or reply[offset:offset + 4] != question[-4:]:
        raise OSError('DNS question mismatch')
    offset += 4
    addresses = []
    for _ in range(ancount):
        offset = _skip_name(reply, offset)
        if offset + 10 > len(reply):
            raise OSError('truncated DNS record')
        kind, cls, _, length = struct.unpack_from('!HHIH', reply, offset)
        offset += 10
        if offset + length > len(reply):
            raise OSError('truncated DNS data')
        if cls == 1 and kind == qtype:
            if length != (4 if qtype == 1 else 16):
                raise OSError('invalid DNS address length')
            addresses.append(str(ipaddress.ip_address(reply[offset:offset + length])))
        offset += length
    return addresses


def resolve(host: str, *, server: str | None = None) -> list[str]:
    """Query A and AAAA directly; caller must validate *every* answer for SSRF."""
    try:
        address = ipaddress.ip_address(server if server is not None else
                                       os.environ.get(SERVER_ENV, DEFAULT_SERVER))
    except ValueError as exc:
        raise OSError('bootstrap DNS server must be an IP literal') from exc
    addresses = []
    errors = []
    for qtype in (1, 28):
        try:
            addresses.extend(_query(host, address, qtype))
        except OSError as exc:
            errors.append(exc)
    if not addresses and errors:
        raise OSError('bootstrap DNS lookup failed') from errors[0]
    return sorted(set(addresses))
