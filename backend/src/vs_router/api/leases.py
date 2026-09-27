"""Live DHCP leases read from the Kea ctrl-agent over its Unix HTTP socket."""
import http.client
import json
import os
import socket

from fastapi import APIRouter, Depends, Query

from .auth import current_user
from .errors import APIError

router = APIRouter(dependencies=[Depends(current_user)])


def kea_request():
    path = os.environ.get('VS_ROUTER_KEA_CTRL_SOCKET', '/run/kea/kea-ctrl-agent.sock')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(4)
    try:
        body = json.dumps({'command': 'lease4-get-all', 'service': ['dhcp4']}).encode()
        sock.connect(path)
        sock.sendall(b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n'
                     b'Connection: close\r\nContent-Length: '
                     + str(len(body)).encode() + b'\r\n\r\n' + body)
        raw = bytearray()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        sock.close()
    head, body = bytes(raw).split(b'\r\n\r\n', 1)
    if b' 200 ' not in head.split(b'\r\n', 1)[0]:
        raise ValueError('kea.http_status')
    if b'transfer-encoding: chunked' in head.lower():
        decoded = bytearray()
        while body:
            size, body = body.split(b'\r\n', 1)
            n = int(size.split(b';')[0], 16)
            if n == 0:
                break
            decoded.extend(body[:n])
            body = body[n + 2:]
        body = bytes(decoded)
    return json.loads(body)


def lease_rows(subnet=None):
    try:
        result = kea_request()
    except OSError:
        raise APIError(503, 'kea.unavailable') from None
    except Exception:
        raise APIError(502, 'kea.error') from None
    try:
        if not result or result[0].get('result') != 0:
            raise ValueError()
        leases = result[0]['arguments']['leases']
    except Exception:
        raise APIError(502, 'kea.error') from None
    return [{'ip': x['ip-address'], 'mac': x.get('hw-address', ''),
             'hostname': x.get('hostname', ''), 'subnet': x.get('subnet-id'),
             'cltt': x.get('cltt'), 'valid_lft': x.get('valid-lft'),
             'expires_in': x.get('valid-lft')}
            for x in leases if subnet is None or str(x.get('subnet-id')) == str(subnet)]


@router.get('/dhcp/leases')
def get_leases(subnet: str | None = None):
    return lease_rows(subnet)


@router.get('/dhcp/leases/search')
def search_leases(q: str = Query(min_length=1)):
    needle = q.casefold()
    return [x for x in lease_rows()
            if needle in ' '.join(str(x.get(k, '')) for k in ('ip', 'mac', 'hostname')).casefold()]
