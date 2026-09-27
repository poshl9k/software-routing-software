"""Live DHCP leases read from the Kea ctrl-agent over HTTP (TCP localhost)."""
import base64
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query

from .auth import current_user
from .errors import APIError

router = APIRouter(dependencies=[Depends(current_user)])


def _auth_header():
    user = os.environ.get('VS_ROUTER_KEA_API_USER')
    password = os.environ.get('VS_ROUTER_KEA_API_PASSWORD')
    if password is None:
        path = os.environ.get('VS_ROUTER_KEA_API_PASSWORD_FILE', '/etc/kea/kea-api-password')
        try:
            password = Path(path).read_text().strip()
        except OSError:
            return None
    if not user or not password:
        return None
    token = base64.b64encode(f'{user}:{password}'.encode()).decode()
    return f'Basic {token}'


def kea_request(command='lease4-get-all'):
    url = urlparse(os.environ.get('VS_ROUTER_KEA_CTRL_URL', 'http://127.0.0.1:8000/'))
    headers = {'Content-Type': 'application/json'}
    auth = _auth_header()
    if auth:
        headers['Authorization'] = auth
    body = json.dumps({'command': command, 'service': ['dhcp4']}).encode()
    connection = http.client.HTTPConnection(url.hostname or '127.0.0.1',
                                            url.port or 8000, timeout=4)
    try:
        connection.request('POST', url.path or '/', body=body, headers=headers)
        response = connection.getresponse()
        if response.status == 401:
            raise APIError(502, 'kea.auth_failed')
        raw = response.read()
    except OSError:
        raise APIError(503, 'kea.unavailable') from None
    except http.client.HTTPException as exc:
        raise APIError(502, 'kea.error') from exc
    finally:
        connection.close()
    return json.loads(raw)


def lease_rows(subnet=None):
    try:
        result = kea_request()
    except APIError:
        raise
    except OSError:
        raise APIError(503, 'kea.unavailable') from None
    except Exception:
        raise APIError(502, 'kea.error') from None
    try:
        if not result:
            raise ValueError()
        # result 0 = success with arguments, 3 = success with zero entries
        if result[0].get('result') not in (0, 3):
            raise ValueError()
        leases = result[0].get('arguments', {}).get('leases', []) if result[0].get('result') == 0 else []
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
