"""Narrow authenticated UDS transport to the panel's internal application."""
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

import httpx

from vs_router.api.errors import APIError

DEFAULT_SOCKET = '/run/vs-router/web/internal.sock'
DEFAULT_SECRET = '/etc/vs-router/portal-internal.secret'


def read_internal_secret():
    source = os.environ.get('VS_PORTAL_INTERNAL_SECRET')
    if source is None:
        source = os.environ.get('VS_PORTAL_INTERNAL_SECRET_FILE', DEFAULT_SECRET)
        is_path = True
    else:
        is_path = source.startswith('/')
    try:
        value = Path(source).read_text().strip() if is_path else source
    except OSError:
        raise APIError(503, 'portal.internal_unavailable') from None
    if not value or '\n' in value or '\r' in value:
        raise APIError(503, 'portal.internal_unavailable')
    return value


class InternalClient:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        raw = os.environ.get('VS_PORTAL_INTERNAL_URL', f'http+unix://{DEFAULT_SOCKET.replace("/", "%2F")}')
        if raw == 'http://portal-internal.sock':
            raw = f'http+unix://{DEFAULT_SOCKET.replace("/", "%2F")}'
        if transport is None:
            parsed = urlsplit(raw)
            if parsed.scheme != 'http+unix' or not parsed.netloc or parsed.path:
                raise APIError(503, 'portal.internal_unavailable')
            socket = unquote(parsed.netloc)
            if not socket.startswith('/'):
                raise APIError(503, 'portal.internal_unavailable')
            transport = httpx.HTTPTransport(uds=socket)
        self.transport = transport

    def _request(self, method, name, suffix, payload=None):
        from urllib.parse import quote
        path = f'/internal/portal/subscribers/{quote(name, safe="")}/{suffix}'
        try:
            with httpx.Client(transport=self.transport, base_url='http://portal-internal.sock', timeout=15) as client:
                response = client.request(method, path, json=payload,
                                          headers={'X-VS-Portal-Secret': read_internal_secret()})
        except httpx.HTTPError:
            raise APIError(503, 'portal.internal_unavailable') from None
        try:
            body = response.json()
        except ValueError:
            raise APIError(503, 'portal.internal_unavailable') from None
        if response.is_error:
            error = body.get('error', {}) if isinstance(body, dict) else {}
            code = error.get('code') if isinstance(error, dict) else None
            raise APIError(response.status_code, code if isinstance(code, str) and code else 'portal.internal_unavailable')
        if not isinstance(body, dict):
            raise APIError(503, 'portal.internal_unavailable')
        return body

    def state(self, name):
        return self._request('GET', name, 'state')

    def device_op(self, name, payload):
        return self._request('POST', name, 'device-op', payload)

    def expire(self, name):
        return self._request('POST', name, 'expire', {})

    def renew(self, name):
        return self._request('POST', name, 'renew', {})
