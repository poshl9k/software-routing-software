"""Bounded client for sing-box's loopback Clash API."""

import ipaddress
import json
import re
import time
from urllib.error import URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .apply import ApplyError


_MAX_RESPONSE = 1024 * 1024
_MAX_LINE = 16 * 1024
_TIMEOUT = 5
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_ADDRESS_KEYS = frozenset({'server', 'server_addr', 'server_address', 'remote_address',
                           'remote_addr', 'destination', 'destination_ip', 'host',
                           'password', 'secret', 'token', 'authorization', 'url'})
_LOG_SECRET = re.compile(r'(?i)(password|secret|token|authorization|uuid|key)\s*[:=]\s*[^\s,;]+|https?://[^\s]+')


def _redact(value):
    if isinstance(value, dict):
        return {key: ('[redacted]' if key.lower() in _ADDRESS_KEYS and item else _redact(item))
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return _LOG_SECRET.sub('[redacted]', value)
    return value


def _segment(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ApplyError('clash.invalid_input')
    return quote(value, safe='')


def _delay_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ApplyError('clash.invalid_input')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ApplyError('clash.invalid_input') from None
    if (parsed.scheme not in ('http', 'https') or not host or not parsed.netloc
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or not _HOST.fullmatch(host) or '..' in host
            or host.lower() in ('localhost',) or host.lower().endswith(('.localhost', '.local', '.internal'))
            or port == 0):
        raise ApplyError('clash.invalid_input')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ApplyError('clash.invalid_input')
    # Numeric and single-label names may resolve to local interfaces.
    if '.' not in host or host.replace('.', '').isdigit():
        raise ApplyError('clash.invalid_input')
    # sing-box resolves independently; DNS preflight cannot prevent rebinding.
    if host.lower() not in ('example.com', 'www.gstatic.com', 'cp.cloudflare.com'):
        raise ApplyError('clash.invalid_input')
    return value


class ClashClient:
    def __init__(self, opener=None, port=9099, clock=None):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('invalid Clash port')
        self.opener = opener if opener is not None else build_opener(ProxyHandler({})).open
        self.base_url = f'http://127.0.0.1:{port}'
        self.clock = clock if clock is not None else time.monotonic

    def _open(self, path, *, method='GET', data=None, timeout=_TIMEOUT):
        request = Request(self.base_url + path, data=data, method=method,
                          headers={'Content-Type': 'application/json'} if data is not None else {})
        return self.opener(request, timeout=timeout)

    def _json(self, path, *, method='GET', data=None, timeout=_TIMEOUT):
        try:
            with self._open(path, method=method, data=data, timeout=timeout) as response:
                if not 200 <= response.status < 300:
                    raise ApplyError('clash.unavailable')
                payload = response.read(_MAX_RESPONSE + 1)
            if len(payload) > _MAX_RESPONSE:
                raise ApplyError('clash.unavailable')
            return _redact(json.loads(payload)) if payload else None
        except (OSError, URLError, ValueError, UnicodeError) as exc:
            raise ApplyError('clash.unavailable') from None

    def version(self):
        return self._json('/version')

    def connections(self):
        return self._json('/connections')

    def close_connection(self, connection_id):
        return self._json('/connections/' + _segment(connection_id), method='DELETE')

    def logs(self, level='info', limit=100):
        if level not in ('debug', 'info', 'warning', 'error', 'all') or type(limit) is not int or not 1 <= limit <= 500:
            raise ApplyError('clash.invalid_input')
        deadline = self.clock() + _TIMEOUT
        result = []
        try:
            with self._open('/logs?' + urlencode({'level': level}), timeout=_TIMEOUT) as response:
                if not 200 <= response.status < 300:
                    raise ApplyError('clash.unavailable')
                while len(result) < limit and self.clock() < deadline:
                    line = response.readline(_MAX_LINE + 1)
                    if not line:
                        break
                    if len(line) > _MAX_LINE:
                        raise ApplyError('clash.unavailable')
                    result.append(_redact(json.loads(line)))
            return result
        except (OSError, URLError, ValueError, UnicodeError):
            raise ApplyError('clash.unavailable') from None

    def proxies(self):
        return self._json('/proxies')

    def select_proxy(self, group, name):
        _segment(name)
        return self._json('/proxies/' + _segment(group), method='PUT',
                          data=json.dumps({'name': name}).encode())

    def proxy_delay(self, tag, url, timeout_ms):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ApplyError('clash.invalid_input')
        safe_url = _delay_url(url)
        query = urlencode({'url': safe_url, 'timeout': timeout_ms})
        return self._json('/proxies/' + _segment(tag) + '/delay?' + query,
                          timeout=min(_TIMEOUT, timeout_ms / 1000 + 1))
