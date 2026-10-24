"""Master's HTTPS client for a node's internal bridge (ADR-0035 D2).

The master is the only caller: it authenticates with the long-lived bearer
token issued during node onboarding. Rotation (``rotate``) authenticates with
the CURRENT token and is idempotent: a lost response retried with the old
token answers ``{'rotated': False}`` when the proposed token is already
current, or 403 when the old token has been revoked — the caller treats a 403
on rotate as "the node is ahead; re-read state or re-onboard manually".
"""
import httpx

from vs_router.api.errors import APIError


class BridgeError(Exception):
    def __init__(self, status, code):
        super().__init__(f'{status}: {code}')
        self.status = status
        self.code = code


class BridgeClient:
    def __init__(self, base_url: str, token: str, transport: httpx.BaseTransport | None = None,
                 timeout: float = 15.0):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.transport = transport
        self.timeout = timeout

    def _request(self, method, path, json=None, token=None):
        headers = {'Authorization': f'Bearer {token if token is not None else self.token}'}
        try:
            with httpx.Client(base_url=self.base_url, transport=self.transport,
                              timeout=self.timeout) as client:
                response = client.request(method, path, json=json, headers=headers)
        except httpx.HTTPError as exc:
            raise BridgeError(503, 'node.unreachable') from exc
        if response.status_code in (401, 403):
            raise BridgeError(response.status_code, 'node.auth_failed')
        try:
            body = response.json()
        except ValueError:
            raise BridgeError(response.status_code, 'node.bad_response') from None
        if response.is_error:
            error = body.get('error', {}) if isinstance(body, dict) else {}
            code = error.get('code') if isinstance(error, dict) else None
            raise BridgeError(response.status_code, code if isinstance(code, str) and code else 'node.bad_response')
        return body

    def node_state(self):
        """Telemetry: {'active_devices': int, 'tunnels': {...}} (D7)."""
        return self._request('GET', '/internal/master/state')

    def state(self, subscriber: str):
        """Subscriber devices, subscription echo, and tunnel export state."""
        return self._request('GET', f'/internal/portal/subscribers/{subscriber}/state')

    def device_op(self, subscriber: str, payload: dict):
        return self._request('POST', f'/internal/portal/subscribers/{subscriber}/device-op', payload)

    def expire(self, subscriber: str):
        return self._request('POST', f'/internal/portal/subscribers/{subscriber}/expire', {})

    def renew(self, subscriber: str):
        return self._request('POST', f'/internal/portal/subscribers/{subscriber}/renew', {})

    def rotate(self, new_token: str, token=None):
        return self._request('POST', '/internal/master/token-rotate',
                             {'new_token': new_token}, token=token)
