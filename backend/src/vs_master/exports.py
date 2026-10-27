"""Master subscriber exports from master-owned keys and exact node state."""
import io
from types import SimpleNamespace

import qrcode
from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from vs_portal.security import get_secret_key
from vs_router.api.errors import APIError
from vs_router.generators.amnezia import amnezia_uri
from vs_router.generators.wireguard import AWG_ORDER
from vs_router.secrets import decrypt_secret, encrypt_secret

from .accounts import current_account, get_db
from .models import Account, Node
from .portal_api import device_owned, subscriber_state

router = APIRouter(prefix='/api/portal', dependencies=[Depends(current_account)])

# Source: semantics copied from vs_portal.devices. Keep output compatible without
# importing that panel-owned module into the master profile.


def _line(value):
    if not isinstance(value, str) or not value or '\n' in value or '\r' in value:
        raise APIError(503, 'portal.export_unavailable')
    return value


def _conf_text(device, tunnel, key):
    """The wg-quick client config for one device, from stored key material."""
    if not isinstance(tunnel, dict) or not device.private_key or not device.allowed_ips:
        raise APIError(503, 'portal.export_unavailable')
    try:
        private = decrypt_secret(device.private_key, key)
    except (InvalidToken, ValueError):
        raise APIError(503, 'portal.export_unavailable') from None
    endpoint = tunnel.get('endpoint')
    if endpoint and ':' not in endpoint and tunnel.get('listen_port'):
        endpoint = f'{endpoint}:{tunnel["listen_port"]}'
    dns = tunnel.get('dns_servers')
    allowed = tunnel.get('allowed_ips')
    if not endpoint or not tunnel.get('public_key') or not dns or not allowed:
        raise APIError(503, 'portal.export_unavailable')
    lines = ['[Interface]', f'PrivateKey = {_line(private)}',
             'Address = ' + ', '.join(_line(v) for v in device.allowed_ips),
             'DNS = ' + ', '.join(_line(v) for v in dns)]
    if tunnel.get('mtu'):
        lines.append(f'MTU = {_line(str(tunnel["mtu"]))}')
    if tunnel.get('protocol') == 'awg':
        obfuscation = tunnel.get('obfuscation') or {}
        if not obfuscation or (any(name in obfuscation for name in ('S3', 'S4', 'I1'))
                               and not tunnel.get('header_protection_key')):
            raise APIError(503, 'portal.export_unavailable')
        lines += [f'{name} = {_line(str(obfuscation[name]))}'
                  for name in AWG_ORDER if name in obfuscation]
        if tunnel.get('header_protection_key'):
            lines.append(f'HeaderProtectionKey = {_line(tunnel["header_protection_key"])}')
        if tunnel.get('random_trailers'):
            lines.append('RandomTrailers = on')
        if tunnel.get('disable_cookies'):
            lines.append('DisableCookies = on')
    elif tunnel.get('protocol') != 'wg':
        raise APIError(503, 'portal.export_unavailable')
    lines += ['', '[Peer]', f'PublicKey = {_line(tunnel["public_key"])}',
              f'Endpoint = {_line(endpoint)}',
              'AllowedIPs = ' + ', '.join(_line(v) for v in allowed),
              'PersistentKeepalive = 25']
    if device.preshared_key:
        try:
            lines.append(f'PresharedKey = {_line(decrypt_secret(device.preshared_key, key))}')
        except (InvalidToken, ValueError):
            raise APIError(503, 'portal.export_unavailable') from None
    return '\n'.join(lines) + '\n'


def _amnezia_uri(device, tunnel, key, account_name):
    """Build the portal-compatible Amnezia ``vpn://`` container."""
    if tunnel.get('protocol') != 'awg':
        raise APIError(400, 'amnezia.role_unsupported')
    for field in ('listen_port', 'public_key', 'endpoint', 'subnet'):
        if not tunnel.get(field):
            raise APIError(503, 'portal.export_unavailable')
    try:
        private = encrypt_secret(decrypt_secret(device.private_key, key), key) \
            if device.private_key else None
        psk = encrypt_secret(decrypt_secret(device.preshared_key, key), key) \
            if device.preshared_key else None
    except (InvalidToken, ValueError):
        raise APIError(503, 'portal.export_unavailable') from None
    hpk = tunnel.get('header_protection_key')
    dns_pair = tunnel.get('dns_servers') or ()
    shim = SimpleNamespace(
        protocol='awg', role='server', name=tunnel.get('name') or device.name,
        listen_port=tunnel['listen_port'], obfuscation=tunnel.get('obfuscation') or {},
        header_protection_key=encrypt_secret(hpk, key) if hpk else None,
        random_trailers=bool(tunnel.get('random_trailers')),
        disable_cookies=bool(tunnel.get('disable_cookies')),
        allowed_ips=tuple(tunnel.get('allowed_ips') or ()),
        keepalive=tunnel.get('keepalive') or 25,
        mtu=tunnel.get('mtu'),
        dns_servers=tuple(dns_pair), endpoint=None)
    peer = SimpleNamespace(name=device.name, allowed_ips=tuple(device.allowed_ips or ()),
                           public_key=device.public_key, private_key=private,
                           preshared_key=psk)
    try:
        return amnezia_uri(shim, peer, None, dns1=dns_pair[0] if dns_pair else None,
                           dns2=dns_pair[1] if len(dns_pair) > 1 else None,
                           endpoint=tunnel.get('endpoint'), description=device.label,
                           subnet=tunnel['subnet'], server_public=tunnel.get('public_key'))
    except ValueError as exc:
        raise APIError(503, 'portal.export_unavailable') from exc


@router.get('/devices/{identity}/export')
def export_device(identity: str, request: Request, format: str = Query('conf'),
                  account: Account = Depends(current_account), db: Session = Depends(get_db)):
    if format not in ('conf', 'qr', 'amnezia'):
        raise APIError(422, 'portal.export_format')
    device = device_owned(db, identity, account.id)
    node = db.get(Node, device.node_id)
    if node is None:
        raise APIError(503, 'portal.export_unavailable')
    try:
        state = subscriber_state(request, node, device.node_subscriber)
    except APIError:
        raise APIError(503, 'portal.export_unavailable') from None
    tunnel = state.get('tunnel')
    key = get_secret_key()
    filename = device.name or f'device-{device.id}'
    if format == 'qr':
        image = qrcode.make(_conf_text(device, tunnel, key))
        out = io.BytesIO()
        image.save(out, 'PNG')
        return Response(out.getvalue(), media_type='image/png',
                        headers={'Cache-Control': 'no-store'})
    if format == 'amnezia':
        uri = _amnezia_uri(device, tunnel, key, device.node_subscriber)
        return Response(uri, media_type='text/plain; charset=utf-8',
                        headers={'Content-Disposition':
                                 f'attachment; filename="{filename}-amnezia.txt"',
                                 'Cache-Control': 'no-store'})
    return Response(_conf_text(device, tunnel, key), media_type='text/plain; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{filename}.conf"',
                             'Cache-Control': 'no-store'})
