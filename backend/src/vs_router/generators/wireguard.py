"""setconf files and client exports; plaintext exists only in protected bundles."""
import base64
import json
import os
from ipaddress import ip_interface, ip_network
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.fernet import InvalidToken

from ..schema import EncryptedSecret
from ..secrets import decrypt_secret
from .bundle import serialize as serialize_wireguard, deserialize as deserialize_wireguard


def reveal(secret):
    try:
        return decrypt_secret(secret, os.environ['VS_ROUTER_SECRET_KEY'].encode())
    except (KeyError, ValueError, InvalidToken):
        raise ValueError('secret.decryption_failed') from None


def line(value):
    value = str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('wireguard.invalid_value')
    return value


def obfuscation(tunnel):
    return [f'{key} = {tunnel.obfuscation[key]}' for key in
            ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4')
            if key in tunnel.obfuscation] if tunnel.protocol == 'awg' else []


def generate_wg_conf(tunnel, key_material: dict) -> str:
    """key_material is reserved for export metadata; schema secrets use the env key."""
    lines = ['[Interface]', f'PrivateKey = {line(reveal(tunnel.private_key))}']
    if tunnel.listen_port is not None:
        lines.append(f'ListenPort = {tunnel.listen_port}')
    lines += obfuscation(tunnel)
    if tunnel.role == 'client':
        lines += ['', '[Peer]', f'PublicKey = {line(tunnel.server_public_key)}',
                  f'Endpoint = {line(tunnel.endpoint)}',
                  'AllowedIPs = ' + ', '.join(map(line, tunnel.allowed_ips)),
                  f'PersistentKeepalive = {tunnel.keepalive}']
    else:
        for peer in sorted(tunnel.peers, key=lambda p: p.name):
            lines += ['', '[Peer]', f'PublicKey = {line(peer.public_key)}']
            if peer.preshared_key:
                lines.append(f'PresharedKey = {line(reveal(peer.preshared_key))}')
            lines.append('AllowedIPs = ' + ', '.join(map(line, peer.allowed_ips)))
    return '\n'.join(lines) + '\n'


def tunnel_addresses(tunnel, configuration):
    """TODO: add explicit tunnel addresses to schema; AllowedIPs are remote routes.

    Prefer configured interface addresses. Legacy MVP servers use the first host
    of their non-default subnet; clients without addresses use 10.66.66.2/24.
    This fallback is intentionally limited and cannot allocate multi-tunnel IPs.
    """
    for interface in configuration.interfaces:
        if interface.name == tunnel.interface and interface.addresses:
            return list(interface.addresses)
    if tunnel.role == 'server':
        for value in tunnel.allowed_ips:
            net = ip_network(value, strict=False)
            if net.prefixlen and net.num_addresses > 1:
                return [f'{next(net.hosts())}/{net.prefixlen}']
    return ['10.66.66.1/24' if tunnel.role == 'server' else '10.66.66.2/24']


def generate_wg_bundle(version, key_material) -> dict[str, str]:
    """Metadata keyed by tunnel name: endpoint and peer_private_keys (encrypted).

    Public server keys are derived, never invented. Peers whose private key is
    unavailable get an explicitly marked export template requiring their key.
    """
    files, manifest = {}, {}
    c = version.configuration
    for t in sorted(c.tunnels, key=lambda t: t.name):
        if t.interface in manifest:
            raise ValueError('wireguard.duplicate_interface')
        files[f'{t.name}.conf'] = generate_wg_conf(t, key_material)
        routes = t.allowed_ips if t.role == 'client' else tuple(
            value for peer in t.peers for value in peer.allowed_ips)
        manifest[t.interface] = {'file': f'{t.name}.conf', 'protocol': t.protocol,
                                 'addresses': tunnel_addresses(t, c),
                                 'routes': sorted({str(ip_network(v, strict=False)) for v in routes})}
        if t.role != 'server' or not t.peers:
            continue
        metadata = key_material.get(t.name, {})
        endpoint = metadata.get('endpoint')
        if endpoint is None:
            wan = next((ip_interface(i.addresses[0]).ip for i in c.interfaces
                        if i.zone == 'wan' and i.addresses), None)
            if wan is None:
                raise ValueError('wireguard.export_endpoint_required')
            endpoint = f'[{wan}]:{t.listen_port}' if wan.version == 6 else f'{wan}:{t.listen_port}'
        try:
            public = base64.b64encode(X25519PrivateKey.from_private_bytes(
                base64.b64decode(reveal(t.private_key), validate=True)).public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode()
        except ValueError:
            raise ValueError('wireguard.invalid_private_key') from None
        for p in sorted(t.peers, key=lambda p: p.name):
            secret = metadata.get('peer_private_keys', {}).get(p.name)
            if isinstance(secret, dict):
                secret = EncryptedSecret.model_validate(secret)
            private = reveal(secret) if secret else '<CLIENT_PRIVATE_KEY>'
            lines = ([] if secret else ['# TEMPLATE: insert client private key before importing.'])
            lines += ['[Interface]', f'PrivateKey = {line(private)}',
                      'Address = ' + ', '.join(map(line, p.allowed_ips))] + obfuscation(t)
            lines += ['', '[Peer]', f'PublicKey = {public}', f'Endpoint = {line(endpoint)}',
                      'AllowedIPs = ' + ', '.join(map(line, t.allowed_ips or ('0.0.0.0/0',))),
                      f'PersistentKeepalive = {t.keepalive or 25}']
            if p.preshared_key:
                lines.append(f'PresharedKey = {line(reveal(p.preshared_key))}')
            files[f'{t.name}.peer-{p.name}.conf'] = '\n'.join(lines) + '\n'
    files['manifest.json'] = json.dumps(manifest, sort_keys=True, indent=2) + '\n'
    return files
