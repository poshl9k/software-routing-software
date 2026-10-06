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


def generate_wg_conf(tunnel, key_material: dict, configuration=None) -> str:
    """key_material is reserved for export metadata; schema secrets use the env key.

    With `configuration`, a server peer that carries no AllowedIPs gets an
    automatic /32 from the tunnel subnet (so `wg/awg setconf` always sees a
    valid line and the peer has an address).
    """
    lines = ['[Interface]', f'PrivateKey = {line(reveal(tunnel.private_key))}']
    if tunnel.listen_port is not None:
        lines.append(f'ListenPort = {tunnel.listen_port}')
    lines += obfuscation(tunnel)
    if tunnel.role == 'client':
        lines += ['', '[Peer]', f'PublicKey = {line(tunnel.server_public_key)}',
                  f'Endpoint = {line(tunnel.endpoint)}']
        # An empty AllowedIPs line is rejected by `wg/awg setconf`
        # ("Line unrecognized"); omit it instead of emitting a dangling key.
        if tunnel.allowed_ips:
            lines.append('AllowedIPs = ' + ', '.join(map(line, tunnel.allowed_ips)))
        lines.append(f'PersistentKeepalive = {tunnel.keepalive}')
    else:
        for peer in sorted(tunnel.peers, key=lambda p: p.name):
            lines += ['', '[Peer]', f'PublicKey = {line(peer.public_key)}']
            if peer.preshared_key:
                lines.append(f'PresharedKey = {line(reveal(peer.preshared_key))}')
            allowed = peer.allowed_ips or (
                tuple(peer_address(tunnel, peer, configuration)) if configuration is not None else ())
            if allowed:
                lines.append('AllowedIPs = ' + ', '.join(map(line, allowed)))
    return '\n'.join(lines) + '\n'


# Deterministic MVP tunnel pool: the Nth tunnel (by name) owns
# 10.66.<base+N>.0/24, so a single tunnel keeps the historical 10.66.66.0/24 and
# further tunnels no longer collide. Explicit interface addresses always win.
SUBNET_BASE = 66


def tunnel_index(tunnel, configuration) -> int:
    return sorted(t.name for t in configuration.tunnels).index(tunnel.name)


def tunnel_addresses(tunnel, configuration):
    """Addresses for the tunnel device.

    Prefer declared interface addresses; a server may also take the first host of
    a non-default subnet from its AllowedIPs. Otherwise the tunnel gets a
    deterministic host in its own /24 slot (server .1, client .2).
    """
    for interface in configuration.interfaces:
        if interface.name == tunnel.interface and interface.addresses:
            return list(interface.addresses)
    if tunnel.role == 'server':
        for value in tunnel.allowed_ips:
            net = ip_network(value, strict=False)
            if net.prefixlen and net.num_addresses > 1:
                return [f'{next(net.hosts())}/{net.prefixlen}']
    host = 1 if tunnel.role == 'server' else 2
    return [f'10.66.{SUBNET_BASE + tunnel_index(tunnel, configuration)}.{host}/24']


def peer_address(tunnel, peer, configuration):
    """A server peer's tunnel address.

    Its own AllowedIPs win; otherwise the peer gets the next free host in the
    tunnel subnet (.2, .3, … in name order) as a /32, so every client receives a
    usable address without hand-assignment.
    """
    if peer.allowed_ips:
        return list(peer.allowed_ips)
    network = ip_network(tunnel_addresses(tunnel, configuration)[0], strict=False)
    order = [p.name for p in sorted(tunnel.peers, key=lambda p: p.name)]
    host = 2 + order.index(peer.name)
    if host >= network.num_addresses:
        raise ValueError('wireguard.peer_pool_exhausted')
    bits = network.max_prefixlen if network.version == 6 else 32
    return [f'{network.network_address + host}/{bits}']


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
        files[f'{t.name}.conf'] = generate_wg_conf(t, key_material, c)
        routes = t.allowed_ips if t.role == 'client' else tuple(
            value for peer in t.peers for value in peer_address(t, peer, c))
        manifest[t.interface] = {'file': f'{t.name}.conf', 'protocol': t.protocol,
                                 'addresses': tunnel_addresses(t, c),
                                 'routes': sorted({str(ip_network(v, strict=False)) for v in routes})}
        if t.role != 'server' or not t.peers:
            continue
        metadata = key_material.get(t.name, {})
        endpoint = metadata.get('endpoint')
        endpoint_missing = False
        if endpoint is None:
            wan = next((ip_interface(i.addresses[0]).ip for i in c.interfaces
                        if i.zone == 'wan' and i.addresses), None)
            if wan is None:
                # A DHCP WAN carries no configured address to derive the client
                # endpoint from. The router-side server config is still valid,
                # so degrade the per-peer export to a fill-in template instead
                # of failing the whole apply; generators stay I/O-free, so the
                # live DHCP lease is deliberately not read here.
                endpoint_missing = True
            else:
                endpoint = f'[{wan}]:{t.listen_port}' if wan.version == 6 else f'{wan}:{t.listen_port}'
        try:
            public = base64.b64encode(X25519PrivateKey.from_private_bytes(
                base64.b64decode(reveal(t.private_key), validate=True)).public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode()
        except ValueError:
            raise ValueError('wireguard.invalid_private_key') from None
        for p in sorted(t.peers, key=lambda p: p.name):
            # Peer keypair generated by the panel (p.private_key) wins over
            # export metadata; without either the export stays a template.
            secret = p.private_key
            if isinstance(secret, dict):
                secret = EncryptedSecret.model_validate(secret)
            if secret is None:
                raw = metadata.get('peer_private_keys', {}).get(p.name)
                if isinstance(raw, dict):
                    raw = EncryptedSecret.model_validate(raw)
                secret = raw
            private = reveal(secret) if secret else '<CLIENT_PRIVATE_KEY>'
            placeholders = []
            if not secret:
                placeholders.append('insert client private key before importing')
            if endpoint_missing:
                placeholders.append('replace <WAN_ENDPOINT> with the router public address')
            lines = [f'# TEMPLATE: {"; ".join(placeholders)}.'] if placeholders else []
            addresses = p.allowed_ips or tuple(peer_address(t, p, c))
            lines += ['[Interface]', f'PrivateKey = {line(private)}']
            if addresses:
                lines.append('Address = ' + ', '.join(map(line, addresses)))
            lines += obfuscation(t)
            lines += ['', '[Peer]', f'PublicKey = {public}',
                      f'Endpoint = {line(endpoint if endpoint is not None else "<WAN_ENDPOINT>")}',
                      'AllowedIPs = ' + ', '.join(map(line, t.allowed_ips or ('0.0.0.0/0',))),
                      f'PersistentKeepalive = {t.keepalive or 25}']
            if p.preshared_key:
                lines.append(f'PresharedKey = {line(reveal(p.preshared_key))}')
            files[f'{t.name}.peer-{p.name}.conf'] = '\n'.join(lines) + '\n'
    files['manifest.json'] = json.dumps(manifest, sort_keys=True, indent=2) + '\n'
    return files
