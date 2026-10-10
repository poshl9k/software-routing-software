"""setconf files and client exports; plaintext exists only in protected bundles.

Auto IPv4 tunnel subnets use 10.66.(66 + SHA-256(name) % 190).0/24;
server/client devices use .1/.2. Auto peers use host
2 + SHA-256(peer name) % 253 in that subnet, as /32. Hash inputs are UTF-8;
collisions raise wireguard.address_collision, never probe by list order.
Explicit interface addresses and peer AllowedIPs take precedence. Existing
materialized addresses remain explicit, including those from older schemes.
"""
import base64
import hashlib
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


SUBNET_BASE = 66
SUBNET_SLOTS = 256 - SUBNET_BASE


def _hash_slot(name: str, slots: int) -> int:
    return int.from_bytes(hashlib.sha256(name.encode('utf-8')).digest(), 'big') % slots


def _automatic_tunnel(tunnel, configuration) -> bool:
    if any(i.name == tunnel.interface and i.addresses for i in configuration.interfaces):
        return False
    if tunnel.role == 'server':
        for value in tunnel.allowed_ips:
            net = ip_network(value, strict=False)
            if net.prefixlen and net.num_addresses > 1:
                return False
    return True


def tunnel_index(tunnel, configuration) -> int:
    slot = _hash_slot(tunnel.name, SUBNET_SLOTS)
    if _automatic_tunnel(tunnel, configuration):
        for other in configuration.tunnels:
            if (other.name != tunnel.name and _automatic_tunnel(other, configuration)
                    and _hash_slot(other.name, SUBNET_SLOTS) == slot):
                raise ValueError('wireguard.address_collision')
    return slot


def tunnel_addresses(tunnel, configuration):
    """Addresses for the tunnel device.

    Prefer declared interface addresses; a server may also take the first host of
    a non-default subnet from its AllowedIPs. Otherwise the tunnel gets a
    hash-selected /24 slot (server .1, client .2).
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

    Its own AllowedIPs win; otherwise hash its name into the usable host range
    starting at .2 (reserving .1 for the server). A collision with another
    automatically assigned peer is an error, not an order-dependent probe.
    """
    if peer.allowed_ips:
        return list(peer.allowed_ips)
    network = ip_network(tunnel_addresses(tunnel, configuration)[0], strict=False)
    slots = network.num_addresses - 3  # .0 network, .1 server, last broadcast
    if slots < 1:
        raise ValueError('wireguard.peer_pool_exhausted')
    host = 2 + _hash_slot(peer.name, slots)
    if any(p.name != peer.name and not p.allowed_ips
           and 2 + _hash_slot(p.name, slots) == host for p in tunnel.peers):
        raise ValueError('wireguard.address_collision')
    bits = network.max_prefixlen
    return [f'{network.network_address + host}/{bits}']


def materialize_addresses(configuration):
    """Fill the deterministic tunnel/peer addresses into a configuration.

    The stored configuration then carries them (the panel shows and can edit
    them). Explicit values always win; a tunnel without a declared interface
    address takes its hash-selected pool slot; a server peer without AllowedIPs
    takes a hash-selected /32 in the tunnel subnet.
    """
    peers_by_tunnel = []
    for tunnel in configuration.tunnels:
        peers = []
        for peer in tunnel.peers:
            if tunnel.role == 'server' and not peer.allowed_ips:
                peers.append(peer.model_copy(
                    update={'allowed_ips': tuple(peer_address(tunnel, peer, configuration))}))
            else:
                peers.append(peer)
        peers_by_tunnel.append(tunnel.model_copy(update={'peers': tuple(peers)}))
    filled = configuration.model_copy(update={'tunnels': tuple(peers_by_tunnel)})
    index = {interface.name: position for position, interface in enumerate(configuration.interfaces)}
    interfaces = list(configuration.interfaces)
    for tunnel in filled.tunnels:
        position = index.get(tunnel.interface)
        if position is None:
            continue
        interface = interfaces[position]
        # An interface without addresses keeps its DHCP/static semantics; only a
        # static (or auto-created) device takes the tunnel's own address.
        if not interface.addresses and interface.addressing != 'dhcp':
            interfaces[position] = interface.model_copy(
                update={'addresses': tuple(tunnel_addresses(tunnel, filled))})
    return filled.model_copy(update={'interfaces': tuple(interfaces)})


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
        # Precedence: caller-provided endpoint (live/agent), the tunnel's own
        # public endpoint, then the WAN address, else a template placeholder.
        endpoint = metadata.get('endpoint') or t.endpoint
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
        elif ':' not in endpoint:
            # A bare host/IP gets the listen port; a value with a port is kept.
            endpoint = f'{endpoint}:{t.listen_port}'
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
