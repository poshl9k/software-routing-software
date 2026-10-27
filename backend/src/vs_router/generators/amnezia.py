"""Amnezia VPN container export (`vpn://`) for a server peer.

The Amnezia app does not import a bare wg-quick ``.conf`` for its AmneziaWG
container; it imports its own document:

    vpn:// + base64url( uint32_be(uncompressed length) + zlib(JSON) )

The JSON is shaped like the app's own export (verified against a real blob):
top-level host/port/DNS, a ``containers`` list, and per container the ``awg``
block with the obfuscation parameters as strings, plus ``last_config`` — a JSON
string whose ``config`` is the peer's ``.conf`` text with
``$PRIMARY_DNS``/``$SECONDARY_DNS`` placeholders the app resolves from the
top-level ``dns1``/``dns2``.

Only AmneziaWG (``protocol == 'awg'``) server tunnels are exported here: a plain
WireGuard container is deliberately out of scope until one is observed, so the
generator never invents a shape it has not seen.
"""
import base64
import json
import zlib
from ipaddress import ip_interface, ip_network

from .wireguard import (AWG_ORDER, DEFAULT_PRIMARY_DNS, DEFAULT_SECONDARY_DNS, client_endpoint,
                        effective_obfuscation, line, obfuscation, peer_address, reveal,
                        server_public_key, tunnel_addresses, tunnel_dns)

# The app's own AWG export carries an MTU. The panel does not model one yet, so
# the observed default is emitted until a per-tunnel MTU field exists.
DEFAULT_MTU = 1376
CONTAINER = 'amnezia-awg2'
PROTOCOL_VERSION = '3.1'
TRANSPORT_PROTO = 'udp'
DEFAULT_ALLOWED_IPS = ('0.0.0.0/0', '::/0')
DNS_PLACEHOLDER = '$PRIMARY_DNS, $SECONDARY_DNS'


def encode_document(document: dict) -> str:
    """``vpn://`` URI for a container document (inverse of ``decode_document``)."""
    raw = json.dumps(document, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    payload = len(raw).to_bytes(4, 'big') + zlib.compress(raw)
    return 'vpn://' + base64.urlsafe_b64encode(payload).decode().rstrip('=')


def decode_document(uri: str) -> dict:
    """Read a ``vpn://`` URI back into its document. Used by tests and diagnostics."""
    body = uri[len('vpn://'):] if uri.startswith('vpn://') else uri
    payload = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
    if len(payload) < 4:
        raise ValueError('amnezia.truncated')
    declared = int.from_bytes(payload[:4], 'big')
    raw = zlib.decompress(payload[4:])
    if len(raw) != declared:
        raise ValueError('amnezia.length_mismatch')
    return json.loads(raw)


def awg_parameters(tunnel) -> dict[str, str]:
    """The obfuscation block the app carries: parameters as strings, I1-I5 always present."""
    effective = effective_obfuscation(tunnel)
    params = {key: str(effective[key]) for key in AWG_ORDER if key in effective}
    for key in ('I1', 'I2', 'I3', 'I4', 'I5'):
        params.setdefault(key, '')
    if tunnel.header_protection_key is not None:
        params['HeaderProtectionKey'] = line(reveal(tunnel.header_protection_key))
    if tunnel.random_trailers:
        params['RandomTrailers'] = 'on'
    if tunnel.disable_cookies:
        params['DisableCookies'] = 'on'
    return params


def _client_addresses(tunnel, peer, configuration) -> list[str]:
    return list(peer.allowed_ips) if peer.allowed_ips else list(peer_address(tunnel, peer, configuration))


def amnezia_uri(tunnel, peer, configuration, *, dns1: str | None = None, dns2: str | None = None, endpoint=None,
                description=None, mtu: int | None = None, subnet: str | None = None,
                server_public: str | None = None) -> str:
    """A ``vpn://`` document for one server peer, importable into the Amnezia app.

    ``dns1``/``dns2`` resolve the config's DNS placeholders. A peer without its own
    private key cannot be exported — the app needs it, and inventing one would
    be a silent mismatch. ``subnet`` lets a caller outside the panel's schema
    (the portal's device export) supply the container subnet the configuration
    object would otherwise be needed for.
    """
    if tunnel.protocol != 'awg' or tunnel.role != 'server':
        raise ValueError('amnezia.role_unsupported')
    if tunnel.listen_port is None:
        raise ValueError('amnezia.listen_port_required')
    if peer.private_key is None:
        raise ValueError('amnezia.peer_private_key_required')
    # The tunnel's own MTU field wins; a caller-provided value (legacy callers
    # passing the observed default) is the fallback. getattr: shim tunnel
    # objects outside the panel schema may not model the field.
    tunnel_mtu = getattr(tunnel, 'mtu', None)
    resolved_mtu = tunnel_mtu if tunnel_mtu is not None else (mtu if mtu is not None else DEFAULT_MTU)
    resolved, missing = client_endpoint(tunnel, configuration, endpoint)
    if missing or resolved is None:
        raise ValueError('amnezia.endpoint_unresolved')
    addresses = _client_addresses(tunnel, peer, configuration)
    if not addresses:
        raise ValueError('amnezia.address_required')
    # The container subnet is the tunnel's own network (the app pairs a /32
    # client_ip with the tunnel subnet), never the peer's /32. An explicit
    # ``subnet`` (portal export) replaces the configuration-derived one.
    if subnet is None:
        subnet = str(tunnel_addresses(tunnel, configuration)[0])
    subnet_net = ip_network(subnet, strict=False)
    client_private = reveal(peer.private_key)
    client_public = peer.public_key
    # The server public key is derived from the private key by the panel; a
    # caller outside the schema (the portal) passes the applied value instead.
    public = server_public if server_public is not None else server_public_key(tunnel)
    allowed = tuple(tunnel.allowed_ips) or DEFAULT_ALLOWED_IPS
    parameters = awg_parameters(tunnel)
    psk = reveal(peer.preshared_key) if peer.preshared_key else None
    dns1, dns2 = tunnel_dns(tunnel, configuration, dns1, dns2)

    conf = [
        '[Interface]',
        f'Address = {line(addresses[0])}',
        f'DNS = {DNS_PLACEHOLDER}',
        f'MTU = {resolved_mtu}',
        f'PrivateKey = {line(client_private)}',
        *obfuscation(tunnel),
        '', '[Peer]',
        f'PublicKey = {line(public)}',
    ]
    if psk is not None:
        conf.append(f'PresharedKey = {line(psk)}')
    conf += [f'AllowedIPs = {", ".join(map(line, allowed))}',
             f'Endpoint = {line(resolved)}',
             f'PersistentKeepalive = {tunnel.keepalive}']
    conf_text = '\n'.join(conf) + '\n'

    host = resolved.rsplit(':', 1)[0].strip('[]')
    last_config = {
        # The app's own last_config omits unset parameters (its outer awg block
        # keeps I1-I5); an empty signature key is unset, not a value.
        **{key: value for key, value in parameters.items() if value != ''},
        'allowed_ips': list(allowed),
        'clientId': client_public,
        'client_ip': str(ip_interface(addresses[0]).ip),
        'client_priv_key': client_private,
        'client_pub_key': client_public,
        'config': conf_text,
        'hostName': host,
        'mtu': str(resolved_mtu),
        'persistent_keep_alive': str(tunnel.keepalive),
        'port': tunnel.listen_port,
        'psk_key': psk,
        'server_pub_key': public,
    }
    awg = {
        **{key: parameters[key] for key in sorted(parameters)},
        'last_config': json.dumps(last_config, ensure_ascii=False),
        'port': str(tunnel.listen_port),
        'protocol_version': PROTOCOL_VERSION,
        'subnet_address': str(subnet_net.network_address),
        'subnet_cidr': str(subnet_net.prefixlen),
        'transport_proto': TRANSPORT_PROTO,
    }
    document = {
        'containers': [{'awg': awg, 'container': CONTAINER}],
        'defaultContainer': CONTAINER,
        'description': description or tunnel.name,
        'dns1': dns1,
        'dns2': dns2,
        'format_version': '1',
        'hostName': host,
    }
    return encode_document(document)
