"""Master subscriber exports from master-owned keys and exact node state."""
import io
import json
from ipaddress import ip_address, ip_network
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

from . import rulesets
from .accounts import current_account, get_db
from .models import Account, Node
from .device_service import device_owned, live_subscription, subscriber_state
from .portal_api import _client_factory

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
        obfuscation = dict(tunnel.get('obfuscation') or {})
        # Mirror the generator's RandomTrailers repair: exports must carry the
        # parameters the node actually runs (equalized S1-S4, no CPA), not the
        # raw stored ones — otherwise re-imported clients cannot handshake.
        if (tunnel.get('random_trailers')
                and all(name in obfuscation for name in ('S1', 'S2', 'S3', 'S4'))
                and all(isinstance(obfuscation[name], int) for name in ('S1', 'S2', 'S3', 'S4'))):
            equal = max(min(obfuscation[k] for k in ('S1', 'S2', 'S3', 'S4')), 12)
            for name in ('S1', 'S2', 'S3', 'S4'):
                obfuscation[name] = equal
            obfuscation.pop('ContentPaddingAddition', None)
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


def _host_port(tunnel):
    """Split the exported endpoint into host and port for a mihomo proxy."""
    endpoint = tunnel.get('endpoint')
    port = tunnel.get('listen_port')
    if not isinstance(endpoint, str) or not endpoint:
        raise APIError(503, 'portal.export_unavailable')
    if endpoint.startswith('['):
        host, _, rest = endpoint.partition(']')
        host = host[1:]
        if rest.startswith(':') and rest[1:].isdigit():
            port = int(rest[1:])
    elif endpoint.count(':') == 1:
        host, _, raw = endpoint.partition(':')
        if raw.isdigit():
            port = int(raw)
    else:
        host = endpoint
    if not host or not isinstance(port, int) or not 1 <= port <= 65535:
        raise APIError(503, 'portal.export_unavailable')
    return host, port


# mihomo spells the AmneziaWG 3+ parameters in lower case with dashes.
_MIHOMO_AWG_KEYS = {
    'Jc': 'jc', 'Jmin': 'jmin', 'Jmax': 'jmax',
    'S1': 's1', 'S2': 's2', 'S3': 's3', 'S4': 's4',
    'H1': 'h1', 'H2': 'h2', 'H3': 'h3', 'H4': 'h4',
    'I1': 'i1', 'I2': 'i2', 'I3': 'i3', 'I4': 'i4', 'I5': 'i5',
    'ContentPaddingAddition': 'content-padding-addition',
    'RekeyAfterTime': 'rekey-after-time', 'RekeyTimeout': 'rekey-timeout',
    'RejectAfterTime': 'reject-after-time', 'KeepaliveTimeout': 'keepalive-timeout',
    'MaxHandshakeAttempts': 'max-handshake-attempts',
}

_MIHOMO_PRIVATE = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8')


def _yaml_scalar(value):
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, int):
        return str(value)
    return json.dumps(_line(str(value)))


def _yaml_lines(node, indent=0):
    """Deterministic block-style YAML for the small shapes we emit.

    Values are JSON-escaped so keys and rules cannot break the document; no
    third-party YAML dependency is added to the master profile for one export.
    """
    pad = '  ' * indent
    lines = []
    for key, value in node.items():
        if isinstance(value, dict):
            if not value:
                lines.append(f'{pad}{key}: {{}}')
                continue
            lines.append(f'{pad}{key}:')
            lines.extend(_yaml_lines(value, indent + 1))
        elif isinstance(value, list):
            if not value:
                lines.append(f'{pad}{key}: []')
                continue
            lines.append(f'{pad}{key}:')
            for item in value:
                if isinstance(item, dict):
                    block = _yaml_lines(item, indent + 2)
                    block[0] = f'{pad}  - ' + block[0][len(pad) + 4:]
                    lines.extend(block)
                elif isinstance(item, list):
                    raise APIError(503, 'portal.export_unavailable')
                else:
                    lines.append(f'{pad}  - {_yaml_scalar(item)}')
        else:
            lines.append(f'{pad}{key}: {_yaml_scalar(value)}')
    return lines


def _awg_option(tunnel):
    """mihomo `amnezia-wg-option`; mirrors what the node actually runs."""
    obfuscation = dict(tunnel.get('obfuscation') or {})
    if not obfuscation:
        raise APIError(503, 'portal.export_unavailable')
    hp_key = tunnel.get('header_protection_key')
    if any(name in obfuscation for name in ('S3', 'S4', 'I1')) and not hp_key:
        raise APIError(503, 'portal.export_unavailable')
    option: dict[str, object] = {'version': 3}
    for name, key in _MIHOMO_AWG_KEYS.items():
        if name not in obfuscation:
            continue
        raw = obfuscation[name]
        if isinstance(raw, bool) or not isinstance(raw, (str, int)):
            raise APIError(503, 'portal.export_unavailable')
        text = str(raw)
        # Plain counters must be YAML integers; patterned values (e.g. "0-32")
        # stay strings. Never emit a boolean as a counter.
        option[key] = int(text) if text.isdigit() else text
    if hp_key:
        option['header-protection-key'] = _line(str(hp_key))
    if tunnel.get('random_trailers'):
        option['random-trailers'] = True
    if tunnel.get('disable_cookies'):
        option['disable-cookies'] = True
    return option


#: Order matters: the forced-tunnel lists must precede the Russian direct rules,
#: so a destination that appears in both (Telegram IPs published by RIPE as RU,
#: for example) still leaves abroad.
PROVIDER_SPECS = (
    ('domain', 'tg-domains', 'PROXY'),
    ('ipcidr', 'tg-ips', 'PROXY'),
    ('domain', 'ru-domains', 'DIRECT'),
    ('ipcidr', 'ru-ips', 'DIRECT'),
)


def _rule_providers(db, origin):
    """Published rule-sets as mihomo providers pinned to an exact version."""
    providers, rules = {}, []
    for kind, name, target in PROVIDER_SPECS:
        row = rulesets.current(db, kind, source=name)
        if row is None:
            continue
        providers[name] = {
            'type': 'http', 'behavior': kind,
            'url': f'{origin}/api/rulesets/{kind}/{row.version}.yaml',
            'path': f'./ruleset-{name}.yaml', 'interval': 86400}
        rules.append(f'RULE-SET,{name},{target}')
    return providers, rules


def _mihomo_yaml(device, tunnel, key, db=None):
    """mihomo (Clash Meta) profile: AWG tunnel plus a client-side RU split.

    The split is the contract: destinations in Russia resolve and leave through
    the subscriber's own provider, so no Russian-to-Russian traffic ever reaches
    a node. Everything else enters the tunnel.
    """
    if not isinstance(tunnel, dict) or not device.private_key or not device.allowed_ips:
        raise APIError(503, 'portal.export_unavailable')
    protocol = tunnel.get('protocol')
    if protocol not in ('wg', 'awg'):
        raise APIError(503, 'portal.export_unavailable')
    try:
        private = decrypt_secret(device.private_key, key)
    except (InvalidToken, ValueError):
        raise APIError(503, 'portal.export_unavailable') from None
    host, port = _host_port(tunnel)
    server_key = tunnel.get('public_key')
    allowed = tunnel.get('allowed_ips')
    dns_servers = tunnel.get('dns_servers')
    if not server_key or not allowed or not dns_servers:
        raise APIError(503, 'portal.export_unavailable')
    addresses = [str(value) for value in device.allowed_ips]
    v4 = next((value for value in addresses if ':' not in value), None)
    v6 = next((value for value in addresses if ':' in value), None)
    if v4 is None:
        raise APIError(503, 'portal.export_unavailable')

    proxy = {'name': 'vell', 'type': 'wireguard', 'server': _line(str(host)),
             'port': port, 'private-key': _line(private),
             'public-key': _line(str(server_key)), 'ip': _line(v4),
             'allowed-ips': [_line(str(value)) for value in allowed], 'udp': True}
    if v6 is not None:
        proxy['ipv6'] = _line(v6)
    # AWG junk/padding consumes headroom; the 1408 default black-holes large TLS
    # handshakes on common paths, so fall back to a safe value when the node is silent.
    proxy['mtu'] = int(tunnel['mtu']) if tunnel.get('mtu') else 1280
    proxy['persistent-keepalive'] = int(tunnel.get('keepalive') or 25)
    if protocol == 'awg':
        proxy['amnezia-wg-option'] = _awg_option(tunnel)
    if device.preshared_key:
        try:
            proxy['preshared-key'] = _line(decrypt_secret(device.preshared_key, key))
        except (InvalidToken, ValueError):
            raise APIError(503, 'portal.export_unavailable') from None

    # Two resolvers, two jobs. Russian names are resolved by the subscriber's own
    # provider (``system``) and never leave the country; everything else is
    # resolved by the tunnel's resolver, and ``respect-rules`` sends those queries
    # through the proxy, so the provider sees no plaintext DNS for foreign names.
    local_dns = ['77.88.8.8', '223.5.5.5']
    # The tunnel's own gateway is not a usable resolver on this node (queries to
    # it time out and add a multi-second stall to the first lookup), so it is
    # dropped when the node also publishes a public resolver.
    subnet = tunnel.get('subnet')
    resolvers = [str(value) for value in dns_servers]
    if subnet:
        try:
            inside = ip_network(subnet, strict=False)
        except ValueError:
            inside = None
        if inside is not None:
            kept = [value for value in resolvers
                    if not _in_network(value, inside)]
            if kept:
                resolvers = kept
    dns = {'enable': True, 'enhanced-mode': 'fake-ip',
           'fake-ip-range': '198.18.0.1/16',
           'ipv6': v6 is not None,
           'respect-rules': True,
           'default-nameserver': local_dns,
           'nameserver': [_line(str(value)) for value in resolvers],
           'proxy-server-nameserver': local_dns,
           'nameserver-policy': {'+.ru': ['system'], '+.su': ['system']},
           'fake-ip-filter': ['*.lan', '*.local', '+.ru', '+.su']}

    # Browsers with their own secure DNS connect to bare IPs; sniffing restores
    # the host name so the RU split still matches by domain instead of by IP.
    sniffer = {'enable': True, 'force-dns-mapping': True, 'parse-pure-ip': True,
               'override-destination': True,
               'sniff': {'HTTP': {'ports': [80, '8080-8880'], 'override-destination': True},
                         'TLS': {'ports': [443, 8443], 'override-destination': True},
                         'QUIC': {'ports': [443, 8443]}}}
    rules = ['GEOIP,RU,DIRECT']
    rules += [f'IP-CIDR,{value},DIRECT,no-resolve' for value in _MIHOMO_PRIVATE]
    # The tunnel is IPv4-only. Telegram's app connects to IPv6 data centres by
    # hard-coded address, so an unrouted :: would simply hang; rejecting it makes
    # the client fall back to IPv4 immediately instead of waiting.
    rules.append('IP-CIDR6,::/0,REJECT')
    rules.append('MATCH,PROXY')
    providers = {}
    origin = rulesets.public_url(db) if db is not None else None
    if origin:
        providers, published = _rule_providers(db, origin)
        rules = published + rules

    document = {
        'mode': 'rule',
        'log-level': 'info',
        # Keep IPv6 destinations inside the rule engine so the ::/0 reject below
        # can fail them fast; DNS still answers A records only.
        'ipv6': True,
        'proxies': [proxy],
        'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['vell']}],
        'rules': rules,
        'dns': dns,
        'sniffer': sniffer,
    }
    if providers:
        document['rule-providers'] = providers
    return '\n'.join(_yaml_lines(document)) + '\n'



def _in_network(value, network):
    """True when the (possible) resolver address belongs to ``network``."""
    try:
        return ip_address(str(value)) in network
    except ValueError:
        return False


def _qr_png(text):
    image = qrcode.make(text)
    out = io.BytesIO()
    image.save(out, 'PNG')
    return out.getvalue()



def _vless_link(device, inbound, node):
    """Client link for the node's subscriber inbound (ADR-0034).

    The device's UUID is derived from the public key both sides already hold, so
    no extra credential is stored or transferred; the dial address is the node's
    declared public entry, never the bridge address.
    """
    if not isinstance(inbound, dict) or not inbound.get('public_key'):
        raise APIError(409, 'portal.inbound_unavailable')
    entry = (node.public_entry or '').strip()
    if not entry:
        raise APIError(409, 'portal.entry_unavailable')
    host = entry.rsplit(':', 1)[0] if entry.count(':') == 1 else entry
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    try:
        from vs_router.generators.vless_uri import device_uuid, vless_uri
        from vs_router.schema import EncryptedSecret, Inbound

        uuid = device_uuid(device.public_key)
        shim = Inbound.model_construct(
            tag=inbound.get('tag') or 'vless',
            listen_port=int(inbound.get('listen_port') or 443),
            server_name=inbound['server_name'],
            handshake_dest='127.0.0.1:1',
            private_key=EncryptedSecret(ciphertext='gAAAAABm'),
            public_key=inbound['public_key'],
            short_ids=tuple(inbound.get('short_ids') or ()),
            flow=inbound.get('flow') or 'xtls-rprx-vision',
            users=(),
        )
        return vless_uri(shim, uuid, host, device.label or device.name)
    except (KeyError, TypeError, ValueError):
        raise APIError(409, 'portal.inbound_unavailable') from None


def device_export(db, account, identity, format, now, node_client_factory):
    """Guarded shared export: bytes, media type, and filename; never a message."""
    if format not in ('conf', 'qr', 'amnezia', 'amnezia-qr', 'mihomo', 'vless', 'vless-qr'):
        raise APIError(422, 'portal.export_format')
    live_subscription(db, account.id, now)
    device = device_owned(db, identity, account.id)
    node = db.get(Node, device.node_id)
    if node is None:
        raise APIError(503, 'portal.export_unavailable')
    try:
        state = subscriber_state(node_client_factory, node, device.node_subscriber)
    except APIError:
        raise APIError(503, 'portal.export_unavailable') from None
    tunnel = state.get('tunnel')
    key = get_secret_key()
    filename = device.name or f'device-{device.id}'
    if format in ('vless', 'vless-qr'):
        link = _vless_link(device, state.get('inbound'), node)
        if format == 'vless-qr':
            return _qr_png(link), 'image/png', f'{filename}-vless.png'
        return link.encode(), 'text/plain; charset=utf-8', f'{filename}-vless.txt'
    if format == 'qr':
        return _qr_png(_conf_text(device, tunnel, key)), 'image/png', f'{filename}.png'
    if format in ('amnezia', 'amnezia-qr'):
        if not isinstance(tunnel, dict):
            raise APIError(503, 'portal.export_unavailable')
        uri = _amnezia_uri(device, tunnel, key, device.node_subscriber)
        if format == 'amnezia-qr':
            # Amnezia adds a connection by scanning the vpn:// container.
            return _qr_png(uri), 'image/png', f'{filename}-amnezia.png'
        return uri.encode(), 'text/plain; charset=utf-8', f'{filename}-amnezia.txt'
    if format == 'mihomo':
        return (_mihomo_yaml(device, tunnel, key, db).encode(), 'application/yaml; charset=utf-8',
                f'{filename}.yaml')
    return (_conf_text(device, tunnel, key).encode(), 'text/plain; charset=utf-8',
            f'{filename}.conf')


@router.get('/devices/{identity}/export')
def export_device(identity: str, request: Request, format: str = Query('conf'),
                  account: Account = Depends(current_account), db: Session = Depends(get_db)):
    content, media_type, filename = device_export(
        db, account, identity, format, request.app.state.portal_auth.now(), _client_factory(request))
    headers = {'Cache-Control': 'no-store'}
    if format not in ('qr', 'amnezia-qr'):
        headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return Response(content, media_type=media_type, headers=headers)
