"""Bounded subscription parsing. No network, no plaintext secrets in results.

Clash YAML support is intentionally the common `proxies:` list of flat scalar maps;
anchors, aliases, nested objects and custom tags fail closed (no YAML dependency).
Python re is NOT RE2: reject lookaround/backrefs/conditionals/atomic groups,
limit pattern and label lengths; pathological nested quantifiers are rejected.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, parse_qs

from ..schema import EncryptedSecret, ProxyOutbound, ProxyGroup, ProxySubscription
from ..secrets import encrypt_secret
from .downloader import DEFAULT_MAX_BYTES

MAX_MEMBERS = 2000


class SubscriptionParseError(ValueError):
    def __init__(self, code: str, line: int | None = None):
        self.code, self.line = code, line
        super().__init__(f"{code} (line {line})" if line is not None else code)


@dataclass(frozen=True)
class Member:
    tag: str
    label: str
    protocol: str
    server: str
    port: int
    sni: str | None
    transport: str
    security: str
    secret: EncryptedSecret
    method: str | None = None
    tls_insecure: bool = False
    transport_options: dict | None = None
    reality_public_key: str | None = None
    reality_short_id: str | None = None
    username: str | None = None


@dataclass(frozen=True)
class Parsed:
    members: tuple[Member, ...]
    skipped: tuple[dict, ...] = ()


def _b64(text: str) -> str:
    raw = text.strip().replace('-', '+').replace('_', '/')
    if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', raw) or len(raw.rstrip('=')) % 4 == 1:
        raise SubscriptionParseError('subscription.invalid_base64')
    try:
        return base64.b64decode(raw + '=' * (-len(raw) % 4), validate=True).decode('utf-8')
    except (ValueError, UnicodeError) as exc:
        raise SubscriptionParseError('subscription.invalid_base64') from exc


def _member(protocol: str, server: str, port: object, password: str, label: str,
            *, key: bytes, sni: str | None = None, transport: str = 'tcp',
            security: str = 'none', method: str | None = None,
            tls_insecure: bool = False, line: int | None = None,
            transport_options: dict | None = None, reality_public_key: str | None = None,
            reality_short_id: str | None = None, username: str | None = None) -> Member:
    if protocol not in {'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'naive', 'mieru'}:
        raise SubscriptionParseError('subscription.unsupported_protocol', line)
    if not isinstance(server, str) or not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]{1,253}', server) or not isinstance(password, str) or not password or len(password) > 8192:
        raise SubscriptionParseError('subscription.invalid_member', line)
    try:
        port_number = int(port)
    except (ValueError, TypeError) as exc:
        raise SubscriptionParseError('subscription.invalid_port', line) from exc
    if not 1 <= port_number <= 65535 or isinstance(port, bool):
        raise SubscriptionParseError('subscription.invalid_port', line)
    if transport not in {'tcp', 'ws', 'grpc', 'http', 'httpupgrade'} or security not in {'none', 'tls'}:
        raise SubscriptionParseError('subscription.unsupported_transport', line)
    if protocol == 'shadowsocks' and not method:
        raise SubscriptionParseError('subscription.invalid_member', line)
    if protocol in {'naive', 'mieru'} and not isinstance(username, str):
        raise SubscriptionParseError('subscription.invalid_member', line)
    identity_parts = [protocol, server.lower(), port_number, password, method]
    if username is not None:
        identity_parts.append(username)
    identity = json.dumps(identity_parts, separators=(',', ':'), ensure_ascii=False)
    tag = 'sub_' + hashlib.sha256(identity.encode()).hexdigest()[:24]
    return Member(tag, str(label or server)[:256], protocol, server, port_number,
                  sni, transport, security, encrypt_secret(password, key), method, tls_insecure,
                  transport_options, reality_public_key, reality_short_id, username)


def _share(raw: str, key: bytes, line: int) -> Member:
    try:
        url = urlsplit(raw)
        scheme = url.scheme.lower()
        if scheme == 'ss':
            if url.query:
                raise SubscriptionParseError('subscription.unsupported_plugin', line)
            body = raw[5:].split('#', 1)[0]
            at = body.rfind('@')
            if at < 0:
                body = _b64(body)
                at = body.rfind('@')
            if at < 0:
                raise SubscriptionParseError('subscription.invalid_member', line)
            credential, hostport = body[:at], body[at + 1:]
            if ':' not in credential:
                credential = _b64(credential)
            method, password = credential.split(':', 1)
            target = urlsplit('ss://' + hostport)
            return _member('shadowsocks', target.hostname or '', target.port, unquote(password),
                           unquote(url.fragment) or target.hostname or '', key=key, method=method, line=line)
        if scheme not in {'vless', 'trojan', 'hysteria2', 'tuic'}:
            raise SubscriptionParseError('subscription.unsupported_protocol', line)
        q = parse_qs(url.query)
        if any(k in q for k in ('plugin', 'flow', 'obfs', 'reality')):
            raise SubscriptionParseError('subscription.unsupported_transport', line)
        transport = q.get('type', ['tcp'])[0]
        security = q.get('security', ['tls' if scheme != 'vless' else 'none'])[0]
        if security not in {'none', 'tls'}:
            raise SubscriptionParseError('subscription.unsupported_transport', line)
        password = unquote(url.username or '')
        if scheme == 'tuic':
            password += ':' + unquote(url.password or '')
            if not url.password:
                raise SubscriptionParseError('subscription.invalid_member', line)
        return _member(scheme, url.hostname or '', url.port, password,
                       unquote(url.fragment) or url.hostname or '', key=key,
                       sni=q.get('sni', q.get('peer', [None]))[0], transport=transport,
                       security=security, line=line)
    except SubscriptionParseError as exc:
        raise SubscriptionParseError(exc.code, line) from None
    except (ValueError, IndexError) as exc:
        raise SubscriptionParseError('subscription.invalid_member', line) from exc


def _object(row: dict, key: bytes, line: int | None = None) -> Member:
    protocol = row.get('type') or row.get('protocol')
    if not isinstance(protocol, str):
        raise SubscriptionParseError('subscription.invalid_member', line)
    protocol = {'ss': 'shadowsocks'}.get(protocol, protocol)
    tls = row.get('tls', False)
    reality = None
    if isinstance(tls, dict):
        sni = tls.get('server_name') or row.get('sni')
        insecure = bool(tls.get('insecure', False))
        reality = tls.get('reality')
        tls = tls.get('enabled', True)
    else:
        sni = row.get('sni') or row.get('servername') or row.get('tls_server_name')
        insecure = False
    if reality is not None and (not isinstance(reality, dict) or not reality.get('public_key')):
        raise SubscriptionParseError('subscription.invalid_member', line)
    raw_transport = row.get('transport', 'tcp')
    transport = raw_transport.get('type', 'tcp') if isinstance(raw_transport, dict) else raw_transport
    if not isinstance(transport, str):
        raise SubscriptionParseError('subscription.unsupported_transport', line)
    options = None
    if isinstance(raw_transport, dict) and transport in {'ws', 'grpc', 'http', 'httpupgrade'}:
        # Only fields understood by sing-box are forwarded to materialization.
        allowed = {'ws': ('path', 'headers', 'max_early_data', 'early_data_header_name'),
                   'grpc': ('service_name', 'idle_timeout', 'ping_timeout', 'permit_without_stream'),
                   'http': ('host', 'path', 'method', 'headers'),
                   'httpupgrade': ('host', 'path', 'headers')}
        options = {'type': transport, **{k: raw_transport[k] for k in allowed[transport] if k in raw_transport}}
    username = row.get('username') if protocol in {'naive', 'mieru'} else None
    return _member(protocol, row.get('server') or row.get('add'),
                   row.get('server_port', row.get('port')), row.get('password') or row.get('uuid') or row.get('id') or '',
                   row.get('name') or row.get('tag') or row.get('ps'), key=key,
                   sni=sni, transport=transport, security='tls' if tls else 'none',
                   method=row.get('method') or row.get('cipher'), tls_insecure=insecure, line=line,
                   transport_options=options,
                   reality_public_key=reality.get('public_key') if reality else None,
                   reality_short_id=reality.get('short_id') if reality else None,
                   username=username)


def _clash(content: str) -> list[tuple[int, dict]]:
    rows: list[tuple[int, dict]] = []
    started = False
    for line, raw in enumerate(content.splitlines(), 1):
        if not started:
            if raw.strip() == 'proxies:':
                started = True
            continue
        if raw and not raw[0].isspace() and not raw.startswith('#'):
            break
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('- '):
            rows.append((line, {}))
            stripped = stripped[2:].strip()
        if not rows or ':' not in stripped or stripped.startswith(('!', '&', '*', '[', '{')):
            raise SubscriptionParseError('subscription.invalid_yaml', line)
        field, value = stripped.split(':', 1)
        value = value.strip()
        if not re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9-]*', field) or value.startswith(('!', '&', '*', '[', '{', '|', '>')):
            raise SubscriptionParseError('subscription.invalid_yaml', line)
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise SubscriptionParseError('subscription.invalid_yaml', line)
            value = value[1:-1]
        rows[-1][1][field] = value
    return rows


def _json_member(row: dict, key: bytes, index: int) -> Member:
    if row.get('type') in {'direct', 'block', 'selector', 'urltest'}:
        raise SubscriptionParseError('non_server', index)
    # Xray/V2Ray: outbound protocol + settings.vnext/servers.
    settings = row.get('settings')
    if isinstance(settings, dict):
        targets = settings.get('vnext') or settings.get('servers')
        if isinstance(targets, list) and targets and isinstance(targets[0], dict):
            target = targets[0]
            users = target.get('users') or [{}]
            user = users[0] if isinstance(users, list) and users and isinstance(users[0], dict) else {}
            stream = row.get('streamSettings') or {}
            if not isinstance(stream, dict):
                raise SubscriptionParseError('subscription.invalid_member', index)
            tls = stream.get('tlsSettings') or {}
            row = {'type': row.get('protocol'), 'server': target.get('address') or target.get('server'),
                   'port': target.get('port'), 'password': target.get('password') or user.get('id') or user.get('password'),
                   'name': row.get('tag'), 'method': target.get('method'),
                   'tls': stream.get('security') == 'tls',
                   'sni': tls.get('serverName') if isinstance(tls, dict) else None,
                   'transport': stream.get('network', 'tcp')}
    return _object(row, key, index)


def parse_body(content: str, *, key: bytes) -> Parsed:
    """Parse bounded body; key is caller-owned Fernet key, never returned."""
    if not isinstance(content, str) or len(content.encode('utf-8')) > DEFAULT_MAX_BYTES:
        raise SubscriptionParseError('subscription.too_large')
    text = content.strip()
    if text and not any(x in text for x in ('://', 'proxies:', '{', '[')):
        try:
            decoded = _b64(''.join(text.split()))
            if '://' in decoded or decoded.lstrip().startswith(('{', 'proxies:')):
                text = decoded
        except SubscriptionParseError:
            pass
    members: list[Member] = []
    skipped: list[dict] = []
    if text.startswith(('{', '[')):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise SubscriptionParseError('subscription.invalid_json') from exc
        if isinstance(data, dict):
            if isinstance(data.get('outbounds'), list) or isinstance(data.get('endpoints'), list):
                rows = []
                for field in ('outbounds', 'endpoints'):
                    value = data.get(field)
                    if isinstance(value, list):
                        rows.extend(value)
            elif isinstance(data.get('servers'), list):
                rows = data['servers']
            elif isinstance(data.get('vnext'), list):
                rows = [dict(type='vless', server=r.get('address'), port=r.get('port'),
                             uuid=(r.get('users') or [{}])[0].get('id')) for r in data['vnext']]
            else:
                raise SubscriptionParseError('subscription.invalid_json')
        elif isinstance(data, list):
            rows = data
        else:
            raise SubscriptionParseError('subscription.invalid_json')
        if len(rows) > MAX_MEMBERS:
            raise SubscriptionParseError('subscription.too_many_members')
        for index, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                skipped.append({'line': index, 'reason': 'subscription.invalid_member'})
                continue
            try:
                members.append(_json_member(row, key, index))
            except SubscriptionParseError as exc:
                skipped.append({'line': index, 'reason': exc.code})
    elif re.search(r'^proxies:\s*$', text, re.M):
        for line, row in _clash(text):
            try:
                members.append(_object(row, key, line))
            except SubscriptionParseError as exc:
                skipped.append({'line': line, 'reason': exc.code})
    else:
        for line, raw in enumerate(text.splitlines(), 1):
            raw = raw.strip()
            if not raw or raw.startswith('#'):
                continue
            if len(members) + len(skipped) >= MAX_MEMBERS:
                raise SubscriptionParseError('subscription.too_many_members')
            if raw.lower().startswith('vmess://'):
                skipped.append({'line': line, 'reason': 'vmess_unsupported'})
                continue
            members.append(_share(raw, key, line))
        if not members and not skipped:
            raise SubscriptionParseError('subscription.empty')
    if len(members) + len(skipped) > MAX_MEMBERS:
        raise SubscriptionParseError('subscription.too_many_members')
    # Repeated identical links are one member; never use input ordering for identity.
    return Parsed(tuple({m.tag: m for m in members}.values()), tuple(skipped))


def _pattern(value: str | None):
    if not value:
        return None
    if len(value) > 256 or re.search(r'\(\?(?:[=!<P>]|\()', value) or re.search(r'\\[1-9]|\\[gk]', value) or re.search(r'\([^)]*[+*][^)]*\)[+*{]', value):
        raise SubscriptionParseError('subscription.filter_not_re2')
    try:
        return re.compile(value)
    except re.error as exc:
        raise SubscriptionParseError('subscription.filter_invalid') from exc


def materialize(subscription: ProxySubscription, members: tuple[Member, ...] | list[Member]) -> tuple[list[ProxyOutbound], list[ProxyGroup]]:
    """Filtered outbounds and single subscription group. Empty groups omitted."""
    include, exclude = _pattern(subscription.filter_include), _pattern(subscription.filter_exclude)
    selected = [m for m in members if m.tag not in subscription.excluded_members
                and (include is None or include.search(m.label))
                and (exclude is None or not exclude.search(m.label))]
    outbounds = [ProxyOutbound(tag=m.tag, type=m.protocol, server=m.server, port=m.port,
                               secret=m.secret, method=m.method, tls=m.security == 'tls',
                               tls_server_name=m.sni, tls_insecure=m.tls_insecure,
                               transport=m.transport_options or ({'type': m.transport} if m.transport != 'tcp' else None),
                               reality_public_key=m.reality_public_key,
                               reality_short_id=m.reality_short_id, username=m.username) for m in selected]
    if not outbounds:
        return outbounds, []
    tags = [o.tag for o in outbounds]
    if subscription.mode == 'selector' and subscription.active_member in tags:
        tags.remove(subscription.active_member)
        tags.insert(0, subscription.active_member)
    group = ProxyGroup(tag=subscription.name, type=subscription.mode, outbounds=tuple(tags),
                       url=subscription.url_test if subscription.mode == 'urltest' else None,
                       interval_minutes=subscription.test_interval_minutes if subscription.mode == 'urltest' else None,
                       tolerance_ms=subscription.test_tolerance_ms if subscription.mode == 'urltest' else None)
    return outbounds, [group]
