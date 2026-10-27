"""Secret-authenticated, narrowly scoped portal bridge to the panel apply cycle."""
import json
import os
import secrets
from datetime import datetime, timezone
from ipaddress import ip_interface, ip_network
from typing import Literal

from fastapi import Body, Depends, FastAPI, Header, Request
from pydantic import Field
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_portal.errors import install_errors
from vs_portal.models import make_engine

from .agent.rpc import ApplyParams, EmptyParams
from .api import versions
from .api.errors import APIError
from .api.keygen import generate_peer_key, generate_peer_keypair
from .db import ConfigurationRow
from .generators.amnezia import tunnel_dns
from .generators.wireguard import client_endpoint, materialize_addresses, peer_address, server_public_key, tunnel_addresses
from .schema import Configuration, EncryptedSecret, Model, Peer
from .secrets import decrypt_secret, encrypt_secret


class DeviceOperation(Model):
    op: Literal['create', 'delete', 'activate', 'deactivate']
    device_id: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, min_length=1, max_length=128)
    keys: dict | None = None
    tunnel: str | None = None


class TokenRotate(Model):
    """Master-generated replacement bearer token (ADR-0035 D2)."""
    new_token: str = Field(min_length=16, max_length=128)


def read_internal_secret():
    from vs_portal.internal import read_internal_secret as read_secret
    try:
        return read_secret()
    except APIError:
        return ''


def _auth(request: Request, x_vs_portal_secret: str | None = Header(default=None)):
    expected = read_internal_secret()
    supplied = x_vs_portal_secret or ''
    if not supplied:
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            supplied = auth[len('Bearer '):].strip()
    if not expected or not supplied:
        raise APIError(403, 'auth.forbidden')
    if secrets.compare_digest(expected, supplied):
        return
    # The master authenticates with its long-lived bearer token (ADR-0035 D2);
    # the previous generation stays valid only until the master confirms rotation.
    with Session(request.app.state.portal_engine) as portal:
        current, previous = _read_master_tokens(portal)
    for candidate in (current, previous):
        if candidate and secrets.compare_digest(candidate, supplied):
            return
    raise APIError(403, 'auth.forbidden')


MASTER_TOKEN_KEY = 'master_bridge_token'


def _read_master_tokens(portal):
    from vs_portal.models import Setting
    row = portal.get(Setting, MASTER_TOKEN_KEY)
    if row is None:
        return '', ''
    try:
        data = json.loads(row.value)
    except ValueError:
        return '', ''
    current = _stored(data.get('current')) or ''
    previous = (_stored(data.get('previous')) or '') if data.get('previous') else ''
    return current, previous


def _write_master_tokens(portal, current, previous):
    from vs_portal.models import Setting
    value = json.dumps({'current': _encrypt(current).model_dump(mode='json'),
                        'previous': _encrypt(previous).model_dump(mode='json') if previous else None})
    row = portal.get(Setting, MASTER_TOKEN_KEY)
    if row is None:
        row = Setting(key=MASTER_TOKEN_KEY, value=value)
        portal.add(row)
    else:
        row.value = value
    portal.commit()


def _db(request: Request):
    with Session(request.app.state.engine) as db:
        yield db


def _portal_db(request: Request):
    with Session(request.app.state.portal_engine) as db:
        yield db


def _models():
    from vs_portal.models import Device, Subscription, Tariff
    return Device, Subscription, Tariff


def _confirmed(db):
    return db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                     .order_by(ConfigurationRow.id.desc()))


def _context(name, db, portal):
    Device, Subscription, Tariff = _models()
    row = _confirmed(db)
    if row is None or name not in {s.name for s in row.configuration.subscribers}:
        raise APIError(404, 'subscriber.not_found')
    subscription = portal.get(Subscription, name)
    devices = list(portal.scalars(select(Device).where(Device.subscriber_name == name).order_by(Device.id)))
    return row, subscription, devices


def _key():
    value = os.environ.get('VS_ROUTER_SECRET_KEY', '').encode()
    if not value:
        raise APIError(503, 'secret.unavailable')
    return value


def _stored(secret):
    if secret is None:
        return None
    from .schema import EncryptedSecret
    return decrypt_secret(EncryptedSecret.model_validate(secret), _key())


def _encrypt(value):
    return encrypt_secret(value, _key())


def _peer(device):
    return Peer(name=device.name, subscriber=device.subscriber_name,
                public_key=device.public_key,
                private_key=device.private_key, preshared_key=device.preshared_key,
                allowed_ips=tuple(device.allowed_ips or ()))


def _device_result(device):
    return {'id': device.id, 'name': device.name, 'label': device.label,
            'tunnel': device.tunnel_name,
            'private_key': _stored(device.private_key), 'public_key': device.public_key,
            'preshared_key': _stored(device.preshared_key),
            'allowed_ips': list(device.allowed_ips or ())}


def _active(subscription):
    return (subscription is not None and subscription.status == 'active'
            and subscription.expires_at > datetime.now(timezone.utc))


def _tunnel(configuration, name, preferred=None):
    # An explicitly bound tunnel wins (the device records its creation tunnel);
    # otherwise existing subscriber peers determine the server, then the sole server.
    servers = [t for t in configuration.tunnels if t.role == 'server']
    if not servers:
        raise APIError(409, 'portal.tunnel_unavailable')
    if preferred is not None:
        named = [t for t in servers if t.name == preferred]
        if named:
            return named[0]
    bound = [t for t in servers if any(p.subscriber == name for p in t.peers)]
    if len(bound) > 1 or (not bound and len(servers) != 1):
        raise APIError(409, 'portal.tunnel_ambiguous')
    return (bound or servers)[0]


def _build(configuration, tunnel, peers, removed):
    updated = tunnel.model_copy(update={'peers': tuple(peers)})
    return Configuration.model_validate(configuration.model_dump(mode='json') | {
        'tunnels': [updated.model_dump(mode='json') if t.name == tunnel.name else t.model_dump(mode='json')
                    for t in configuration.tunnels],
        'routing_rules': [r.model_dump(mode='json') for r in configuration.routing_rules
                          if not (r.subject.kind == 'device' and r.subject.subscriber in removed
                                  and r.subject.peer in removed[r.subject.subscriber])],
    })


def _restore_policy(db, configuration, peers, previous_peers):
    """Restore suspended device policy from its last confirmed presence.

    Removing a peer temporarily makes device selectors invalid. Their source
    remains in immutable confirmed history; reactivation must not silently turn
    a formerly blocked/routed device into unrestricted direct traffic.
    """
    old = {(p.subscriber, p.name, p.public_key): p for p in previous_peers}
    pending = {(p.subscriber, p.name, p.public_key) for p in peers if p.subscriber} - old.keys()
    modes = {key: peer.dns_mode for key, peer in old.items()}
    rules = list(configuration.routing_rules)
    for version in db.scalars(select(ConfigurationRow).where(ConfigurationRow.status == 'confirmed')
                             .order_by(ConfigurationRow.id.desc())):
        if not pending:
            break
        history = version.configuration
        found = {(p.subscriber, p.name, p.public_key): p for t in history.tunnels for p in t.peers
                 if (p.subscriber, p.name, p.public_key) in pending}
        if not found:
            continue
        owners = {(subscriber, name) for subscriber, name, _ in found}
        modes.update({key: peer.dns_mode for key, peer in found.items()})
        for index in range(len(history.routing_rules) - 1, -1, -1):
            rule = history.routing_rules[index]
            if rule.subject.kind != 'device' or (rule.subject.subscriber, rule.subject.peer) not in owners:
                continue
            existing = next((item for item in rules if item.name == rule.name), None)
            if existing is not None:
                if existing != rule:
                    raise APIError(409, 'portal.device_policy_conflict')
                continue
            anchors = {item.name for item in history.routing_rules[index + 1:]}
            position = next((i for i, item in enumerate(rules) if item.name in anchors), len(rules))
            rules.insert(position, rule)
        pending.difference_update(found)
    peers = [p.model_copy(update={'dns_mode': modes.get((p.subscriber, p.name, p.public_key), p.dns_mode)})
             for p in peers]
    return peers, tuple(rules)


def _allocate(configuration, tunnel, device, devices):
    # Reserve every portal allocation, including expired/inactive devices missing
    # from the currently installed configuration; never recycle their /32.
    reserved = [p for p in tunnel.peers if p.name != device.name]
    for other in devices:
        if other.id != device.id and other.allowed_ips and other.name not in {p.name for p in reserved}:
            reserved.append(_peer(other))
    candidate = _peer(device)
    synthetic = tunnel.model_copy(update={'peers': tuple([*reserved, candidate])})
    if not device.allowed_ips:
        address = peer_address(synthetic, candidate, configuration)
        device.allowed_ips = address
    proposed = tuple(device.allowed_ips)
    occupied = {str(ip_network(cidr, strict=False)) for p in reserved for cidr in p.allowed_ips}
    if any(str(ip_network(cidr, strict=False)) in occupied for cidr in proposed):
        raise APIError(409, 'wireguard.address_collision')
    return _peer(device)


def _apply(db, original, configuration):
    configuration = materialize_addresses(configuration)
    row = ConfigurationRow(id=(db.scalar(select(func.max(ConfigurationRow.id))) or 0) + 1,
                           status='draft', profile=original.profile, configuration=configuration)
    db.add(row)
    db.commit()  # Agent opens its own DB connection to fetch the draft.
    try:
        result = versions.apply(ApplyParams(version_id=row.id), db)
        if result.get('status') not in ('confirmed', 'pending'):
            raise APIError(409, 'apply.failed')
        return 'applied' if result['status'] == 'confirmed' else 'pending'
    except APIError as exc:
        db.rollback()
        own = db.get(ConfigurationRow, row.id)
        if own is not None and own.status == 'draft':
            db.delete(own)
            db.commit()
        if exc.code == 'agent.apply_pending':
            raise APIError(409, 'apply.busy') from exc
        raise
    except Exception:
        # Delete only the draft we inserted; never touch an admin-created row.
        db.rollback()
        own = db.get(ConfigurationRow, row.id)
        if own is not None and own.status == 'draft':
            db.delete(own)
            db.commit()
        raise


def _mutate(name, action, db, portal, body=None):
    Device, Subscription, Tariff = _models()
    try:
        db.execute(text('BEGIN IMMEDIATE'))
        row, subscription, devices = _context(name, db, portal)
        op = body.op if action == 'device' else action
        if op in ('create', 'activate', 'renew') and not _active(subscription):
            raise APIError(403, 'portal.subscription_expired')
        if db.scalar(select(ConfigurationRow.id).where(ConfigurationRow.status == 'draft')) is not None:
            raise APIError(409, 'apply.busy')
        marker = versions.agent_call('status', EmptyParams())
        if isinstance(marker, dict) and marker.get('status') not in ('confirmed', 'rolled_back', 'failed', 'rollback_failed'):
            raise APIError(409, 'apply.busy')
        config = row.configuration
        reservations = list(portal.scalars(select(Device).where(Device.status != 'removed')))
        # The device's recorded creation tunnel (or an explicit hint) resolves
        # ambiguity; the peer-binding heuristics stay as the fallback.
        preferred = body.get('tunnel') if isinstance(body, dict) else None
        if action == 'device' and body is not None and body.tunnel:
            preferred = body.tunnel
        if action == 'renew' or (action == 'expire' and preferred is None):
            preferred = next((d.tunnel_name for d in devices
                              if d.status != 'removed' and d.tunnel_name), None)
        tunnel = _tunnel(config, name, preferred)
        peers = list(tunnel.peers)
        device = None
        if action == 'device':
            if body.device_id is not None:
                device = next((d for d in devices if d.id == body.device_id), None)
                if device is None:
                    raise APIError(404, 'device.not_found')
            elif op == 'create':
                device = Device(subscriber_name=name, name='portal_pending', label=body.label or 'Устройство',
                                status='active', allowed_ips=[])
                portal.add(device)
                portal.flush()
                devices.append(device)
            else:
                raise APIError(422, 'device.id_required')
            if op == 'create':
                if device.status == 'removed':
                    raise APIError(409, 'device.removed')
                device.name = f'portal_{device.id}'
                device.tunnel_name = tunnel.name
                if not device.private_key:
                    pair = generate_peer_keypair()
                    device.private_key = _encrypt(pair['private_key'])
                    device.public_key = pair['public_key']
                    device.preshared_key = _encrypt(generate_peer_key()['preshared_key'])
                if body.keys and (any(body.keys.get(k) != value for k, value in
                                      [('private_key', _stored(device.private_key)),
                                       ('public_key', device.public_key),
                                       ('preshared_key', _stored(device.preshared_key))]
                                      if k in body.keys)
                                  or ('allowed_ips' in body.keys and body.keys['allowed_ips']
                                      and device.allowed_ips and body.keys['allowed_ips'] != device.allowed_ips)):
                    raise APIError(409, 'device.keys_mismatch')
                if body.label:
                    device.label = body.label
                existing = next((p for p in peers if p.name == device.name), None)
                if existing is not None and (existing.subscriber != name or existing.public_key != device.public_key):
                    raise APIError(409, 'device.name_conflict')
                peer = _allocate(config, tunnel, device, reservations)
                if existing is None:
                    peers.append(peer)
            else:
                if device.status == 'removed' and op != 'delete':
                    raise APIError(404, 'device.not_found')
                if op == 'activate':
                    device.tunnel_name = device.tunnel_name or tunnel.name
                    peer = _allocate(config, tunnel, device, reservations)
                    peers = [p for p in peers if not (p.name == device.name and p.subscriber == name)]
                    peers.append(peer)
                elif op in ('delete', 'deactivate'):
                    peers = [p for p in peers if not (p.name == device.name and p.subscriber == name)]
        elif op == 'expire':
            peers = [p for p in peers if p.subscriber != name]
        else:  # renew preserves desired inactive devices and addresses.
            peers = [p for p in peers if p.subscriber != name]
            for device in devices:
                if device.status == 'active':
                    peers.append(_allocate(config, tunnel, device, reservations))
        changed = tuple(peers) != tunnel.peers
        if not changed:
            db.rollback()
            portal.commit()
            return {'status': 'applied', **({'device': _device_result(device)} if device else {})}
        # Remove device-scoped routes whose peer is removed; otherwise schema
        # validation rejects the whole configuration as a dangling reference.
        removed = {p.name for p in tunnel.peers if p.subscriber == name and p.name not in {q.name for q in peers}}
        configuration = _build(config, tunnel, peers, {name: removed})
        # Persist material before the agent can mutate host state: retry keeps
        # identical private/preshared keys and /32 even after a failed apply.
        portal.commit()
        status = _apply(db, row, configuration)
        return {'status': status, **({'device': _device_result(device)} if device else {})}
    except (IntegrityError, OperationalError) as exc:
        db.rollback()
        portal.rollback()
        raise APIError(409, 'apply.busy') from exc
    except Exception:
        db.rollback()
        portal.rollback()
        raise


def create_internal_app(engine=None, *, database_url=None, portal_engine=None):
    app = FastAPI(title='vs-router-internal', docs_url=None, redoc_url=None, openapi_url=None)
    if engine is None:
        url = database_url or os.environ.get('VS_ROUTER_DATABASE_URL', 'sqlite:///vs-router.db')
        opts = {'connect_args': {'check_same_thread': False}} if url.startswith('sqlite:') else {}
        if url in ('sqlite://', 'sqlite:///:memory:'):
            opts['poolclass'] = StaticPool
        engine = create_engine(url, **opts)
    if portal_engine is None:
        portal_engine = make_engine()
    app.state.engine = engine
    app.state.portal_engine = portal_engine
    install_errors(app)

    @app.middleware('http')
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/internal/portal/subscribers/{name}/state', dependencies=[Depends(_auth)])
    def state(name: str, tunnel: str | None = None, db: Session = Depends(_db),
              portal: Session = Depends(_portal_db)):
        # A subscriber with no devices yet must still activate and list devices:
        # the first device is created by the subscriber in the portal, so tunnel
        # resolution is deferred until a device (with its tunnel_name) exists.
        # The explicit `tunnel` query (device export) forces one resolution.
        row, subscription, devices = _context(name, db, portal)
        config = row.configuration
        live_devices = [d for d in devices if d.status != 'removed']
        servers = {t.name: t for t in config.tunnels if t.role == 'server'}

        def resolve(preferred):
            if preferred is not None and preferred in servers:
                return servers[preferred]
            return _tunnel(config, name, preferred)

        if tunnel is not None:
            resolved = resolve(tunnel)
            selected = {resolved.name: resolved}
        elif live_devices:
            selected = {}
            for device in live_devices:
                resolved = resolve(device.tunnel_name)
                selected.setdefault(resolved.name, resolved)
        else:
            selected = {}
        peers_by_name = {p.name: p for t in selected.values() for p in t.peers if p.subscriber == name}
        try:
            live = versions.agent_call('tunnel_activity', {})
        except APIError:
            live = {}
        handshakes = {}
        for t in selected.values():
            activity = live.get(t.interface, []) if isinstance(live, dict) else []
            if isinstance(activity, list):
                handshakes.update({p.get('public_key'): p.get('latest_handshake')
                                   for p in activity if isinstance(p, dict)})
        if len(selected) == 1:
            tunnel_row = next(iter(selected.values()))
            endpoint, _ = client_endpoint(tunnel_row, config)
            if endpoint is None:
                # The config cannot derive an endpoint (DHCP WAN without a
                # lease, no explicit tunnel endpoint). Fall back to the live
                # WAN address the agent reads from the host, so device export
                # works on NAT/DHCP hosts without pinning an endpoint by hand.
                try:
                    live_addresses = versions.agent_call('list_addresses', {})
                except APIError:
                    live_addresses = {}
                if isinstance(live_addresses, dict):
                    wan_address = next((ip_interface(address).ip
                                        for interface in config.interfaces
                                        if interface.zone == 'wan'
                                        for address in live_addresses.get(interface.name, [])),
                                       None)
                    if wan_address is not None:
                        endpoint, _ = client_endpoint(tunnel_row, config,
                                                      metadata_endpoint=str(wan_address))
            tunnel_view = {'name': tunnel_row.name, 'protocol': tunnel_row.protocol,
                           'obfuscation': tunnel_row.obfuscation, 'dns_mode': 'panel', 'exit': 'direct',
                           'public_key': server_public_key(tunnel_row), 'endpoint': endpoint,
                           'dns': list(tunnel_dns(tunnel_row, config)),
                           'dns_servers': list(tunnel_dns(tunnel_row, config)),
                           'header_protection_key': (_stored(tunnel_row.header_protection_key)
                                                     if tunnel_row.header_protection_key else None),
                           'random_trailers': tunnel_row.random_trailers,
                           'disable_cookies': tunnel_row.disable_cookies,
                           'allowed_ips': list(tunnel_row.allowed_ips or ('0.0.0.0/0',)),
                           'mtu': tunnel_row.mtu,
                           'listen_port': tunnel_row.listen_port,
                           'keepalive': tunnel_row.keepalive,
                           'subnet': str(tunnel_addresses(tunnel_row, config)[0])}
        else:
            tunnel_view = None
        return {'subscription': ({'status': subscription.status, 'expires_at': subscription.expires_at,
                                  'tariff_id': subscription.tariff_id} if subscription else None),
                'devices': [{'id': d.id, 'name': d.name, 'label': d.label, 'status': d.status,
                             'allowed_ips': d.allowed_ips or [],
                             'applied': d.name in peers_by_name,
                             'last_handshake': (handshakes.get(peers_by_name[d.name].public_key)
                                                if d.name in peers_by_name else None)}
                            for d in live_devices],
                'tunnel': tunnel_view}

    @app.post('/internal/portal/subscribers/{name}/device-op', dependencies=[Depends(_auth)])
    def device_op(name: str, body: DeviceOperation, db: Session = Depends(_db),
                  portal: Session = Depends(_portal_db)):
        return _mutate(name, 'device', db, portal, body)

    @app.post('/internal/portal/subscribers/{name}/expire', dependencies=[Depends(_auth)])
    def expire(name: str, db: Session = Depends(_db), portal: Session = Depends(_portal_db)):
        return _mutate(name, 'expire', db, portal)

    @app.post('/internal/portal/subscribers/{name}/renew', dependencies=[Depends(_auth)])
    def renew(name: str, body: dict | None = Body(default=None),
              db: Session = Depends(_db), portal: Session = Depends(_portal_db)):
        return _mutate(name, 'renew', db, portal, body)

    @app.post('/internal/master/token-rotate')
    def token_rotate(request: Request, body: TokenRotate, portal: Session = Depends(_portal_db)):
        # Authenticated by the CURRENT token (the token is its own channel).
        # Idempotent: a retry that arrives with the OLD token after a lost
        # response is answered 200 {'rotated': False} when the proposed token is
        # already current, 403 when the old token has been revoked.
        auth = request.headers.get('Authorization', '')
        supplied = auth[len('Bearer '):].strip() if auth.startswith('Bearer ') else ''
        current, previous = _read_master_tokens(portal)
        matched_current = bool(current) and secrets.compare_digest(current, supplied)
        matched_previous = (not matched_current) and bool(previous) and secrets.compare_digest(previous, supplied)
        if not (matched_current or matched_previous):
            raise APIError(403, 'auth.forbidden')
        same_as_current = bool(current) and secrets.compare_digest(current, body.new_token)
        if matched_previous and not same_as_current:
            raise APIError(403, 'auth.forbidden')
        if same_as_current:
            return {'rotated': False}
        _write_master_tokens(portal, body.new_token, current)
        return {'rotated': True}

    @app.get('/internal/master/state', dependencies=[Depends(_auth)])
    def master_state(portal: Session = Depends(_portal_db)):
        # Master telemetry (ADR-0035 D7): subscriber device counts plus the
        # live tunnel activity when the agent can read it.
        Device, _, _ = _models()
        active = portal.scalar(select(func.count(Device.id)).where(Device.status == 'active')) or 0
        try:
            live = versions.agent_call('tunnel_activity', {})
        except APIError:
            live = {}
        return {'active_devices': active, 'tunnels': live if isinstance(live, dict) else {}}

    return app


app = create_internal_app()
