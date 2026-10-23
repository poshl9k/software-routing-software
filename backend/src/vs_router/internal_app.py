"""Secret-authenticated, narrowly scoped portal bridge to the panel apply cycle."""
import os
import secrets
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Literal

from fastapi import Depends, FastAPI, Header, Request
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
from .generators.wireguard import client_endpoint, materialize_addresses, peer_address, server_public_key
from .schema import Configuration, EncryptedSecret, Model, Peer
from .secrets import decrypt_secret, encrypt_secret


class DeviceOperation(Model):
    op: Literal['create', 'delete', 'activate', 'deactivate']
    device_id: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, min_length=1, max_length=128)
    keys: dict | None = None


def read_internal_secret():
    from vs_portal.internal import read_internal_secret as read_secret
    try:
        return read_secret()
    except APIError:
        return ''


def _auth(x_vs_portal_secret: str | None = Header(default=None)):
    expected = read_internal_secret()
    if not expected or not x_vs_portal_secret or not secrets.compare_digest(expected, x_vs_portal_secret):
        raise APIError(403, 'auth.forbidden')


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
            'private_key': _stored(device.private_key), 'public_key': device.public_key,
            'preshared_key': _stored(device.preshared_key),
            'allowed_ips': list(device.allowed_ips or ())}


def _active(subscription):
    return (subscription is not None and subscription.status == 'active'
            and subscription.expires_at > datetime.now(timezone.utc))


def _tunnel(configuration, name):
    # Existing subscriber peers determine the server; otherwise use the sole server.
    servers = [t for t in configuration.tunnels if t.role == 'server']
    bound = [t for t in servers if any(p.subscriber == name for p in t.peers)]
    if not servers:
        raise APIError(409, 'portal.tunnel_unavailable')
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
        tunnel = _tunnel(config, name)
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
    def state(name: str, db: Session = Depends(_db), portal: Session = Depends(_portal_db)):
        row, subscription, devices = _context(name, db, portal)
        config = row.configuration
        tunnel = _tunnel(config, name)
        actual = {p.name: p for p in tunnel.peers if p.subscriber == name}
        try:
            live = versions.agent_call('tunnel_activity', {})
        except APIError:
            live = {}
        handshakes = {p.get('public_key'): p.get('latest_handshake')
                      for p in (live.get(tunnel.interface, []) if isinstance(live, dict) else [])
                      if isinstance(p, dict)}
        endpoint, _ = client_endpoint(tunnel, config)
        return {'subscription': ({'status': subscription.status, 'expires_at': subscription.expires_at,
                                  'tariff_id': subscription.tariff_id} if subscription else None),
                'devices': [{'id': d.id, 'name': d.name, 'label': d.label, 'status': d.status,
                             'allowed_ips': d.allowed_ips or [], 'applied': d.name in actual,
                             'last_handshake': handshakes.get(actual[d.name].public_key) if d.name in actual else None}
                            for d in devices if d.status != 'removed'],
                'tunnel': {'name': tunnel.name, 'protocol': tunnel.protocol,
                           'obfuscation': tunnel.obfuscation, 'dns_mode': 'panel', 'exit': 'direct',
                           'public_key': server_public_key(tunnel), 'endpoint': endpoint,
                           'dns': list(tunnel_dns(tunnel, config)),
                           'dns_servers': list(tunnel_dns(tunnel, config)),
                           'header_protection_key': (_stored(tunnel.header_protection_key)
                                                     if tunnel.header_protection_key else None),
                           'random_trailers': tunnel.random_trailers,
                           'disable_cookies': tunnel.disable_cookies,
                           'allowed_ips': list(tunnel.allowed_ips or ('0.0.0.0/0',)),
                           'listen_port': tunnel.listen_port}}

    @app.post('/internal/portal/subscribers/{name}/device-op', dependencies=[Depends(_auth)])
    def device_op(name: str, body: DeviceOperation, db: Session = Depends(_db),
                  portal: Session = Depends(_portal_db)):
        return _mutate(name, 'device', db, portal, body)

    @app.post('/internal/portal/subscribers/{name}/expire', dependencies=[Depends(_auth)])
    def expire(name: str, db: Session = Depends(_db), portal: Session = Depends(_portal_db)):
        return _mutate(name, 'expire', db, portal)

    @app.post('/internal/portal/subscribers/{name}/renew', dependencies=[Depends(_auth)])
    def renew(name: str, db: Session = Depends(_db), portal: Session = Depends(_portal_db)):
        return _mutate(name, 'renew', db, portal)

    return app


app = create_internal_app()
