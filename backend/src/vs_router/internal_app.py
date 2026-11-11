"""Secret-authenticated, narrowly scoped portal bridge to the panel apply cycle."""
import base64
from contextlib import asynccontextmanager
import json
import os
import secrets
from datetime import datetime, timezone
from ipaddress import ip_interface, ip_network
from pathlib import Path
from typing import Literal

from fastapi import Body, Depends, FastAPI, Header, Request
from pydantic import AwareDatetime, Field
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
from .db import (ConfigurationRow, MasterBridgeDevice, MasterBridgeEntitlement,
                 MasterBridgeSetting)
from .generators.amnezia import tunnel_dns
from .generators.wireguard import (client_endpoint, effective_obfuscation, materialize_addresses,
                                   peer_address, server_public_key, tunnel_addresses, tunnel_mtu)
from .schema import Configuration, EncryptedSecret, Model, Name, Peer, Subscriber
from .secrets import decrypt_secret, encrypt_secret


class DeviceOperation(Model):
    op: Literal['create', 'delete', 'activate', 'deactivate']
    device_id: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, min_length=1, max_length=128)
    keys: dict | None = None
    tunnel: str | None = None


class Entitlement(Model):
    version: int = Field(ge=1)
    status: Literal['active', 'expired']
    expires_at: AwareDatetime


class MasterDeviceOperation(Model):
    # Legacy snapshots have no operation ID; zero is older than every direct op.
    operation_id: int = Field(default=0, ge=0)
    reservations: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    op: Literal['create', 'delete', 'activate', 'deactivate']
    device_id: int = Field(ge=1)
    name: Name
    label: str | None = Field(default=None, min_length=1, max_length=128)
    keys: dict | None = Field(default=None, repr=False)
    tunnel: str | None = None
    entitlement: Entitlement


class MasterGrant(Model):
    entitlement: Entitlement
    devices: tuple[MasterDeviceOperation, ...] = ()


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
    # Local portal principal is never a bearer principal.
    expected = read_internal_secret()
    if not expected or not x_vs_portal_secret or not secrets.compare_digest(expected, x_vs_portal_secret):
        raise APIError(403, 'auth.forbidden')


MASTER_TOKEN_KEY = 'master_bridge_token'


def _read_master_tokens(db):
    row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
    if row is None:
        return '', ''
    data = row.value
    return (_stored(data.get('current')) or '',
            _stored(data.get('previous')) or '')


def _write_master_tokens(db, current, previous, *, setup_pending=False):
    value = {'current': _encrypt(current).model_dump(mode='json'),
             'previous': _encrypt(previous).model_dump(mode='json') if previous else None,
             'setup_pending': setup_pending}
    row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
    if row is None:
        db.add(MasterBridgeSetting(key=MASTER_TOKEN_KEY, value=value))
    else:
        row.value = value
    db.commit()


def import_legacy_master_tokens(engine, portal_engine):
    """One-time, local startup import. Never query portal SQLite on a request.

    Keep the legacy DB untouched; a router-owned record always wins, even
    after rotation/revocation. Missing legacy DB is normal on master-only nodes.
    """
    from vs_portal.models import Setting
    with Session(engine) as db:
        db.execute(text('BEGIN IMMEDIATE'))
        if db.get(MasterBridgeSetting, MASTER_TOKEN_KEY) is not None:
            return
        legacy_path = portal_engine.url.database
        if (portal_engine.dialect.name == 'sqlite' and legacy_path
                and legacy_path != ':memory:' and not Path(legacy_path).is_file()):
            return  # Import is read-only: never manufacture a legacy database.
        try:
            with Session(portal_engine) as portal:
                row = portal.get(Setting, MASTER_TOKEN_KEY)
                value = json.loads(row.value) if row else None
        except OperationalError:
            return
        if value is not None:
            # Validate/decrypt before accepting anything into the new store.
            current = _stored(value.get('current'))
            previous = _stored(value.get('previous'))
            if not current:
                raise ValueError('master token import: empty current token')
            _write_master_tokens(db, current, previous)


def _master_auth(request: Request):
    auth = request.headers.get('Authorization', '')
    supplied = auth[len('Bearer '):].strip() if auth.startswith('Bearer ') else ''
    if not supplied:
        raise APIError(403, 'auth.forbidden')
    with Session(request.app.state.engine) as db:
        current, previous = _read_master_tokens(db)
        matched = any(candidate and secrets.compare_digest(candidate, supplied)
                      for candidate in (current, previous))
        if not matched:
            raise APIError(403, 'auth.forbidden')
        row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
        if row is not None and isinstance(row.value, dict) and row.value.get('setup_pending') is True:
            # Serialize verification with pending-token replacement. Recheck the
            # bearer after acquiring the write lock so an old in-flight request
            # cannot mark a newly pasted credential as verified.
            db.rollback()
            db.execute(text('BEGIN IMMEDIATE'))
            current, previous = _read_master_tokens(db)
            if not any(candidate and secrets.compare_digest(candidate, supplied)
                       for candidate in (current, previous)):
                db.rollback()
                raise APIError(403, 'auth.forbidden')
            row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
            if row is not None and isinstance(row.value, dict) and row.value.get('setup_pending') is True:
                row.value = {**row.value, 'setup_pending': False}
                db.commit()
            else:
                db.rollback()


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


def _allocate(configuration, tunnel, device, devices, reserved_ips=()):
    # Reserve every portal allocation, including expired/inactive devices missing
    # from the currently installed configuration; never recycle their /32.
    reserved = [p for p in tunnel.peers if p.name != device.name]
    for other in devices:
        if other.id != device.id and other.allowed_ips and other.name not in {p.name for p in reserved}:
            reserved.append(_peer(other))
    for index, cidr in enumerate(reserved_ips):
        reserved.append(Peer(name=f'master_reserved_{index}', public_key='', allowed_ips=(cidr,)))
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


def _check_master_intent(db, expected):
    name, version, devices, require_active = expected
    db.expire_all()  # A different request may have committed after our intent.
    grant = db.get(MasterBridgeEntitlement, name)
    if (grant is None or grant.version != version or
            (require_active and not _active(grant))):
        raise APIError(409, 'master.entitlement_stale')
    current = {d.id: (d.last_operation, d.last_action, d.status) for d in db.scalars(
        select(MasterBridgeDevice).where(MasterBridgeDevice.subscriber_name == name))}
    if current != devices:
        raise APIError(409, 'master.operation_stale')


def _apply(db, original, configuration, *, master_intent=None):
    # The master path committed encrypted intent before this point. Reacquire
    # the SQLite writer lock and recheck the base; an intervening admin apply
    # must be retried, never overwritten with a stale whole-document snapshot.
    if db.get_bind().dialect.name == 'sqlite' and not db.connection().connection.driver_connection.in_transaction:
        db.execute(text('BEGIN IMMEDIATE'))
    if master_intent is not None:
        _check_master_intent(db, master_intent)
    latest = _confirmed(db)
    if latest is None or latest.id != original.id:
        raise APIError(409, 'apply.busy')
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


def _accept_entitlement(db, name, grant):
    saved = db.get(MasterBridgeEntitlement, name)
    if saved is not None:
        if grant.version < saved.version:
            raise APIError(409, 'master.entitlement_stale')
        if grant.version == saved.version and (grant.status != saved.status or grant.expires_at != saved.expires_at):
            raise APIError(409, 'master.entitlement_conflict')
    else:
        saved = MasterBridgeEntitlement(subscriber_name=name)
        db.add(saved)
    saved.version, saved.status, saved.expires_at = grant.version, grant.status, grant.expires_at
    return saved


def _validate_master_keys(keys):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    try:
        private = X25519PrivateKey.from_private_bytes(base64.b64decode(keys['private_key'], validate=True))
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
        if public != keys['public_key']:
            raise ValueError()
        if keys.get('preshared_key') and len(base64.b64decode(keys['preshared_key'], validate=True)) != 32:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise APIError(422, 'master.device_material_invalid') from None


def _master_mutate(name, action, body, db):
    """Persist execution intent before apply; retry reconciles against confirmed history.

    Device IDs are in the MASTER namespace and are never looked up in portal DB.
    The authenticated master's grant is mandatory; no local Subscription gates it.
    """
    Subscriber(name=name)  # Validate config identifier, not a local account lookup.
    try:
        db.execute(text('BEGIN IMMEDIATE'))
        row = _confirmed(db)
        if row is None:
            raise APIError(409, 'portal.tunnel_unavailable')
        if db.scalar(select(ConfigurationRow.id).where(ConfigurationRow.status == 'draft')) is not None:
            raise APIError(409, 'apply.busy')
        marker = versions.agent_call('status', EmptyParams())
        if not isinstance(marker, dict) or marker.get('status') not in ('confirmed', 'rolled_back', 'failed', 'rollback_failed'):
            raise APIError(409, 'apply.busy')
        grant = _accept_entitlement(db, name, body.entitlement)
        op = body.op if action == 'device' else action
        if op in ('create', 'activate', 'renew') and not _active(grant):
            raise APIError(403, 'portal.subscription_expired')
        if op == 'expire' and _active(grant):
            raise APIError(409, 'master.entitlement_active')
        config = row.configuration
        device = None
        if action == 'device' and body.operation_id < 1:
            raise APIError(422, 'master.operation_id_required')
        operations = (body,) if action == 'device' else body.devices
        for operation in operations:
            if operation.entitlement != body.entitlement:
                raise APIError(409, 'master.entitlement_conflict')
            device = db.get(MasterBridgeDevice, operation.device_id)
            keys = operation.keys or {}
            if device is None:
                _validate_master_keys(keys)
                tunnel = _tunnel(config, name, operation.tunnel)
                existing = next((p for p in tunnel.peers if p.name == operation.name), None)
                if existing is not None and (existing.subscriber != name or existing.public_key != keys['public_key']):
                    raise APIError(409, 'device.name_conflict')
                device = MasterBridgeDevice(id=operation.device_id, subscriber_name=name,
                            name=operation.name, label=operation.label or operation.name, tunnel_name=tunnel.name,
                            public_key=keys['public_key'], private_key=_encrypt(keys['private_key']),
                            preshared_key=_encrypt(keys['preshared_key']) if keys.get('preshared_key') else None,
                            allowed_ips=list(keys.get('allowed_ips') or (existing.allowed_ips if existing else ())),
                            status='inactive')
                db.add(device)
            elif (device.subscriber_name != name or device.name != operation.name
                  or operation.tunnel and device.tunnel_name != operation.tunnel):
                raise APIError(409, 'device.identity_conflict')
            elif any(keys.get(k) is not None and keys[k] != v for k, v in (
                    ('private_key', _stored(device.private_key)), ('public_key', device.public_key),
                    ('preshared_key', _stored(device.preshared_key)))):
                raise APIError(409, 'device.keys_mismatch')
            if action == 'device':
                if operation.operation_id < (device.last_operation or 0):
                    raise APIError(409, 'master.operation_stale')
                if operation.operation_id == device.last_operation and operation.op != device.last_action:
                    raise APIError(409, 'master.operation_conflict')
                device.last_operation, device.last_action = operation.operation_id, operation.op
            else:
                desired = {'create': 'active', 'activate': 'active',
                           'deactivate': 'inactive', 'delete': 'removed'}[operation.op]
                # A delayed snapshot must not undo a newer direct operation.
                if (operation.operation_id < (device.last_operation or 0) or
                        (operation.operation_id == (device.last_operation or 0) and
                         device.last_action and device.status != desired)):
                    continue
                if operation.operation_id > (device.last_operation or 0) or not device.last_action:
                    device.last_operation, device.last_action = operation.operation_id, operation.op
            if device.status == 'removed' and operation.op != 'delete':
                raise APIError(409, 'device.removed')
            device.status = {'create': 'active', 'activate': 'active',
                             'deactivate': 'inactive', 'delete': 'removed'}[operation.op]
        if action != 'device':
            device = None
        db.flush()
        devices = list(db.scalars(select(MasterBridgeDevice).where(MasterBridgeDevice.subscriber_name == name)))
        reservations = list(db.scalars(select(MasterBridgeDevice).where(MasterBridgeDevice.status != 'removed')))
        data = config.model_dump(mode='json')
        if devices and name not in {s.name for s in config.subscribers}:
            data['subscribers'].append(Subscriber(name=name).model_dump(mode='json'))
        # Only bridge-owned peers may be removed/restored; never all local peers by name.
        for tunnel in config.tunnels:
            owned = [d for d in devices if d.tunnel_name == tunnel.name]
            identities = {(d.name, d.public_key) for d in owned}
            previous = list(tunnel.peers)
            peers = [p for p in previous if not (p.subscriber == name and (p.name, p.public_key) in identities)]
            for item in owned:
                if op != 'expire' and _active(grant) and item.status == 'active':
                    peers.append(_allocate(config, tunnel, item,
                                 [d for d in reservations if d.tunnel_name == tunnel.name],
                                 (body.reservations.get(tunnel.name, ())
                                  if action == 'device' and item.id == body.device_id else ())))
            removed = {p.name for p in previous if p.subscriber == name and p.name not in {q.name for q in peers}}
            current = Configuration.model_validate(data)
            current = _build(current, next(t for t in current.tunnels if t.name == tunnel.name), peers, {name: removed})
            restored, rules = _restore_policy(db, current, peers, previous)
            current = _build(current, next(t for t in current.tunnels if t.name == tunnel.name), restored, {})
            data = current.model_dump(mode='json') | {'routing_rules': [r.model_dump(mode='json') for r in rules]}
        updated = _mirror_inbound_users(Configuration.model_validate(data), devices, op, grant)
        # The execution cache carries encrypted key material and reserved addresses
        # across crashes / agent failures; it is not proof that apply succeeded.
        expected = (name, grant.version,
                    {d.id: (d.last_operation, d.last_action, d.status) for d in devices},
                    action == 'renew' or (action == 'device' and body.op in ('create', 'activate')))
        db.commit()
        if updated == config:
            if db.get_bind().dialect.name == 'sqlite' and not db.connection().connection.driver_connection.in_transaction:
                db.execute(text('BEGIN IMMEDIATE'))
            _check_master_intent(db, expected)
            latest = _confirmed(db)
            if latest is None or latest.id != row.id:
                raise APIError(409, 'apply.busy')
            status = 'applied'
        else:
            status = _apply(db, row, updated, master_intent=expected)
        return {'status': status, **({'device': _device_result(device)} if device is not None else {})}
    except (IntegrityError, OperationalError) as exc:
        db.rollback()
        raise APIError(409, 'apply.busy') from exc
    except Exception:
        db.rollback()
        raise


def _mirror_inbound_users(config, devices, op, grant):
    """Rebuild inbound users from the bridge's device table (ADR-0034).

    The node never stores a second credential: a device's VLESS UUID is derived
    from the public key the bridge already owns, so creating a device grants
    access and deleting it (which drops the peer) revokes access in the same
    apply. Without a declared inbound the configuration is returned untouched.
    """
    if not config.inbounds:
        return config
    from .generators.vless_uri import device_uuid

    active = sorted((d for d in devices if d.status == 'active'), key=lambda d: d.name)
    users = []
    if op != 'expire' and _active(grant):
        for item in active:
            users.append({'name': f'{item.subscriber_name}_{item.name}',
                          'uuid': _encrypt(device_uuid(item.public_key)).model_dump(mode='json')})
    data = config.model_dump(mode='json')
    for inbound in data['inbounds']:
        inbound['users'] = users
    return Configuration.model_validate(data)


def create_internal_app(engine=None, *, database_url=None, portal_engine=None):
    @asynccontextmanager
    async def lifespan(app):
        import_legacy_master_tokens(app.state.engine, app.state.portal_engine)
        yield

    app = FastAPI(lifespan=lifespan, title='vs-router-internal', docs_url=None, redoc_url=None, openapi_url=None)
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
        return state_view(name, row, subscription, devices, tunnel)

    def state_view(name, row, subscription, devices, tunnel=None):
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
                           'obfuscation': effective_obfuscation(tunnel_row), 'dns_mode': 'panel', 'exit': 'direct',
                           'public_key': server_public_key(tunnel_row), 'endpoint': endpoint,
                           'dns': list(tunnel_dns(tunnel_row, config)),
                           'dns_servers': list(tunnel_dns(tunnel_row, config)),
                           'header_protection_key': (_stored(tunnel_row.header_protection_key)
                                                     if tunnel_row.header_protection_key else None),
                           'random_trailers': tunnel_row.random_trailers,
                           'disable_cookies': tunnel_row.disable_cookies,
                           'allowed_ips': list(tunnel_row.allowed_ips or ('0.0.0.0/0',)),
                           'mtu': tunnel_mtu(tunnel_row),
                           'listen_port': tunnel_row.listen_port,
                           'keepalive': tunnel_row.keepalive,
                           'subnet': str(tunnel_addresses(tunnel_row, config)[0])}
        else:
            tunnel_view = None
        # ADR-0034: the master builds the client link, so it needs the inbound's
        # public half. No secret crosses the bridge — the per-device UUID is
        # derived from the device's public key on both sides.
        inbound_view = None
        if config.inbounds:
            item = config.inbounds[0]
            members = {user.name for user in item.users}
            inbound_view = {'tag': item.tag, 'listen_port': item.listen_port,
                            'server_name': item.server_name, 'public_key': item.public_key,
                            'short_ids': list(item.short_ids), 'flow': item.flow,
                            'users': sorted(members)}
        return {'subscription': ({'status': subscription.status, 'expires_at': subscription.expires_at,
                                  'tariff_id': getattr(subscription, 'tariff_id', None)} if subscription else None),
                'devices': [{'id': d.id, 'name': d.name, 'label': d.label, 'status': d.status,
                             'allowed_ips': d.allowed_ips or [],
                             'applied': d.name in peers_by_name,
                             'last_handshake': (handshakes.get(peers_by_name[d.name].public_key)
                                                if d.name in peers_by_name else None),
                             'inbound_user': (f'{d.subscriber_name}_{d.name}'
                                              if inbound_view and d.status == 'active' else None)}
                            for d in live_devices],
                'tunnel': tunnel_view,
                'inbound': inbound_view}

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

    @app.get('/internal/master/subscribers/{name}/state', dependencies=[Depends(_master_auth)])
    def master_subscriber_state(name: Name, tunnel: str | None = None, db: Session = Depends(_db)):
        row = _confirmed(db)
        if row is None:
            raise APIError(409, 'portal.tunnel_unavailable')
        devices = list(db.scalars(select(MasterBridgeDevice).where(MasterBridgeDevice.subscriber_name == name)))
        return state_view(name, row, db.get(MasterBridgeEntitlement, name), devices, tunnel)

    @app.post('/internal/master/subscribers/{name}/device-op', dependencies=[Depends(_master_auth)])
    def master_device_op(name: Name, body: MasterDeviceOperation, db: Session = Depends(_db)):
        return _master_mutate(name, 'device', body, db)

    @app.post('/internal/master/subscribers/{name}/expire', dependencies=[Depends(_master_auth)])
    def master_expire(name: Name, body: MasterGrant, db: Session = Depends(_db)):
        return _master_mutate(name, 'expire', body, db)

    @app.post('/internal/master/subscribers/{name}/renew', dependencies=[Depends(_master_auth)])
    def master_renew(name: Name, body: MasterGrant, db: Session = Depends(_db)):
        return _master_mutate(name, 'renew', body, db)

    @app.post('/internal/master/token-rotate')
    def token_rotate(request: Request, body: TokenRotate, db: Session = Depends(_db)):
        db.execute(text('BEGIN IMMEDIATE'))
        # Authenticated by the CURRENT token (the token is its own channel).
        # Idempotent: a retry that arrives with the OLD token after a lost
        # response is answered 200 {'rotated': False} when the proposed token is
        # already current, 403 when the old token has been revoked.
        auth = request.headers.get('Authorization', '')
        supplied = auth[len('Bearer '):].strip() if auth.startswith('Bearer ') else ''
        current, previous = _read_master_tokens(db)
        matched_current = bool(current) and secrets.compare_digest(current, supplied)
        matched_previous = (not matched_current) and bool(previous) and secrets.compare_digest(previous, supplied)
        if not (matched_current or matched_previous):
            raise APIError(403, 'auth.forbidden')
        same_as_current = bool(current) and secrets.compare_digest(current, body.new_token)
        if matched_previous and not same_as_current:
            raise APIError(403, 'auth.forbidden')
        if same_as_current:
            return {'rotated': False}
        _write_master_tokens(db, body.new_token, current)
        return {'rotated': True}

    @app.get('/internal/master/state', dependencies=[Depends(_master_auth)])
    def master_state(db: Session = Depends(_db)):
        # Master telemetry (ADR-0035 D7): subscriber device counts plus the
        # live tunnel activity when the agent can read it.
        row = _confirmed(db)
        active = sum(1 for t in row.configuration.tunnels for p in t.peers
                     if db.scalar(select(MasterBridgeDevice.id).where(
                         MasterBridgeDevice.name == p.name, MasterBridgeDevice.public_key == p.public_key,
                         MasterBridgeDevice.subscriber_name == p.subscriber)) is not None) if row else 0
        try:
            live = versions.agent_call('tunnel_activity', {})
        except APIError:
            live = {}
        return {'active_devices': active, 'tunnels': live if isinstance(live, dict) else {}}

    return app


app = create_internal_app()
