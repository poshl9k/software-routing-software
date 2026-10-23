"""Subscriber device operations and queued expiry acceptance."""
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from test_portal_auth import activate, portal, anyio_backend
from vs_portal.devices import process_pending
from vs_portal.models import Audit, Device, DeviceOp, Subscription, Tariff

pytestmark = pytest.mark.anyio


async def test_criterion_2_create_encrypt_export_and_no_other_accounts(portal):
    client, engine, _, calls, _, state, _ = portal
    await activate(portal)
    created = await client.post('/api/portal/devices', json={'label': 'Телефон'})
    assert created.status_code == 200, created.text
    assert created.json()['status'] == 'applied'
    with Session(engine) as db:
        device = db.scalar(select(Device))
        assert device.name == f'portal_{device.id}'
        assert device.private_key.ciphertext.startswith('gAAAA')
        assert device.preshared_key.ciphertext.startswith('gAAAA')
        assert device.status == 'active'
        assert db.scalar(select(DeviceOp)).status == 'applied'
        assert 'client-private' not in str(db.execute(select(Device.__table__.c.private_key)).scalar())
    listed = await client.get('/api/portal/devices')
    assert listed.status_code == 200
    assert 'client-private' not in listed.text and 'ciphertext' not in listed.text
    conf = await client.get(f'/api/portal/devices/{device.name}/export?format=conf')
    assert conf.status_code == 200
    assert 'PrivateKey = client-private' in conf.text
    assert 'PublicKey = SERVER' in conf.text
    assert 'Endpoint = vpn.example:51820' in conf.text
    assert '10.66.1.2/32' in conf.text
    assert 'PresharedKey = client-psk' in conf.text
    assert conf.headers['Cache-Control'] == 'no-store'
    for kind in ('qr', 'amnezia'):
        response = await client.get(f'/api/portal/devices/{device.name}/export?format={kind}')
        assert response.status_code == 501 and response.json()['error']['code'] == 'portal.export_pending'
    state['tunnel']['endpoint'] = None
    assert (await client.get(f'/api/portal/devices/{device.name}/export')).status_code == 503
    assert any(b'"device_id":' in body for _, path, body in calls if path.endswith('device-op'))


async def test_criterion_3_busy_replay_idempotent_placeholder(portal):
    client, engine, now, calls, busy, _, app = portal
    await activate(portal)
    busy[0] = True
    first = await client.post('/api/portal/devices', json={'label': 'Laptop'})
    assert first.status_code == 202
    with Session(engine) as db:
        assert db.scalar(select(DeviceOp)).status == 'pending'
        assert db.scalar(select(Device)).name == f"portal_{first.json()['device_id']}"
    busy[0] = False
    process_pending(engine, app.state.internal, now[0])
    with Session(engine) as db:
        assert db.scalar(select(DeviceOp)).status == 'applied'
        assert db.scalar(select(Device)).status == 'active'
    ids = [body for _, path, body in calls if path.endswith('/device-op')]
    assert len(ids) == 2 and ids[0] == ids[1]
    process_pending(engine, app.state.internal, now[0])
    assert len([path for _, path, _ in calls if path.endswith('/device-op')]) == 2


async def test_criterion_4_limit_includes_pending_and_downgrade_notice(portal):
    client, engine, _, _, busy, _, _ = portal
    await activate(portal)
    busy[0] = True
    assert (await client.post('/api/portal/devices', json={'label': 'A'})).status_code == 202
    assert (await client.post('/api/portal/devices', json={'label': 'B'})).status_code == 202
    denied = await client.post('/api/portal/devices', json={'label': 'C'})
    assert denied.status_code == 403 and denied.json()['error']['code'] == 'portal.device_limit'
    assert '2 устройств' in denied.text
    busy[0] = False
    from vs_portal.devices import process_pending
    process_pending(engine, portal[-1].state.internal, portal[2][0])
    with Session(engine) as db:
        db.get(Tariff, 1).device_limit = 1
        db.commit()
    assert len((await client.get('/api/portal/devices')).json()['devices']) == 2
    assert any(item['code'] == 'portal.device_limit' for item in
               (await client.get('/api/portal/me')).json()['notices'])
    assert (await client.post('/api/portal/devices', json={'label': 'D'})).status_code == 403
    # The existing devices remain unchanged after downgrade.
    with Session(engine) as db:
        assert len(db.scalars(select(Device).where(Device.status == 'active')).all()) == 2


async def test_criterion_5_deactivate_delete_crypto_erasure(portal):
    client, engine, _, _, _, _, _ = portal
    await activate(portal)
    await client.post('/api/portal/devices', json={'label': 'Phone'})
    with Session(engine) as db:
        name = db.scalar(select(Device)).name
    assert (await client.post(f'/api/portal/devices/{name}/deactivate')).status_code == 200
    with Session(engine) as db:
        device = db.scalar(select(Device))
        assert device.status == 'inactive' and device.private_key is not None
    assert (await client.post(f'/api/portal/devices/{name}/activate')).status_code == 200
    assert (await client.delete(f'/api/portal/devices/{name}')).status_code == 200
    with Session(engine) as db:
        device = db.scalar(select(Device))
        assert device.status == 'removed' and device.private_key is None
        assert device.preshared_key is None and device.allowed_ips == []
        assert {'device.delete', 'device.delete.applied'} <= set(db.scalars(select(Audit.action)))
    assert (await client.get(f'/api/portal/devices/{name}/export')).status_code == 404


async def test_criterion_6_expiration_busy_then_renew_same_material(portal):
    client, engine, now, calls, busy, _, app = portal
    await activate(portal)
    await client.post('/api/portal/devices', json={'label': 'Phone'})
    with Session(engine) as db:
        device = db.scalar(select(Device))
        saved = (device.private_key.ciphertext, device.preshared_key.ciphertext, list(device.allowed_ips))
    now[0] += timedelta(days=31)
    assert (await client.post('/api/portal/login', json={
        'username': 'alice', 'password': 'password123'})).status_code == 200
    busy[0] = True
    process_pending(engine, app.state.internal, now[0])
    with Session(engine) as db:
        assert db.get(Subscription, 'alice').status == 'expired'
        assert db.scalar(select(DeviceOp).where(DeviceOp.op == 'expire')).status == 'pending'
    assert (await client.post('/api/portal/devices', json={'label': 'Denied'})).status_code == 403
    assert (await client.get('/api/portal/me')).json()['subscription']['status'] == 'expired'
    busy[0] = False
    process_pending(engine, app.state.internal, now[0])
    assert any(path.endswith('/expire') for _, path, _ in calls)
    with Session(engine) as db:
        sub = db.get(Subscription, 'alice')
        sub.status = 'active'
        sub.expires_at = now[0] + timedelta(days=30)
        db.commit()
    process_pending(engine, app.state.internal, now[0])
    assert any(path.endswith('/renew') for _, path, _ in calls)
    with Session(engine) as db:
        device = db.scalar(select(Device))
        assert (device.private_key.ciphertext, device.preshared_key.ciphertext,
                device.allowed_ips) == saved
        assert db.scalar(select(DeviceOp).where(DeviceOp.op == 'expire')).detail == 'renewed'


async def test_criterion_3_failed_create_frees_slot_and_pending_delete_keeps_keys(portal):
    import httpx
    client, engine, now, _, busy, _, app = portal
    await activate(portal)
    original = app.state.internal.transport
    app.state.internal.transport = httpx.MockTransport(lambda request: httpx.Response(
        409, json={'error': {'code': 'portal.tunnel_ambiguous'}}))
    failed = await client.post('/api/portal/devices', json={'label': 'Bad tunnel'})
    assert failed.status_code == 409 and failed.json()['error']['code'] == 'portal.tunnel_ambiguous'
    with Session(engine) as db:
        assert db.scalar(select(Device)).status == 'removed'
        assert db.scalar(select(DeviceOp)).detail == 'portal.tunnel_ambiguous'
    app.state.internal.transport = original
    created = await client.post('/api/portal/devices', json={'label': 'Working'})
    assert created.status_code == 200
    busy[0] = True
    pending = await client.delete(f"/api/portal/devices/portal_{created.json()['device_id']}")
    assert pending.status_code == 202
    with Session(engine) as db:
        device = db.get(Device, created.json()['device_id'])
        assert device.private_key and device.allowed_ips and device.status == 'active'
    busy[0] = False
    process_pending(engine, app.state.internal, now[0])
    with Session(engine) as db:
        device = db.get(Device, created.json()['device_id'])
        assert device.status == 'removed' and device.private_key is None


async def test_criterion_6_renew_before_pending_expiration_does_not_remove_peers(portal):
    client, engine, now, calls, busy, _, app = portal
    await activate(portal)
    await client.post('/api/portal/devices', json={'label': 'Keep'})
    now[0] += timedelta(days=31)
    busy[0] = True
    process_pending(engine, app.state.internal, now[0])
    with Session(engine) as db:
        subscription = db.get(Subscription, 'alice')
        subscription.status = 'active'
        subscription.expires_at = now[0] + timedelta(days=30)
        db.commit()
    before = len([path for _, path, _ in calls if path.endswith('/expire')])
    busy[0] = False
    process_pending(engine, app.state.internal, now[0])
    assert len([path for _, path, _ in calls if path.endswith('/expire')]) == before
    with Session(engine) as db:
        last = db.scalar(select(DeviceOp).where(DeviceOp.op == 'expire'))
        assert last.status == 'applied' and last.detail == 'renewed'
        assert db.scalar(select(Device).where(Device.status == 'active')) is not None


async def test_criterion_9_audit_no_key_material(portal):
    client, engine, _, _, _, _, _ = portal
    await activate(portal)
    await client.post('/api/portal/devices', json={'label': 'Phone'})
    with Session(engine) as db:
        entries = db.scalars(select(Audit)).all()
        assert {'device.create', 'device.create.applied'} <= {a.action for a in entries}
        assert all('client-private' not in str(a.detail) and 'client-psk' not in str(a.detail)
                   for a in entries)
