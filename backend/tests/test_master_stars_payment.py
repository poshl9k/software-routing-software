"""Offline payment ledger and actual worker replay, not live service proof."""
import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from test_master_stars import (EXPIRY, NOW, TOKEN, anyio_backend, approved, checkout,
                               command, invoices, rig, send)
from vs_master.models import (Account, Device, DeviceOp, PaymentReceipt, Subscription,
                              SubscriptionNotification, Tariff)
from vs_master.worker import process_pending

pytestmark = pytest.mark.anyio


def payment(payload, update_id=3, charge='synthetic-charge', **changes):
    value = {'telegram_payment_charge_id': charge, 'currency': 'XTR', 'total_amount': 1,
             'invoice_payload': payload, 'provider_payment_charge_id': ''}
    value.update(changes)
    return {'update_id': update_id, 'message': {'from': {'id': 100},
            'chat': {'id': 100, 'type': 'private'}, 'successful_payment': value}}


def order_row(engine):
    with engine.connect() as db:
        return dict(db.execute(text('SELECT * FROM master_stars_orders')).mappings().one())


async def test_payment_atomically_extends_super_once_and_queues_node_renewal(rig):
    payload = await approved(rig)
    bot = await send(rig, payment(payload))
    assert bot.offset == 4
    with Session(rig[2]) as db:
        subscription = db.get(Subscription, 1)
        assert subscription is not None and subscription.expires_at == EXPIRY + timedelta(days=30)
        assert subscription.tariff_id == 3 and subscription.notification_revision == 2
        assert db.get(Tariff, 3).device_limit == 50
        assert len(db.scalars(select(PaymentReceipt)).all()) == 1
        assert [(op.op, op.status, op.node_id) for op in db.scalars(select(DeviceOp))] == [('expire', 'pending', 1)]
        assert len(db.scalars(select(SubscriptionNotification)).all()) == 2
        assert [(d.id, d.status, d.name) for d in db.scalars(select(Device).order_by(Device.id))] == [
            (1, 'active', 'd1'), (2, 'active', 'd2')]
    assert order_row(rig[2])['state'] == 'paid'
    assert order_row(rig[2])['fulfillment_status'] == 'pending'
    await send(rig, payment(payload), restart=True, token='900:rotated-synthetic')
    await send(rig, payment(payload, 1), restart=True)
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY + timedelta(days=30)
        assert len(db.scalars(select(DeviceOp)).all()) == 1
    from vs_master.notifications import claim_notification
    assert claim_notification(rig[2], 1, NOW) is None
    with Session(rig[2]) as db:
        assert db.get(SubscriptionNotification, 1).status == 'suppressed'


async def test_paid_retry_extends_once_and_preserves_expired_first_order(rig):
    await send(rig, command())
    old_payload = invoices(rig)[0]['payload']
    rig[3][0] += timedelta(minutes=11)
    await send(rig, command(2), restart=True)
    assert len(invoices(rig)) == 2
    new_payload = invoices(rig)[1]['payload']
    await send(rig, checkout(old_payload, update_id=3), restart=True)
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False
    await send(rig, checkout(new_payload, update_id=4, id='retry-checkout'), restart=True)
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is True
    await send(rig, payment(new_payload, update_id=5), restart=True)
    await send(rig, payment(new_payload, update_id=5), restart=True)
    with Session(rig[2]) as db:
        subscription = db.get(Subscription, 1)
        assert subscription is not None and subscription.expires_at == EXPIRY + timedelta(days=30)
        assert len(db.scalars(select(DeviceOp)).all()) == 1
    with rig[2].connect() as db:
        assert db.execute(text('SELECT state FROM master_stars_orders ORDER BY id')).scalars().all() == ['sent', 'paid']
        assert db.scalar(text("SELECT COUNT(*) FROM master_stars_payment_events WHERE status='granted'")) == 1


@pytest.mark.parametrize('result', ['pending', 'timeout', 'invalid', 'denied'])
async def test_bridge_fulfillment_remains_durable_until_all_acknowledged(rig, result):
    from vs_master.bridge import BridgeError
    payload = await approved(rig)
    await send(rig, payment(payload))
    calls = []

    class Bridge:
        failed = True

        def node_state(self):
            return {'active_devices': 2}

        def renew(self, subscriber, body):
            calls.append((subscriber, body))
            if self.failed:
                if result == 'timeout':
                    raise TimeoutError('synthetic lost response')
                if result == 'denied':
                    raise BridgeError(403, 'synthetic.denied')
                return {'status': result}
            return {'status': 'applied'}

        def expire(self, *_):
            pytest.fail('Active renewal must never expire devices')

    bridge = Bridge()
    await asyncio.to_thread(process_pending, rig[2], lambda node: bridge, NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'pending'
    with Session(rig[2]) as db:
        assert db.scalar(select(DeviceOp)).status == 'pending'
    bridge.failed = False
    await asyncio.to_thread(process_pending, rig[2], lambda node: bridge, NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'applied'
    assert len(calls) == 2
    assert calls[0] == calls[1], 'Lost ACK retry must preserve identities and entitlement version'
    body = calls[-1][1]
    assert body['entitlement']['expires_at'] == (EXPIRY + timedelta(days=30)).isoformat()
    assert [d['device_id'] for d in body['devices']] == [1, 2]
    with Session(rig[2]) as db:
        assert [d.status for d in db.scalars(select(Device))] == ['active', 'active']
        assert db.scalar(select(DeviceOp)).detail == 'renewed'
    await asyncio.to_thread(process_pending, rig[2], lambda node: bridge, NOW)
    assert len(calls) == 2


@pytest.mark.parametrize('mode', ['amount', 'currency', 'payer', 'group', 'recurring', 'tariff', 'disabled', 'relink', 'bot'])
async def test_paid_mismatch_is_reviewable_without_ack_or_grant(rig, mode):
    payload = await approved(rig)
    update = payment(payload)
    if mode in ('amount', 'currency', 'recurring'):
        update['message']['successful_payment'].update(
            {'total_amount': 2} if mode == 'amount' else {'currency': 'USD'} if mode == 'currency' else {'is_recurring': True})
    elif mode == 'payer':
        update['message']['from']['id'] = 200
    elif mode == 'group':
        update['message']['chat']['type'] = 'group'
    elif mode != 'bot':
        with Session(rig[2]) as db:
            if mode == 'tariff':
                db.get(Subscription, 1).tariff_id = 1
            elif mode == 'disabled':
                db.get(Account, 1).status = 'disabled'
            else:
                db.get(Account, 1).telegram_linked_at = NOW + timedelta(seconds=1)
            db.commit()
    bot = await send(rig, update, restart=True, token='901:synthetic' if mode == 'bot' else TOKEN)
    assert bot.offset is None
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY
        assert len(db.scalars(select(PaymentReceipt)).all()) == 1
        assert db.scalar(select(DeviceOp)) is None
    with rig[2].connect() as db:
        assert db.scalar(text('SELECT status FROM master_stars_payment_events')) == 'review'


async def test_second_charge_and_conflicting_replay_retained_without_second_grant(rig):
    payload = await approved(rig)
    await send(rig, payment(payload))
    bot = await send(rig, payment(payload, 4, charge='another-charge'))
    assert bot.offset == 4, 'Conflicting update must not advance offset'
    await send(rig, payment(payload, 5, total_amount=2), restart=True)
    await send(rig, payment(payload, 5, total_amount=2), restart=True)
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY + timedelta(days=30)
        assert len(db.scalars(select(PaymentReceipt)).all()) == 2
    with rig[2].connect() as db:
        assert db.scalar(text("SELECT COUNT(*) FROM master_stars_payment_events WHERE status='review'")) == 2


async def test_delayed_approved_payment_extends_from_max_now_and_survives_flag_off(rig, monkeypatch):
    payload = await approved(rig)
    rig[3][0] = EXPIRY + timedelta(days=1)
    monkeypatch.delenv('VS_MASTER_STARS_TEST_ENABLED')
    await send(rig, payment(payload))
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == rig[3][0] + timedelta(days=30)


async def test_payment_before_checkout_never_grants_even_after_later_approval(rig):
    await send(rig, command())
    payload = invoices(rig)[0]['payload']
    bot = await send(rig, payment(payload), restart=True)
    assert bot.offset is None
    await send(rig, checkout(payload), restart=True)
    bot = await send(rig, payment(payload), restart=True)
    assert bot.offset is None
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY


async def test_per_node_tickets_wait_for_every_node_and_exclude_other_owners(rig):
    from vs_master.models import Node, StarsFulfillment
    from vs_router.schema import EncryptedSecret
    with Session(rig[2]) as db:
        node = db.get(Node, 1)
        assert node is not None
        db.add(Node(id=2, name='second', bridge_url='https://second.invalid',
                    bridge_token=node.bridge_token, state='ok', enabled=True))
        db.flush()
        device = db.get(Device, 2)
        assert device is not None
        device.node_id = 2
        db.add(Device(account_id=2, node_id=1, node_subscriber='foreign', name='other',
                      label='Unrelated', status='active', public_key='foreign-public',
                      private_key=EncryptedSecret(ciphertext='gAAAA-untouched'), allowed_ips=['10.0.0.9/32']))
        db.commit()
    payload = await approved(rig)
    await send(rig, payment(payload))
    with Session(rig[2]) as db:
        assert len(db.scalars(select(StarsFulfillment)).all()) == 2
    calls = []
    pending = [True]

    class Bridge:
        def __init__(self, node_id):
            self.node_id = node_id

        def node_state(self):
            return {'active_devices': 2}

        def renew(self, subscriber, body):
            calls.append((self.node_id, subscriber, body))
            assert subscriber == 'owner'
            assert all(d['device_id'] in (1, 2) for d in body['devices'])
            return {'status': 'pending' if self.node_id == 2 and pending[0] else 'applied'}

    await asyncio.to_thread(process_pending, rig[2], lambda node: Bridge(node.id), NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'pending'
    pending[0] = False
    await asyncio.to_thread(process_pending, rig[2], lambda node: Bridge(node.id), NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'applied'
    assert [node_id for node_id, _, _ in calls] == [1, 2, 2]
    with Session(rig[2]) as db:
        assert db.scalar(select(Device).where(Device.account_id == 2)).public_key == 'foreign-public'


@pytest.mark.parametrize('field,value', [('total_amount', True), ('telegram_payment_charge_id', ''),
                                        ('invoice_payload', None), ('currency', 1)])
async def test_malformed_payment_does_not_ack(rig, field, value):
    bot = await send(rig, payment('unknown', **{field: value}), restart=True)
    assert bot.offset is None
    with Session(rig[2]) as db:
        assert db.scalar(select(PaymentReceipt)) is None


async def test_unknown_payment_remains_in_operator_ledger_without_blocking_bot(rig, caplog):
    bot = await send(rig, payment('unknown-order', update_id=7), restart=True)
    assert bot.offset == 8
    with Session(rig[2]) as db:
        assert db.scalar(select(PaymentReceipt)) is not None
        subscription = db.get(Subscription, 1)
        assert subscription is not None and subscription.expires_at == EXPIRY
        assert db.scalar(select(DeviceOp)) is None
    with rig[2].connect() as db:
        assert db.scalar(text('SELECT status FROM master_stars_payment_events')) == 'unmatched'
    assert 'Unmatched Telegram payment retained for manual review' in caplog.text


async def test_node_goes_down_after_checkout_and_paid_renewal_retries(rig):
    from vs_master.models import Node
    from vs_master.bridge import BridgeError
    payload = await approved(rig)
    with Session(rig[2]) as db:
        node = db.get(Node, 1)
        assert node is not None
        node.state = 'down'
        db.commit()
    await send(rig, payment(payload))
    assert order_row(rig[2])['fulfillment_status'] == 'pending'
    with Session(rig[2]) as db:
        subscription = db.get(Subscription, 1)
        assert subscription is not None and subscription.expires_at == EXPIRY + timedelta(days=30)
    class Bridge:
        available = False
        def node_state(self):
            if not self.available:
                raise BridgeError(503, 'node.unreachable')
            return {'active_devices': 2}
        def renew(self, subscriber, body):
            if not self.available:
                raise BridgeError(503, 'node.unreachable')
            return {'status': 'applied'}
    bridge = Bridge()
    await asyncio.to_thread(process_pending, rig[2], lambda node: bridge, NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'pending'
    bridge.available = True
    await asyncio.to_thread(process_pending, rig[2], lambda node: bridge, NOW)
    assert order_row(rig[2])['fulfillment_status'] == 'applied'
