"""Race, rollback and fail-closed timing checks using local resources only."""
import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from test_master_stars import (EXPIRY, NOW, anyio_backend, approved, checkout, command,
                               invoices, rig, send)
from test_master_stars_payment import order_row, payment
from vs_master import stars
from vs_master.models import Account, Device, DeviceOp, PaymentReceipt, StarsOrder, Subscription
from vs_master.telegram_bot import Bot

pytestmark = pytest.mark.anyio


async def test_simultaneous_receipts_grant_once(rig):
    payload = await approved(rig)
    barrier = threading.Barrier(2)

    def capture():
        barrier.wait(timeout=5)
        stars.accept_payment(rig[2], '900', payment(payload)['message'], lambda: NOW)

    with ThreadPoolExecutor(max_workers=2) as executor:
        await asyncio.gather(*[asyncio.wrap_future(executor.submit(capture)) for _ in range(2)])
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY + timedelta(days=30)
        assert len(db.scalars(select(DeviceOp)).all()) == 1
        assert len(db.scalars(select(PaymentReceipt)).all()) == 1


async def test_simultaneous_buy_requests_reserve_only_one_invoice(rig):
    barrier = threading.Barrier(2)

    def reserve():
        barrier.wait(timeout=5)
        return stars.prepare_invoice(rig[2], '900', 100, lambda: NOW)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = await asyncio.gather(*[asyncio.wrap_future(executor.submit(reserve)) for _ in range(2)])
    assert sum(result is not None for result in results) == 1


async def test_failed_node_ticket_insert_rolls_back_receipt_grant_and_notice(rig):
    payload = await approved(rig)

    def fail_ticket(connection, cursor, statement, parameters, context, many):
        if statement.startswith('INSERT INTO master_stars_fulfillments'):
            raise RuntimeError('synthetic disk failure')

    event.listen(rig[2], 'before_cursor_execute', fail_ticket)
    try:
        bot = await send(rig, payment(payload))
        assert bot.offset == 3
    finally:
        event.remove(rig[2], 'before_cursor_execute', fail_ticket)
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY
        assert db.scalar(select(PaymentReceipt)) is None
        assert db.scalar(select(DeviceOp)) is None
        assert db.get(Subscription, 1).notification_revision == 1
    await send(rig, payment(payload), restart=True)
    assert order_row(rig[2])['state'] == 'paid'


async def test_checkout_rejects_within_deadline_while_device_io_busy(rig):
    await send(rig, command())
    await rig[0].io_limit.acquire()
    try:
        start = time.monotonic()
        await send(rig, checkout(invoices(rig)[0]['payload']))
        assert time.monotonic() - start < 5
    finally:
        rig[0].io_limit.release()
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False
    with Session(rig[2]) as db:
        assert db.scalar(select(StarsOrder)).approved_at is None


async def test_cancelled_io_keeps_capacity_until_thread_finishes(rig):
    entered, release = threading.Event(), threading.Event()

    def work():
        entered.set()
        release.wait(timeout=5)

    task = asyncio.create_task(rig[0]._io(work))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert rig[0].io_limit.locked(), 'Timed-out checkout must not leave unbounded DB threads'
    finally:
        release.set()
        await asyncio.sleep(0.05)
    assert not rig[0].io_limit.locked()


async def test_conflicted_order_is_frozen_before_another_capture(rig):
    await send(rig, command())
    payload = invoices(rig)[0]['payload']
    await send(rig, payment(payload), restart=True)
    await send(rig, checkout(payload), restart=True)
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False
    assert order_row(rig[2])['state'] == 'review'


async def test_capture_preserves_newer_admin_extension_and_queues_when_node_down(rig):
    payload = await approved(rig)
    from vs_master.models import Node
    with Session(rig[2]) as db:
        db.get(Subscription, 1).expires_at += timedelta(days=5)
        db.get(Node, 1).state = 'down'
        db.commit()
    await send(rig, payment(payload))
    with Session(rig[2]) as db:
        assert db.get(Subscription, 1).expires_at == EXPIRY + timedelta(days=35)
        assert db.scalar(select(DeviceOp)).status == 'pending'


async def test_readiness_rejects_undecryptable_active_device_material(rig):
    from vs_router.schema import EncryptedSecret
    with Session(rig[2]) as db:
        db.get(Device, 1).private_key = EncryptedSecret(ciphertext='gAAAA-synthetic-invalid')
        db.commit()
    await send(rig, command())
    assert not invoices(rig)


async def test_lost_checkout_answer_does_not_block_later_payment_update(rig):
    await send(rig, command())
    payload = invoices(rig)[0]['payload']
    rig[1].fail_answer = True  # Telegram may have accepted the answer before losing its HTTP reply.
    bot = await send(rig, checkout(payload))
    assert bot.offset == 2
    rig[1].fail_answer = False
    rig[1].reject_answer = True  # The same checkout cannot be answered once its deadline passed.
    rig[3][0] += timedelta(seconds=11)
    retry = Bot(rig[2], bot.client, public_url='https://master.invalid', clock=lambda: rig[3][0])
    rig[1].updates = [checkout(payload), payment(payload)]
    await retry.poll('900:synthetic-not-live')
    assert retry.offset == 4
    assert order_row(rig[2])['state'] == 'paid'
    with Session(rig[2]) as db:
        subscription = db.get(Subscription, 1)
        assert subscription is not None
        assert subscription.expires_at == EXPIRY + timedelta(days=30)
