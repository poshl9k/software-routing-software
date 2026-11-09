"""Fail-closed one-off Stars test. No network I/O in writer transactions."""
import json
import os
import re
import secrets
import time
from datetime import timedelta
from hashlib import sha256
from typing import TypedDict

from sqlalchemy import select, text
from sqlalchemy.orm import Session
from cryptography.fernet import InvalidToken

from vs_portal.security import get_secret_key
from vs_router.secrets import decrypt_secret

from .models import (Account, Audit, Device, DeviceOp, Node, PaymentReceipt, StarsFulfillment,
                     StarsOrder, StarsPaymentEvent, Subscription, Tariff)
from .notifications import enqueue_subscription

SLOT = 'super-30d-1xtr-v1'
RETRY_SLOT = 'super-30d-1xtr-retry-v1'


class PaymentValues(TypedDict):
    telegram_charge_id: str
    payer_chat_id: str
    currency: str
    amount: int
    payload_hash: str


def opted_account():
    value = os.environ.get('VS_MASTER_STARS_TEST_ACCOUNT_ID', '')
    if (os.environ.get('VS_MASTER_STARS_TEST_ENABLED') == '1'
            and re.fullmatch(r'[1-9][0-9]{0,8}', value)):
        return int(value)
    return None


def _write(db):
    if db.get_bind().dialect.name != 'sqlite':
        raise ValueError('Stars test requires SQLite writer serialization')
    db.execute(text('BEGIN IMMEDIATE'))


def _ready(db, account_id, payer, now, order=None):
    account = db.get(Account, account_id)
    if (account is None or account.status != 'active' or account.telegram_linked_at is None
            or account.telegram_chat_id != str(payer)
            or account.telegram_linked_chat_id != str(payer)
            or (order is not None and account.telegram_linked_at != order.linked_at)):
        return None
    subscription = db.scalar(select(Subscription).where(
        Subscription.account_id == account_id).order_by(Subscription.id.desc()))
    tariff = db.get(Tariff, subscription.tariff_id) if subscription else None
    if (subscription is None or subscription.status != 'active' or subscription.expires_at <= now
            or tariff is None or tariff.id != 3 or tariff.name != 'Super' or tariff.device_limit != 50
            or (order is not None and (subscription.id != order.subscription_id
                                      or subscription.expires_at != order.prior_expires_at))):
        return None
    devices = list(db.scalars(select(Device).where(
        Device.account_id == account_id, Device.status != 'removed')))
    nodes = {}
    for device in devices:
        node = db.get(Node, device.node_id)
        if (node is None or not node.enabled or node.state != 'ok'
                or (device.status == 'active' and (not device.private_key or not device.public_key
                    or not device.tunnel_name or not device.allowed_ips))):
            return None
        nodes[node.id] = node
    try:
        for device in devices:
            if device.private_key:
                decrypt_secret(device.private_key, get_secret_key())
            if device.preshared_key:
                decrypt_secret(device.preshared_key, get_secret_key())
        for node in nodes.values():
            decrypt_secret(node.bridge_token, get_secret_key())
    except (InvalidToken, ValueError, KeyError):
        return None
    if db.scalar(select(DeviceOp.id).where(
            DeviceOp.account_id == account_id, DeviceOp.status == 'pending')) is not None:
        return None
    return account, subscription, tariff


def prepare_invoice(engine, bot_id, payer, clock):
    """Reserve a new slot before sending; never reuse an ambiguous invoice."""
    account_id = opted_account()
    if account_id is None:
        return None
    with Session(engine) as db:
        _write(db)
        now = clock()
        ready = _ready(db, account_id, payer, now)
        if ready is None:
            return None
        orders = list(db.scalars(select(StarsOrder).order_by(StarsOrder.id)))
        if not orders:
            slot = SLOT
        elif len(orders) == 1:
            prior = orders[0]
            if (prior.test_slot != SLOT or prior.state != 'sent' or prior.bot_id != bot_id
                    or prior.account_id != account_id or prior.payer_chat_id != str(payer)
                    or prior.expires_at > now or prior.sent_at is None
                    or type(prior.message_id) is not int or prior.message_id <= 0
                    or prior.checkout_id is not None or prior.approved_at is not None
                    or prior.paid_charge_id is not None or prior.fulfillment_status != 'pending'
                    or _ready(db, account_id, payer, now, prior) is None
                    or db.scalar(select(PaymentReceipt.telegram_charge_id)) is not None
                    or db.scalar(select(StarsPaymentEvent.fingerprint)) is not None):
                return None
            slot = RETRY_SLOT
        else:
            return None
        account, subscription, tariff = ready
        payload = secrets.token_urlsafe(32)
        order = StarsOrder(test_slot=slot, bot_id=bot_id, account_id=account.id,
                           subscription_id=subscription.id, tariff_id=tariff.id, tariff_name=tariff.name,
                           device_limit=tariff.device_limit, payer_chat_id=str(payer),
                           linked_at=account.telegram_linked_at, currency='XTR', amount=1, term_days=30,
                           prior_expires_at=subscription.expires_at, payload_hash=sha256(payload.encode()).hexdigest(),
                           created_at=now, expires_at=now + timedelta(minutes=10), state='sending')
        db.add(order)
        db.flush()
        order_id = order.id
        db.commit()
    return order_id, {
        'chat_id': payer, 'title': 'Super: тестовое продление',
        'description': ('Реальная разовая оплата 1 Star: +30 дней Super, 50 устройств. '
                        'Без автопродления. Оплачивая счёт, вы соглашаетесь с /terms. '
                        'Поддержка: /paysupport (@poshl9k).'),
        'payload': payload, 'currency': 'XTR', 'prices': [{'label': 'Super +30 дней', 'amount': 1}],
        'start_parameter': 'super-test', 'protect_content': True}


def invoice_sent(engine, order_id, payer, result, clock):
    chat = result.get('chat') if isinstance(result, dict) else None
    if (not isinstance(result, dict) or type(result.get('message_id')) is not int
            or result['message_id'] <= 0 or not isinstance(chat, dict)
            or type(chat.get('id')) is not int or chat['id'] != payer or chat.get('type') != 'private'):
        raise ValueError('Invalid invoice acknowledgement')
    with Session(engine) as db:
        _write(db)
        order = db.get(StarsOrder, order_id)
        if order is not None and order.state == 'sending':
            order.state, order.sent_at, order.message_id = 'sent', clock(), result['message_id']
            db.commit()


def approve_checkout(engine, bot_id, query, clock, deadline):
    account_id = opted_account()
    payer = query.get('from')
    payload = query.get('invoice_payload')
    if (account_id is None or not isinstance(payer, dict) or type(payer.get('id')) is not int
            or payer['id'] <= 0 or not isinstance(payload, str) or not 1 <= len(payload) <= 128
            or query.get('currency') != 'XTR' or type(query.get('total_amount')) is not int
            or query['total_amount'] != 1 or not isinstance(query.get('id'), str)
            or not 1 <= len(query['id']) <= 255):
        return False
    with Session(engine) as db:
        _write(db)
        now = clock()
        order = db.scalar(select(StarsOrder).where(
            StarsOrder.payload_hash == sha256(payload.encode()).hexdigest()))
        if (order is None or order.bot_id != bot_id or order.state != 'sent'
                or (order.test_slot == SLOT and db.scalar(select(StarsOrder.id).where(
                    StarsOrder.test_slot == RETRY_SLOT)) is not None)
                or order.account_id != account_id or order.payer_chat_id != str(payer['id'])
                or order.expires_at <= now or now < order.created_at
                or (order.checkout_id is not None and order.checkout_id != query['id'])
                or _ready(db, account_id, payer['id'], now, order) is None
                or time.monotonic() >= deadline):
            return False
        order.checkout_id = query['id']
        order.approved_at = order.approved_at or now
        db.commit()
        return True


def checkout_answer_expired(engine, bot_id, query, clock):
    """A previously attempted answer cannot be retried after Telegram's deadline.

    A successful first answer may have captured a charge despite a lost HTTP
    response. Advance only this stale pre-checkout update so the following
    successful_payment can be processed; the approved order remains durable.
    """
    payload = query.get('invoice_payload')
    checkout_id = query.get('id')
    if not isinstance(payload, str) or not isinstance(checkout_id, str):
        return False
    with Session(engine) as db:
        order = db.scalar(select(StarsOrder).where(
            StarsOrder.payload_hash == sha256(payload.encode()).hexdigest()))
        return bool(order is not None and order.bot_id == bot_id
                    and order.checkout_id == checkout_id and order.approved_at is not None
                    and clock() >= order.approved_at + timedelta(seconds=10))


def _payment(message, bot_id):
    payer = message.get('from')
    payment = message.get('successful_payment')
    if not isinstance(payer, dict) or not isinstance(payment, dict):
        raise ValueError('Invalid payment update')
    identity = payer.get('id')
    charge, currency = payment.get('telegram_payment_charge_id'), payment.get('currency')
    amount, payload = payment.get('total_amount'), payment.get('invoice_payload')
    if (type(identity) is not int or identity <= 0 or not isinstance(charge, str)
            or not 1 <= len(charge) <= 255 or not isinstance(currency, str) or len(currency) != 3
            or type(amount) is not int or amount <= 0 or not isinstance(payload, str)
            or not 1 <= len(payload.encode()) <= 128):
        raise ValueError('Invalid payment update')
    chat = message.get('chat')
    private = (isinstance(chat, dict) and chat.get('type') == 'private'
               and type(chat.get('id')) is int and chat['id'] == identity)
    recurring = any(payment.get(k) not in (None, False) for k in (
        'is_recurring', 'is_first_recurring', 'subscription_expiration_date'))
    values = PaymentValues(telegram_charge_id=charge, payer_chat_id=str(identity), currency=currency,
                  amount=amount, payload_hash=sha256(payload.encode()).hexdigest())
    fingerprint = sha256(json.dumps(values | {'bot_id': bot_id, 'private': private,
                                              'recurring': recurring}, sort_keys=True).encode()).hexdigest()
    return values, fingerprint, private and not recurring


def _paid_target(db, order):
    account = db.get(Account, order.account_id)
    subscription = db.scalar(select(Subscription).where(
        Subscription.account_id == order.account_id).order_by(Subscription.id.desc()))
    tariff = db.get(Tariff, order.tariff_id)
    if (account is None or account.status != 'active'
            or account.telegram_chat_id != order.payer_chat_id
            or account.telegram_linked_chat_id != order.payer_chat_id
            or account.telegram_linked_at != order.linked_at
            or subscription is None or subscription.id != order.subscription_id
            or subscription.tariff_id != order.tariff_id
            or subscription.expires_at < order.prior_expires_at
            or tariff is None or tariff.name != order.tariff_name or tariff.device_limit != order.device_limit):
        return None
    return subscription


def accept_payment(engine, bot_id, message, clock):
    """Receipt + ledger + master grant + node tickets + notice in ONE commit.

    Approved captures survive opt-out/restart/delayed delivery. Unknown payments
    never grant. Conflicts commit review evidence, then raise to retain offset.
    """
    values, fingerprint, context_valid = _payment(message, bot_id)
    review = False
    with Session(engine) as db:
        _write(db)
        now = clock()
        event = db.get(StarsPaymentEvent, fingerprint)
        if event is not None:
            if event.status == 'review':
                raise ValueError('Payment requires manual review')
            return
        receipt = db.get(PaymentReceipt, values['telegram_charge_id'])
        conflict = receipt is not None and any(getattr(receipt, k) != v for k, v in values.items())
        # Never promote a legacy unmatched receipt into a paid grant on replay.
        legacy = receipt is not None and db.scalar(select(StarsPaymentEvent.fingerprint).where(
            StarsPaymentEvent.telegram_charge_id == receipt.telegram_charge_id)) is None
        if receipt is None:
            db.add(PaymentReceipt(**values, received_at=now))
            db.flush()
        order = db.scalar(select(StarsOrder).where(StarsOrder.payload_hash == values['payload_hash']))
        event = StarsPaymentEvent(**values, fingerprint=fingerprint, order_id=order.id if order else None,
                                  status='unmatched', received_at=now)
        db.add(event)
        subscription = _paid_target(db, order) if order is not None else None
        if conflict or (order is not None and (
                legacy or not context_valid or order.bot_id != bot_id or order.state != 'sent'
                or order.approved_at is None or order.approved_at >= order.expires_at
                or values['payer_chat_id'] != order.payer_chat_id
                or values['currency'] != order.currency or values['amount'] != order.amount
                or subscription is None)):
            event.status, event.reason = 'review', 'payment.conflict'
            if order is not None and order.state != 'paid':
                order.state, order.fulfillment_status = 'review', 'review'
            db.add(Audit(actor='master', action='payment.review', at=now))
            review = True
        elif order is None:
            db.add(Audit(actor='master', action='payment.unmatched', at=now))
        else:
            assert order is not None and subscription is not None
            try:
                expires = max(now, subscription.expires_at) + timedelta(days=order.term_days)
            except OverflowError:
                event.status, event.reason = 'review', 'payment.expiry_overflow'
                order.state, order.fulfillment_status = 'review', 'review'
                review = True
            else:
                subscription.expires_at, subscription.status, subscription.updated_at = expires, 'active', now
                subscription.notification_revision += 1
                enqueue_subscription(db, subscription, 'active', now)
                order.state, order.paid_charge_id, order.paid_at = 'paid', values['telegram_charge_id'], now
                order.granted_expires_at = expires
                node_ids = list(db.scalars(select(Device.node_id).where(
                    Device.account_id == order.account_id, Device.status != 'removed').distinct()))
                for node_id in node_ids:
                    # A fresh order-scoped ticket also repairs an active grant's
                    # expiry on nodes; process_pending does not infer this itself.
                    op = DeviceOp(account_id=order.account_id, node_id=node_id,
                                  op='expire', status='pending', created_at=now)
                    db.add(op)
                    db.flush()
                    db.add(StarsFulfillment(order_id=order.id, node_id=node_id, op_id=op.id))
                order.fulfillment_status = 'pending' if node_ids else 'applied'
                event.status = 'granted'
                db.add(Audit(actor='master', action='payment.granted', at=now))
        status = event.status
        db.commit()
    if review:
        raise ValueError('Payment requires manual review')
    return status


def refresh_fulfillments(engine):
    """Worker ACKs, not the charge or master grant, determine node completion."""
    with Session(engine) as db:
        _write(db)
        for order in db.scalars(select(StarsOrder).where(
                StarsOrder.state == 'paid', StarsOrder.fulfillment_status == 'pending')):
            ops = list(db.scalars(select(DeviceOp).join(
                StarsFulfillment, StarsFulfillment.op_id == DeviceOp.id).where(
                    StarsFulfillment.order_id == order.id)))
            if ops and all(op.status == 'applied' and op.detail == 'renewed' for op in ops):
                order.fulfillment_status = 'applied'
            elif any(op.status == 'failed' or (op.status == 'applied' and op.detail != 'renewed') for op in ops):
                order.fulfillment_status = 'review'
        db.commit()
