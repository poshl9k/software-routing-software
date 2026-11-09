"""One-off real-price Stars path; all Telegram/bridge I/O is synthetic."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vs_master.models import (Account, Base, Device, DeviceOp, Node, PaymentReceipt,
                              Subscription, SubscriptionNotification, Tariff, make_engine)
from vs_master.telegram_bot import Bot
from vs_master.worker import process_pending
from vs_router.secrets import encrypt_secret

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)
EXPIRY = NOW + timedelta(days=30, hours=8, minutes=17, seconds=13)
TOKEN = '900:synthetic-not-live'
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


class Telegram:
    def __init__(self):
        self.updates = []
        self.calls = []
        self.fail_invoice = False
        self.bad_ack = False
        self.fail_answer = False
        self.reject_answer = False

    def __call__(self, request):
        method = request.url.path.rsplit('/', 1)[-1]
        payload = json.loads(request.content)
        self.calls.append((method, payload))
        if method == 'sendInvoice' and self.fail_invoice:
            raise httpx.ReadTimeout('synthetic transport loss')
        if method == 'answerPreCheckoutQuery' and self.fail_answer:
            raise httpx.ReadTimeout('synthetic lost pre-checkout answer')
        if method == 'answerPreCheckoutQuery' and self.reject_answer:
            return httpx.Response(400, json={'ok': False, 'description': 'query is too old'})
        result = self.updates if method == 'getUpdates' else (
            {'message_id': 10, 'chat': {'id': 999 if self.bad_ack else 100, 'type': 'private'}}
            if method == 'sendInvoice' else True)
        return httpx.Response(200, json={'ok': True, 'result': result})


@pytest.fixture
async def rig(tmp_path, monkeypatch):
    monkeypatch.setenv('VS_MASTER_STARS_TEST_ENABLED', '1')
    monkeypatch.setenv('VS_MASTER_STARS_TEST_ACCOUNT_ID', '1')
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    engine = make_engine('sqlite:///' + (tmp_path / 'stars.db').as_posix())
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([
            Account(id=1, display_name='Test', telegram_chat_id='100', password_hash='unused',
                    telegram_linked_chat_id='100', telegram_linked_at=NOW),
            Account(id=2, display_name='Other', telegram_chat_id='200', password_hash='unused',
                    telegram_linked_chat_id='200', telegram_linked_at=NOW),
            Tariff(id=1, name='Base', device_limit=3, term_days=30),
            Tariff(id=3, name='Super', device_limit=50, term_days=30),
            Node(id=1, name='synthetic', bridge_url='https://node.invalid',
                 bridge_token=encrypt_secret('synthetic', key), state='ok', enabled=True)])
        db.flush()
        db.add(Subscription(id=1, account_id=1, tariff_id=3, expires_at=EXPIRY,
                            notification_revision=1, updated_at=NOW))
        db.flush()
        db.add(SubscriptionNotification(subscription_id=1, revision=1, kind='active',
                                       chat_id='100', linked_at=NOW, expires_at=EXPIRY,
                                       next_attempt_at=NOW))
        for identity in (1, 2):
            db.add(Device(id=identity, account_id=1, node_id=1, node_subscriber='owner',
                          name=f'd{identity}', label=f'Device {identity}', status='active',
                          public_key=f'public-{identity}', private_key=encrypt_secret('synthetic', key),
                          allowed_ips=[f'10.0.0.{identity + 1}/32'], tunnel_name='wg0'))
        db.commit()
    telegram = Telegram()
    clock = [NOW]
    async with httpx.AsyncClient(transport=httpx.MockTransport(telegram)) as client:
        bot = Bot(engine, client, public_url='https://master.invalid', clock=lambda: clock[0])
        yield bot, telegram, engine, clock
    engine.dispose()


def command(update_id=1, identity=100, sender=100, kind='private'):
    return {'update_id': update_id, 'message': {'chat': {'id': identity, 'type': kind},
            'from': {'id': sender}, 'text': '/buy'}}


async def send(rig, update, *, restart=False, token=TOKEN):
    bot, telegram, engine, clock = rig
    telegram.updates = [update]
    if restart:
        bot = Bot(engine, bot.client, public_url='https://master.invalid', clock=lambda: clock[0])
    await bot.poll(token)
    return bot


def invoices(rig):
    return [p for m, p in rig[1].calls if m == 'sendInvoice']


@pytest.mark.parametrize('text', ['/paysupport', '/support', '/terms'])
async def test_payment_terms_and_support_reachable_without_purchase_or_link(rig, text):
    update = command(identity=200, sender=200)
    update['message']['text'] = text
    await send(rig, update)
    messages = [p for method, p in rig[1].calls if method == 'sendMessage']
    assert len(messages) == 1
    assert messages[0]['chat_id'] == 200
    assert '@poshl9k' in messages[0]['text']
    if text == '/terms':
        assert all(value in messages[0]['text'] for value in ('1 Star', '30 дней', '50 устройств',
                                                             'Автопродления нет'))
    else:
        assert 'возврата' in messages[0]['text']
    assert 'Поддержка Telegram' in messages[0]['text']
    assert not invoices(rig)


async def test_payment_support_never_replies_to_group_or_mismatched_sender(rig):
    for update in (command(kind='group'), command(sender=200)):
        update['message']['text'] = '/paysupport'
        await send(rig, update, restart=True)
    assert not [p for method, p in rig[1].calls if method == 'sendMessage']


async def test_invoice_is_durable_exact_one_time_price_and_never_resent(rig):
    await send(rig, command())
    assert len(invoices(rig)) == 1
    invoice = invoices(rig)[0]
    assert invoice == {
        'chat_id': 100, 'title': 'Super: тестовое продление',
        'description': ('Реальная разовая оплата 1 Star: +30 дней Super, 50 устройств. '
                        'Без автопродления. Оплачивая счёт, вы соглашаетесь с /terms. '
                        'Поддержка: /paysupport (@poshl9k).'),
        'payload': invoice['payload'], 'currency': 'XTR',
        'prices': [{'label': 'Super +30 дней', 'amount': 1}],
        'start_parameter': 'super-test', 'protect_content': True}
    assert 32 <= len(invoice['payload']) <= 128
    await send(rig, command(2), restart=True)
    assert len(invoices(rig)) == 1
    with rig[2].connect() as db:
        order = db.execute(text('SELECT * FROM master_stars_orders')).mappings().one()
        assert order['state'] == 'sent'
        assert order['amount'] == 1 and order['term_days'] == 30
        assert order['account_id'] == 1 and order['tariff_id'] == 3
        assert invoice['payload'] not in str(dict(order))
    with Session(rig[2]) as db:
        subscription = db.get(Subscription, 1)
        assert subscription is not None and subscription.expires_at == EXPIRY
        assert db.scalar(select(PaymentReceipt)) is None


def checkout(payload, update_id=2, **changes):
    query = {'id': 'synthetic-checkout', 'from': {'id': 100}, 'currency': 'XTR',
             'total_amount': 1, 'invoice_payload': payload}
    query.update(changes)
    return {'update_id': update_id, 'pre_checkout_query': query}


async def approved(rig):
    await send(rig, command())
    payload = invoices(rig)[0]['payload']
    await send(rig, checkout(payload))
    return payload


async def test_checkout_validates_and_persists_one_approval_across_restart(rig):
    await approved(rig)
    answers = [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery']
    assert answers[-1] == {'pre_checkout_query_id': 'synthetic-checkout', 'ok': True}
    with rig[2].connect() as db:
        assert db.execute(text('SELECT checkout_id, approved_at FROM master_stars_orders')).one()[0] == 'synthetic-checkout'
    await send(rig, checkout(invoices(rig)[0]['payload'], 3), restart=True)
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is True
    await send(rig, checkout(invoices(rig)[0]['payload'], 4, id='different-checkout'))
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False


@pytest.mark.parametrize('changes', [
    {'from': {'id': 200}}, {'from': {'id': True}}, {'currency': 'USD'},
    {'total_amount': 2}, {'total_amount': True}, {'invoice_payload': 'unknown'},
    {'invoice_payload': None}])
async def test_checkout_mismatch_fails_closed(rig, changes):
    await send(rig, command())
    await send(rig, checkout(invoices(rig)[0]['payload'], **changes))
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False


@pytest.mark.parametrize('change', ['disabled', 'allowlist', 'expired', 'link', 'tariff', 'node', 'subscription', 'pending'])
async def test_checkout_rechecks_live_state(rig, monkeypatch, change):
    await send(rig, command())
    if change == 'disabled':
        monkeypatch.delenv('VS_MASTER_STARS_TEST_ENABLED')
    elif change == 'allowlist':
        monkeypatch.setenv('VS_MASTER_STARS_TEST_ACCOUNT_ID', '2')
    elif change == 'expired':
        rig[3][0] += timedelta(minutes=11)
    else:
        with Session(rig[2]) as db:
            if change == 'link':
                db.get(Account, 1).telegram_linked_at += timedelta(seconds=1)
            elif change == 'tariff':
                db.get(Tariff, 3).device_limit = 3
            elif change == 'node':
                db.get(Node, 1).enabled = False
            elif change == 'subscription':
                db.get(Subscription, 1).tariff_id = 1
            else:
                db.add(DeviceOp(account_id=1, node_id=1, op='deactivate', device_id=1))
            db.commit()
    await send(rig, checkout(invoices(rig)[0]['payload']))
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False


@pytest.mark.parametrize('value', ['', '0', '-1', '01', '1,2', ' 1', 'True'])
async def test_invoice_requires_exact_opt_in_allowlist(rig, monkeypatch, value):
    monkeypatch.setenv('VS_MASTER_STARS_TEST_ACCOUNT_ID', value)
    await send(rig, command())
    assert not invoices(rig)


@pytest.mark.parametrize('mode', ['flag', 'stranger', 'group', 'sender', 'unlinked', 'inactive', 'base'])
async def test_invoice_unauthorized_never_sends(rig, monkeypatch, mode):
    update = command()
    if mode == 'flag':
        monkeypatch.delenv('VS_MASTER_STARS_TEST_ENABLED')
    elif mode == 'stranger':
        update = command(identity=200, sender=200)
    elif mode == 'group':
        update = command(kind='group')
    elif mode == 'sender':
        update = command(sender=200)
    else:
        with Session(rig[2]) as db:
            if mode == 'unlinked':
                db.get(Account, 1).telegram_linked_at = None
            elif mode == 'inactive':
                db.get(Account, 1).status = 'disabled'
            else:
                db.get(Subscription, 1).tariff_id = 1
            db.commit()
    await send(rig, update)
    assert not invoices(rig)


@pytest.mark.parametrize('bad_ack', [True, False])
async def test_ambiguous_invoice_send_consumes_slot_without_retry(rig, bad_ack):
    rig[1].bad_ack = bad_ack
    rig[1].fail_invoice = not bad_ack
    bot = await send(rig, command())
    assert bot.offset is None
    await send(rig, command(), restart=True)
    assert len(invoices(rig)) == 1
    with rig[2].connect() as db:
        assert db.scalar(text('SELECT state FROM master_stars_orders')) == 'sending'
    await send(rig, checkout(invoices(rig)[0]['payload']), restart=True)
    assert [p for m, p in rig[1].calls if m == 'answerPreCheckoutQuery'][-1]['ok'] is False
