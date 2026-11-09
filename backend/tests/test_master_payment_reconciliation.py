"""Read-only admin reconciliation must expose failures without payment secrets."""
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import Session

from vs_master.app import create_master_app
from vs_master.models import (Account, Base, DeviceOp, Node, PaymentReceipt, StarsFulfillment,
                              StarsOrder, StarsPaymentEvent, Subscription, Tariff, make_engine)
from vs_router.secrets import encrypt_secret

pytestmark = pytest.mark.anyio
NOW = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
PATH = '/api/master-admin/payments/reconciliation'


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def master(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet

    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    engine = make_engine('sqlite:///' + (tmp_path / 'master.db').as_posix())
    Base.metadata.create_all(engine)
    app = create_master_app(engine=engine, clock=lambda: NOW)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://master.test') as client:
        yield client, engine
    engine.dispose()


async def login(client):
    assert (await client.post('/api/admin/setup', json={'password': 'synthetic-admin-password'})).status_code == 201
    assert (await client.post('/api/admin/login', json={'password': 'synthetic-admin-password'})).status_code == 200


def order(slot, payload, created, *, state='sent', paid_at=None, charge=None, fulfillment='pending'):
    return StarsOrder(test_slot=slot, bot_id='synthetic-bot', account_id=1, subscription_id=1,
                      tariff_id=3, tariff_name='Super', device_limit=50, payer_chat_id='100',
                      linked_at=NOW - timedelta(days=1), currency='XTR', amount=1, term_days=30,
                      prior_expires_at=NOW + timedelta(days=30), payload_hash=payload * 64,
                      created_at=created, expires_at=created + timedelta(minutes=10),
                      state=state, sent_at=created, message_id=10,
                      paid_at=paid_at, paid_charge_id=charge,
                      granted_expires_at=NOW + timedelta(days=60) if charge else None,
                      fulfillment_status=fulfillment)


async def test_admin_only_empty_read_is_non_mutating(master):
    client, engine = master
    assert (await client.get(PATH)).status_code == 401
    assert (await client.post(PATH)).status_code in (401, 405)
    await login(client)
    result = await client.get(PATH)
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    assert result.json() == {
        'summary': {'orders': 0, 'receipts': 0, 'granted_events': 0, 'review_events': 0,
                    'unmatched_events': 0, 'orphan_receipts': 0, 'pending_renewals': 0,
                    'review_orders': 0},
        'orders': [], 'next_before_id': None}
    assert (await client.get(PATH + '?limit=0')).status_code == 422
    assert (await client.get(PATH + '?limit=101')).status_code == 422
    assert (await client.get(PATH + '?before_id=-1')).status_code == 422


async def test_reconciliation_identifies_stalled_renewal_and_redacts_receipts(master):
    client, engine = master
    with Session(engine) as db:
        from vs_portal.security import get_secret_key

        db.add_all([Account(id=1, display_name='Synthetic', telegram_chat_id='100',
                            password_hash='never-show-password'),
                    Tariff(id=3, name='Super', device_limit=50, term_days=30),
                    Node(id=1, name='synthetic-node', bridge_url='https://node.invalid/internal',
                         bridge_token=encrypt_secret('never-show-node-token', get_secret_key()),
                         capacity=10, state='ok')])
        db.flush()
        db.add(Subscription(id=1, account_id=1, tariff_id=3,
                            expires_at=NOW + timedelta(days=60)))
        db.add_all([PaymentReceipt(telegram_charge_id='never-show-charge', payer_chat_id='100',
                                   currency='XTR', amount=1, payload_hash='b' * 64),
                    PaymentReceipt(telegram_charge_id='unmatched-secret-charge', payer_chat_id='100',
                                   currency='XTR', amount=1, payload_hash='c' * 64),
                    PaymentReceipt(telegram_charge_id='orphan-secret-charge', payer_chat_id='100',
                                   currency='XTR', amount=1, payload_hash='d' * 64)])
        db.flush()
        db.add(order('super-30d-1xtr-v1', 'a', NOW - timedelta(minutes=30)))
        db.add(order('super-30d-1xtr-retry-v1', 'b', NOW - timedelta(minutes=15),
                     state='paid', paid_at=NOW - timedelta(minutes=10),
                     charge='never-show-charge'))
        db.flush()
        db.add_all([StarsPaymentEvent(fingerprint='e' * 64, telegram_charge_id='never-show-charge',
                                      order_id=2, payer_chat_id='100', currency='XTR', amount=1,
                                      payload_hash='b' * 64, status='granted', received_at=NOW),
                    StarsPaymentEvent(fingerprint='f' * 64, telegram_charge_id='unmatched-secret-charge',
                                      order_id=None, payer_chat_id='100', currency='XTR', amount=1,
                                      payload_hash='c' * 64, status='unmatched', received_at=NOW)])
        op = DeviceOp(account_id=1, node_id=1, op='expire', status='pending',
                      detail='never-show-node-token', created_at=NOW)
        db.add(op)
        db.flush()
        db.add(StarsFulfillment(order_id=2, node_id=1, op_id=op.id))
        op_id = op.id
        db.commit()
    await login(client)
    result = await client.get(PATH + '?limit=1')
    assert result.status_code == 200
    data = result.json()
    assert data['summary'] == {'orders': 2, 'receipts': 3, 'granted_events': 1,
                               'review_events': 0, 'unmatched_events': 1,
                               'orphan_receipts': 1, 'pending_renewals': 1, 'review_orders': 0}
    assert data['next_before_id'] == 2
    assert data['orders'] == [{
        'id': 2, 'account_id': 1, 'state': 'paid', 'currency': 'XTR', 'amount': 1,
        'created_at': (NOW - timedelta(minutes=15)).isoformat(),
        'expires_at': (NOW - timedelta(minutes=5)).isoformat(),
        'paid_at': (NOW - timedelta(minutes=10)).isoformat(),
        'granted_expires_at': (NOW + timedelta(days=60)).isoformat(),
        'fulfillment_status': 'pending', 'attention': 'renewal.overdue',
        'operations': [{'node_id': 1, 'status': 'pending', 'detail': None}],
    }]
    older = (await client.get(PATH + '?limit=1&before_id=2')).json()
    assert older['next_before_id'] is None
    assert older['orders'][0]['id'] == 1 and older['orders'][0]['attention'] is None
    assert older['summary'] == data['summary']
    for secret in ('never-show', 'unmatched-secret-charge', 'orphan-secret-charge',
                   '100', 'a' * 64, 'b' * 64, 'e' * 64, 'f' * 64):
        assert secret not in result.text + str(older)
    with Session(engine) as db:
        assert db.query(StarsOrder).count() == 2
        assert db.query(StarsPaymentEvent).count() == 2
        paid = db.get(StarsOrder, 2)
        assert paid is not None
        paid.fulfillment_status = 'applied'
        operation = db.get(DeviceOp, op_id)
        assert operation is not None
        operation.status, operation.detail = 'applied', 'renewed'
        db.commit()
    completed = (await client.get(PATH + '?limit=1')).json()
    assert completed['summary']['pending_renewals'] == 0
    assert completed['orders'][0]['attention'] is None
    assert completed['orders'][0]['operations'] == [
        {'node_id': 1, 'status': 'applied', 'detail': 'renewed'}]


async def test_review_and_ambiguous_invoice_are_actionable(master):
    client, engine = master
    with Session(engine) as db:
        db.add_all([Account(id=1, display_name='Synthetic', telegram_chat_id='100',
                            password_hash='unused'),
                    Tariff(id=3, name='Super', device_limit=50, term_days=30)])
        db.flush()
        db.add(Subscription(id=1, account_id=1, tariff_id=3,
                            expires_at=NOW + timedelta(days=30)))
        db.flush()
        db.add(order('super-30d-1xtr-v1', 'a', NOW - timedelta(minutes=30),
                     state='sending'))
        db.add(order('super-30d-1xtr-retry-v1', 'b', NOW - timedelta(minutes=15),
                     state='review', fulfillment='review'))
        db.commit()
    await login(client)
    data = (await client.get(PATH)).json()
    assert data['summary']['review_orders'] == 1
    assert [item['attention'] for item in data['orders']] == ['payment.review', 'invoice.ack_unknown']
