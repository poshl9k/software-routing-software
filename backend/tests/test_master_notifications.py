"""Durable, opt-in master subscription notifications; no live Telegram calls."""
import asyncio
from datetime import datetime, timedelta, timezone
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from vs_master.accounts import register_telegram
from vs_master.app import create_master_app
from vs_master.models import Account, Base, Subscription, Tariff, make_engine
from vs_master.worker import process_pending


NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)
MESSAGE = {'text': '/start', 'chat': {'id': 12345, 'type': 'private'},
           'from': {'id': 12345, 'first_name': 'Ира'}}


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def engine(tmp_path):
    value = make_engine(f"sqlite:///{tmp_path / 'notifications.db'}")
    Base.metadata.create_all(value)
    yield value
    value.dispose()


def test_only_verified_private_start_links_existing_and_new_accounts(engine):
    with Session(engine) as db:
        db.add(Account(display_name='Admin-created', telegram_chat_id='12345', password_hash='x'))
        db.commit()
    assert register_telegram(engine, {**MESSAGE, 'from': {'id': 999}}) is None
    with Session(engine) as db:
        assert getattr(db.get(Account, 1), 'telegram_linked_at', None) is None
    assert register_telegram(engine, MESSAGE) == (1, False)
    with Session(engine) as db:
        linked = getattr(db.get(Account, 1), 'telegram_linked_at', None)
        assert linked is not None, 'A stored numeric chat ID alone is not a verified private-chat link'
    assert register_telegram(engine, MESSAGE) == (1, False)
    with Session(engine) as db:
        assert db.get(Account, 1).telegram_linked_at == linked
    other = {**MESSAGE, 'chat': {'id': 67890, 'type': 'private'}, 'from': {'id': 67890}}
    assert register_telegram(engine, other) == (2, True)
    with Session(engine) as db:
        assert db.get(Account, 2).telegram_linked_at is not None
        db.get(Account, 1).status = 'disabled'
        db.get(Account, 1).telegram_linked_at = None
        db.commit()
    assert register_telegram(engine, MESSAGE) is None
    with Session(engine) as db:
        assert db.get(Account, 1).telegram_linked_at is None


def admin(engine, clock=lambda: NOW):
    client = TestClient(create_master_app(engine, clock=clock), base_url='https://master.test')
    assert client.post('/api/admin/setup', json={'password': 'test-password'}).status_code == 201
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200
    with Session(engine) as db:
        db.add(Tariff(name='Base', device_limit=2, term_days=30))
        db.commit()
    return client


def events(engine):
    assert 'master_subscription_notifications' in inspect(engine).get_table_names(), \
        'Subscription mutations need a transactional durable outbox'
    with engine.connect() as connection:
        return connection.execute(text(
            'SELECT * FROM master_subscription_notifications ORDER BY id')).mappings().all()


def assign(client, expiry, *, days=None):
    body = {'tariff_id': 1, 'days': days} if days else {'tariff_id': 1, 'expires_at': expiry.isoformat()}
    return client.put('/api/master-admin/subscribers/1/subscription', json=body)


def test_past_expiry_tariff_change_persists_without_reactivation_or_notice(engine):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    expiry = NOW + timedelta(days=1)
    assert assign(client, expiry).status_code == 200
    process_pending(engine, now=expiry)
    api_time[0] = expiry + timedelta(seconds=1)
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200
    with Session(engine) as db:
        db.add(Tariff(name='Alternate', device_limit=4, term_days=60))
        db.commit()
        alternate = db.scalar(select(Tariff).where(Tariff.name == 'Alternate')).id
    response = client.put('/api/master-admin/subscribers/1/subscription', json={
        'tariff_id': alternate, 'expires_at': expiry.isoformat()})
    assert response.status_code == 200
    assert response.json()['status'] == 'expired'
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        assert subscription.tariff_id == alternate
        assert subscription.status == 'expired'
        assert subscription.notification_revision == 1
    process_pending(engine, now=api_time[0])
    assert [(row['revision'], row['kind']) for row in events(engine)] == [(1, 'active'), (1, 'expired')]


def test_future_absolute_expiry_tariff_change_renews_and_activates(engine):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    expiry = NOW + timedelta(days=1)
    assert assign(client, expiry).status_code == 200
    process_pending(engine, now=expiry)
    api_time[0] = expiry + timedelta(seconds=1)
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200
    with Session(engine) as db:
        db.add(Tariff(name='Alternate', device_limit=4, term_days=60))
        db.commit()
        alternate = db.scalar(select(Tariff).where(Tariff.name == 'Alternate')).id
    future = NOW + timedelta(days=10)
    response = client.put('/api/master-admin/subscribers/1/subscription', json={
        'tariff_id': alternate, 'expires_at': future.isoformat()})
    assert response.status_code == 200
    assert response.json()['status'] == 'active'
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        assert subscription.tariff_id == alternate
        assert subscription.expires_at == future
        assert subscription.status == 'active'
        assert subscription.notification_revision == 2
    assert [(row['revision'], row['kind']) for row in events(engine)] == [(1, 'active'), (1, 'expired'), (2, 'active')]


def test_additive_days_overflow_returns_validation_error_not_server_error(engine):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    maximum = datetime.max.replace(tzinfo=timezone.utc)
    assert assign(client, maximum).status_code == 200
    api_time[0] = maximum
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200

    response = assign(client, None, days=1)
    assert response.status_code == 422
    assert response.json()['error']['code'] == 'master.subscription_term_invalid'
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        assert subscription is not None
        assert subscription.expires_at == maximum
        assert subscription.notification_revision == 1


def test_admin_shortening_active_subscription_to_past_enqueues_one_expiry(engine):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    assert assign(client, NOW + timedelta(days=1)).status_code == 200

    response = assign(client, NOW - timedelta(seconds=1))
    assert response.status_code == 200 and response.json()['status'] == 'expired'
    assert [(row['revision'], row['kind']) for row in events(engine)] == [
        (1, 'active'), (2, 'expired')]
    process_pending(engine, now=NOW)
    assert len(events(engine)) == 2


def test_admin_after_elapsed_expiry_before_worker_does_not_lose_notice(engine):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    expiry = NOW + timedelta(days=1)
    assert assign(client, expiry).status_code == 200
    api_time[0] = expiry + timedelta(seconds=1)
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200

    response = assign(client, expiry)
    assert response.status_code == 200 and response.json()['status'] == 'expired'
    assert [(row['revision'], row['kind']) for row in events(engine)] == [
        (1, 'active'), (1, 'expired')]
    process_pending(engine, now=api_time[0])
    assert len(events(engine)) == 2


def test_admin_assignment_is_durable_and_identical_put_and_worker_do_not_repeat(engine):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    expiry = NOW + timedelta(days=30)
    assert assign(client, expiry).status_code == 200
    assert len(events(engine)) == 1
    assert events(engine)[0]['kind'] == 'active'
    assert assign(client, expiry).status_code == 200
    process_pending(engine, now=NOW)
    process_pending(engine, now=NOW)
    assert len(events(engine)) == 1
    assert assign(client, None, days=1).status_code == 200
    assert [(row['revision'], row['kind']) for row in events(engine)] == [(1, 'active'), (2, 'active')]


def test_identical_expired_absolute_put_does_not_reactivate_or_repeat_expiry(engine):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    expiry = NOW + timedelta(days=1)
    assert assign(client, expiry).status_code == 200
    process_pending(engine, now=expiry)
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        assert subscription.status == 'expired'
        assert subscription.notification_revision == 1
    api_time[0] = expiry + timedelta(seconds=1)
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200
    assert assign(client, expiry).status_code == 200
    with Session(engine) as db:
        subscription = db.scalar(select(Subscription))
        assert subscription.status == 'expired'
        assert subscription.notification_revision == 1
    process_pending(engine, now=expiry + timedelta(seconds=1))
    assert [(row['revision'], row['kind']) for row in events(engine)] == [
        (1, 'active'), (1, 'expired')]


def test_expiry_is_once_per_grant_and_renewal_allows_another_expiry(engine):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    assert assign(client, NOW + timedelta(days=1)).status_code == 200
    for _ in range(2):
        process_pending(engine, now=NOW + timedelta(days=1))
    assert [row['kind'] for row in events(engine)] == ['active', 'expired']
    assert assign(client, NOW + timedelta(days=2)).status_code == 200
    for _ in range(2):
        process_pending(engine, now=NOW + timedelta(days=2))
    assert [(row['revision'], row['kind']) for row in events(engine)] == [
        (1, 'active'), (1, 'expired'), (2, 'active'), (2, 'expired')]


@pytest.mark.parametrize('linked,status', [(False, 'active'), (True, 'disabled')])
def test_unlinked_or_inactive_accounts_generate_no_notifications(engine, linked, status):
    if linked:
        register_telegram(engine, MESSAGE)
    else:
        with Session(engine) as db:
            db.add(Account(display_name='Manual', telegram_chat_id='12345', password_hash='x'))
            db.commit()
    with Session(engine) as db:
        db.get(Account, 1).status = status
        db.commit()
    client = admin(engine)
    assert assign(client, NOW + timedelta(days=1)).status_code == 200
    process_pending(engine, now=NOW + timedelta(days=1))
    assert events(engine) == []


def test_subscription_mutation_rolls_back_if_outbox_insert_fails(engine):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    assert events(engine) == []
    with engine.begin() as connection:
        connection.execute(text("CREATE TRIGGER fail_notification BEFORE INSERT ON "
                                "master_subscription_notifications BEGIN SELECT RAISE(ABORT, 'test'); END"))
    try:
        with pytest.raises(Exception, match='test'):
            assign(client, NOW + timedelta(days=1))
        with Session(engine) as db:
            assert db.scalar(select(Subscription)) is None
    finally:
        with engine.begin() as connection:
            connection.execute(text('DROP TRIGGER fail_notification'))
    assert assign(client, NOW + timedelta(days=1)).status_code == 200
    assert len(events(engine)) == 1


class StopCycle(Exception):
    pass


async def cycle(bot):
    async def stop(_delay):
        raise StopCycle
    with pytest.raises(StopCycle):
        await bot.run('synthetic-not-live', sleep=stop)


def bot_for(engine, client, *, enabled=False, now=NOW):
    from vs_master.models import Setting
    from vs_master.telegram_bot import Bot
    with Session(engine) as db:
        db.merge(Setting(key='master_public_url', value='https://master.test'))
        db.commit()
    return Bot(engine, client, public_url='https://master.test',
               notifications_enabled=enabled, clock=lambda: now)


def telegram_success(payload):
    return httpx.Response(200, json={'ok': True, 'result': {
        'message_id': 77, 'chat': {'id': payload['chat_id'], 'type': 'private'}}})


@pytest.mark.anyio
async def test_bot_runner_sends_only_when_opted_in_and_marks_after_success_without_writer_lock(engine):
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=30)).status_code == 200
    calls = []

    def api(request):
        method = request.url.path.rsplit('/', 1)[-1]
        if method == 'getUpdates':
            return httpx.Response(200, json={'ok': True, 'result': []})
        assert method == 'sendMessage'
        payload = json.loads(request.content)
        calls.append(payload)
        assert payload['chat_id'] == 12345
        assert 'Подписка активна' in payload['text']
        assert 'token' not in payload['text']
        assert events(engine)[0]['delivered_at'] is None
        # A separate SQLite writer must succeed while the network is in progress.
        with engine.begin() as connection:
            connection.execute(text('BEGIN IMMEDIATE'))
            connection.execute(text("UPDATE master_accounts SET display_name='Changed' WHERE id=1"))
        return telegram_success(payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
        await cycle(bot_for(engine, client))
        assert calls == []
        assert events(engine)[0]['attempts'] == 0
        await cycle(bot_for(engine, client, enabled=True))
        assert len(calls) == 1, 'The polling runner must drain the durable subscription outbox'
        assert events(engine)[0]['status'] == 'delivered'
        assert events(engine)[0]['message_id'] == 77
        assert events(engine)[0]['delivered_at'] is not None
        await cycle(bot_for(engine, client, enabled=True))
        assert len(calls) == 1


@pytest.mark.anyio
@pytest.mark.parametrize('failure', ['http', 'timeout', 'rejected', 'malformed'])
async def test_failed_delivery_survives_bot_restart_and_retries_with_backoff(engine, failure, caplog):
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=30)).status_code == 200
    calls = []

    def api(request):
        if request.url.path.endswith('/getUpdates'):
            return httpx.Response(200, json={'ok': True, 'result': []})
        assert request.url.path.endswith('/sendMessage')
        payload = json.loads(request.content)
        calls.append(payload)
        if len(calls) == 1:
            if failure == 'http':
                return httpx.Response(503)
            if failure == 'timeout':
                raise httpx.ReadTimeout('synthetic-not-live secret must not be logged', request=request)
            if failure == 'rejected':
                return httpx.Response(200, json={'ok': False})
            return httpx.Response(200, json={'ok': True, 'result': True})
        return telegram_success(payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
        await cycle(bot_for(engine, client, enabled=True))
        assert len(calls) == 1
        row = events(engine)[0]
        assert row['status'] == 'pending' and row['delivered_at'] is None
        assert row['attempts'] == 1
        await cycle(bot_for(engine, client, enabled=True, now=NOW + timedelta(seconds=29)))
        assert len(calls) == 1
        await cycle(bot_for(engine, client, enabled=True, now=NOW + timedelta(seconds=30)))
        assert len(calls) == 2
        assert events(engine)[0]['status'] == 'delivered'
        assert events(engine)[0]['attempts'] == 2
        await cycle(bot_for(engine, client, enabled=True, now=NOW + timedelta(hours=1)))
        assert len(calls) == 2
    assert 'synthetic-not-live' not in caplog.text


@pytest.mark.anyio
@pytest.mark.parametrize('change', ['disabled', 'unlinked', 'chat_changed', 'relinked', 'renewed', 'expired'])
async def test_delivery_rechecks_recipient_and_suppresses_obsolete_or_unauthorized_events(engine, change):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    assert assign(client, NOW + timedelta(days=30)).status_code == 200
    with Session(engine) as db:
        account = db.get(Account, 1)
        if change == 'disabled':
            account.status = 'disabled'
        elif change == 'unlinked':
            account.telegram_linked_at = None
        elif change == 'chat_changed':
            account.telegram_chat_id = '67890'
        elif change == 'relinked':
            account.telegram_linked_at += timedelta(seconds=1)
        db.commit()
    if change == 'renewed':
        assert assign(client, NOW + timedelta(days=31)).status_code == 200
    when = NOW + timedelta(days=30) if change == 'expired' else NOW
    calls = []

    def api(request):
        if request.url.path.endswith('/getUpdates'):
            return httpx.Response(200, json={'ok': True, 'result': []})
        calls.append(json.loads(request.content))
        return telegram_success(calls[-1])

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as http:
        await cycle(bot_for(engine, http, enabled=True, now=when))
    assert events(engine)[0]['status'] == 'suppressed'
    assert len(calls) == (1 if change == 'renewed' else 0)


@pytest.mark.anyio
async def test_expiry_delivery_is_private_and_old_expiry_is_not_sent_after_renewal(engine):
    register_telegram(engine, MESSAGE)
    client = admin(engine)
    assert assign(client, NOW + timedelta(days=1)).status_code == 200
    process_pending(engine, now=NOW + timedelta(days=1))
    calls = []

    def api(request):
        if request.url.path.endswith('/getUpdates'):
            return httpx.Response(200, json={'ok': True, 'result': []})
        calls.append(json.loads(request.content))
        return telegram_success(calls[-1])

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as http:
        await cycle(bot_for(engine, http, enabled=True, now=NOW + timedelta(days=1)))
        assert len(calls) == 1 and 'истёк' in calls[0]['text']
        assert calls[0]['chat_id'] == 12345
        assert [row['status'] for row in events(engine)] == ['suppressed', 'delivered']
        assert assign(client, NOW + timedelta(days=2)).status_code == 200
        process_pending(engine, now=NOW + timedelta(days=2))
        assert assign(client, NOW + timedelta(days=3)).status_code == 200
        await cycle(bot_for(engine, http, enabled=True, now=NOW + timedelta(days=2)))
    assert len(calls) == 2 and 'активна' in calls[1]['text']
    assert events(engine)[3]['status'] == 'suppressed'


@pytest.mark.anyio
@pytest.mark.parametrize('change', ['absolute', 'days', 'tariff'])
async def test_past_deadline_correction_preserves_unsent_expiry_notice(engine, change):
    register_telegram(engine, MESSAGE)
    api_time = [NOW]
    client = admin(engine, clock=lambda: api_time[0])
    expiry = NOW + timedelta(days=1)
    assert assign(client, expiry).status_code == 200
    api_time[0] = NOW + timedelta(days=3)
    process_pending(engine, now=api_time[0])
    client.cookies.clear()
    assert client.post('/api/admin/login', json={'password': 'test-password'}).status_code == 200
    corrected = NOW + timedelta(days=2)
    if change == 'days':
        response = assign(client, None, days=1)
    elif change == 'tariff':
        with Session(engine) as db:
            db.add(Tariff(name='Alternate', device_limit=4, term_days=60))
            db.commit()
        response = client.put('/api/master-admin/subscribers/1/subscription', json={
            'tariff_id': 2, 'expires_at': corrected.isoformat()})
    else:
        response = assign(client, corrected)
    assert response.status_code == 200 and response.json()['status'] == 'expired'
    assert [(row['revision'], row['kind']) for row in events(engine)] == [
        (1, 'active'), (1, 'expired')]
    sent = []

    def api(request):
        payload = json.loads(request.content)
        sent.append(payload)
        return telegram_success(payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as http:
        await bot_for(engine, http, enabled=True, now=api_time[0]).deliver_notifications(
            'synthetic-not-live')
    assert len(sent) == 1 and 'истёк' in sent[0]['text']
    assert [row['status'] for row in events(engine)] == ['suppressed', 'delivered']


def test_changing_an_account_identity_does_not_transfer_verified_private_chat_link(engine):
    register_telegram(engine, MESSAGE)
    with Session(engine) as db:
        account = db.get(Account, 1)
        assert account is not None
        account.telegram_chat_id = '67890'
        db.commit()
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    assert events(engine) == [], 'A link verified by one sender must not authorize another numeric ID'


@pytest.mark.anyio
async def test_abandoned_claim_is_recovered_after_restart_and_old_owner_cannot_ack(engine):
    from vs_master.notifications import claim_notification, finish_notification
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    first = claim_notification(engine, events(engine)[0]['id'], NOW)
    assert first is not None
    assert claim_notification(engine, events(engine)[0]['id'], NOW) is None
    assert claim_notification(engine, events(engine)[0]['id'], NOW + timedelta(seconds=59)) is None
    calls = []

    def api(request):
        calls.append(json.loads(request.content))
        return telegram_success(calls[-1])

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
        bot = bot_for(engine, client, enabled=True, now=NOW + timedelta(seconds=60))
        await bot.deliver_notifications('synthetic-not-live')
    assert len(calls) == 1 and events(engine)[0]['status'] == 'delivered'
    finish_notification(engine, events(engine)[0]['id'], first[0], NOW, message_id=999)
    assert events(engine)[0]['message_id'] == 77


@pytest.mark.anyio
async def test_concurrent_bots_share_durable_lease_without_duplicate_send(engine):
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def api(request):
        calls.append(json.loads(request.content))
        entered.set()
        await release.wait()
        return telegram_success(calls[-1])

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
        first, second = bot_for(engine, client, enabled=True), bot_for(engine, client, enabled=True)
        task = asyncio.create_task(first.deliver_notifications('synthetic-not-live'))
        try:
            await asyncio.wait_for(entered.wait(), timeout=5)
            await second.deliver_notifications('synthetic-not-live')
            assert len(calls) == 1
            assert events(engine)[0]['status'] == 'pending'
        finally:
            release.set()
            await task
    assert events(engine)[0]['status'] == 'delivered'


def test_concurrent_expiry_workers_generate_one_event(engine):
    from concurrent.futures import ThreadPoolExecutor
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    with ThreadPoolExecutor(max_workers=2) as pool:
        work = [pool.submit(process_pending, engine, now=NOW + timedelta(days=1)) for _ in range(2)]
        for result in work:
            result.result(timeout=5)
    assert [row['kind'] for row in events(engine)] == ['active', 'expired']


def test_unlinked_private_sender_cannot_read_subscription_or_receive_magic_link(engine):
    from vs_master.telegram_bot import Bot
    with Session(engine) as db:
        db.add(Account(display_name='Manual', telegram_chat_id='12345', password_hash='x'))
        db.commit()
    assert assign(admin(engine), NOW + timedelta(days=30)).status_code == 200
    bot = Bot(engine, None, public_url='https://master.test')
    assert bot.notifications_enabled is False
    for view in ('status', 'login'):
        reply = bot.reply(12345, view)
        assert reply == ('Аккаунт не найден. Отправьте /start.', None)


def test_expiry_rolls_back_together_with_failed_outbox_insert(engine):
    from sqlalchemy.exc import IntegrityError
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    with engine.begin() as connection:
        connection.execute(text("CREATE TRIGGER fail_expiry BEFORE INSERT ON master_subscription_notifications "
                                "WHEN NEW.kind='expired' BEGIN SELECT RAISE(ABORT, 'test-expiry'); END"))
    try:
        with pytest.raises(IntegrityError, match='test-expiry'):
            process_pending(engine, now=NOW + timedelta(days=1))
        with Session(engine) as db:
            subscription = db.scalar(select(Subscription))
            assert subscription is not None and subscription.status == 'active'
        assert [row['kind'] for row in events(engine)] == ['active']
    finally:
        with engine.begin() as connection:
            connection.execute(text('DROP TRIGGER fail_expiry'))
    process_pending(engine, now=NOW + timedelta(days=1))
    assert [row['kind'] for row in events(engine)] == ['active', 'expired']


@pytest.mark.anyio
async def test_successful_telegram_send_with_failed_local_ack_is_retried_at_least_once(engine):
    from sqlalchemy.exc import IntegrityError
    register_telegram(engine, MESSAGE)
    assert assign(admin(engine), NOW + timedelta(days=1)).status_code == 200
    with engine.begin() as connection:
        connection.execute(text("CREATE TRIGGER fail_ack BEFORE UPDATE ON master_subscription_notifications "
                                "WHEN NEW.status='delivered' BEGIN SELECT RAISE(ABORT, 'test-ack'); END"))
    calls = []

    def api(request):
        calls.append(json.loads(request.content))
        return telegram_success(calls[-1])

    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
        try:
            bot = bot_for(engine, client, enabled=True)
            with pytest.raises(IntegrityError, match='test-ack'):
                await bot.deliver_notifications('synthetic-not-live')
            assert len(calls) == 1
            assert events(engine)[0]['status'] == 'pending'
            assert events(engine)[0]['delivered_at'] is None
        finally:
            with engine.begin() as connection:
                connection.execute(text('DROP TRIGGER fail_ack'))
        restarted = bot_for(engine, client, enabled=True, now=NOW + timedelta(seconds=60))
        await restarted.deliver_notifications('synthetic-not-live')
    assert len(calls) == 2 and calls[0] == calls[1]
    assert events(engine)[0]['status'] == 'delivered'
