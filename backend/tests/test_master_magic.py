"""Master Telegram identity and one-use portal sign-in."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from importlib import import_module

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master import accounts
from vs_master.accounts import issue_magic_token
from vs_master.app import create_master_app
from vs_master.models import Account, Base, MagicLogin, PaymentReceipt, Setting, Subscription, make_engine
from vs_router.secrets import encrypt_secret


NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)


def account_fixture():
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Account(display_name='Ира', telegram_chat_id='12345', password_hash='unusable'))
        db.commit()
    return engine


def test_unknown_magic_token_is_rejected_without_a_session():
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        client = TestClient(create_master_app(engine), base_url='https://master.example')
        response = client.post('/api/portal/login/magic', json={'token': 'not-a-token'})
        assert response.status_code == 401
        assert 'set-cookie' not in response.headers
        assert 'not-a-token' not in response.text
    finally:
        engine.dispose()


def test_magic_proof_is_hashed_single_use_and_does_not_grant_subscription():
    engine = account_fixture()
    try:
        token = issue_magic_token(engine, 1, NOW)
        with Session(engine) as db:
            proof = db.scalar(select(MagicLogin))
            assert proof is not None
            assert proof.token_hash == sha256(token.encode()).hexdigest()
            assert token not in proof.token_hash
            assert db.scalar(select(Subscription)) is None

        client = TestClient(create_master_app(engine, clock=lambda: NOW),
                            base_url='https://master.example')
        response = client.post('/api/portal/login/magic', json={'token': token})
        assert response.status_code == 200
        assert response.json() == {'id': 1, 'display_name': 'Ира'}
        assert all(flag in response.headers['set-cookie'] for flag in
                   ('Secure', 'HttpOnly', 'SameSite=lax'))
        assert client.get('/api/portal/me').json()['subscription'] is None
        assert client.post('/api/portal/devices', json={'label': 'Телефон'}).status_code == 403
        replay = TestClient(create_master_app(engine, clock=lambda: NOW),
                            base_url='https://master.example')
        assert replay.post('/api/portal/login/magic', json={'token': token}).status_code == 401
        assert replay.get('/api/portal/me').status_code == 401
    finally:
        engine.dispose()


def test_magic_proof_expires_rotates_and_disabled_accounts_are_denied():
    engine = account_fixture()
    try:
        old = issue_magic_token(engine, 1, NOW)
        current = issue_magic_token(engine, 1, NOW)
        client = TestClient(create_master_app(engine, clock=lambda: NOW),
                            base_url='https://master.example')
        assert client.post('/api/portal/login/magic', json={'token': old}).status_code == 401
        late = TestClient(create_master_app(engine, clock=lambda: NOW + timedelta(minutes=11)),
                          base_url='https://master.example')
        assert late.post('/api/portal/login/magic', json={'token': current}).status_code == 401
        with Session(engine) as db:
            account = db.get(Account, 1)
            assert account is not None
            account.status = 'disabled'
            db.commit()
        assert client.post('/api/portal/login/magic', json={'token': current}).status_code == 401
        assert client.get('/api/portal/me').status_code == 401
    finally:
        engine.dispose()


def test_registration_requires_verified_private_telegram_sender_and_no_subscription():
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    try:
        message = {'chat': {'id': 12345, 'type': 'private'},
                   'from': {'id': 12345, 'first_name': 'Ира'}, 'text': '/start'}
        assert accounts.register_telegram(engine, message) == (1, True)
        assert accounts.register_telegram(engine, message) == (1, False)
        with Session(engine) as db:
            account = db.scalar(select(Account))
            assert account is not None
            assert account.display_name == 'Ира'
            assert account.telegram_chat_id == '12345'
            assert account.password_hash != ''
            assert db.scalar(select(Subscription)) is None
        assert accounts.register_telegram(engine, {
            **message, 'from': {'id': 67890, 'first_name': 'Чужой'}}) is None
        assert accounts.register_telegram(engine, {
            **message, 'chat': {'id': -100, 'type': 'supergroup'}}) is None
        with Session(engine) as db:
            account = db.scalar(select(Account))
            assert account is not None
            account.status = 'disabled'
            db.commit()
        assert accounts.register_telegram(engine, message) is None
    finally:
        engine.dispose()


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.mark.anyio
async def test_master_bot_registers_then_edits_menu_and_issues_magic_link():
    Bot = import_module('vs_master.telegram_bot').Bot
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    calls = []
    updates = [{'update_id': 1, 'message': {
        'message_id': 10, 'chat': {'id': 12345, 'type': 'private'},
        'from': {'id': 12345, 'first_name': 'Ира'}, 'text': '/start'}},
               {'update_id': 2, 'callback_query': {
                   'id': 'q1', 'data': 'login', 'from': {'id': 12345},
                   'message': {'message_id': 20, 'chat': {'id': 12345, 'type': 'private'},
                               'text': 'Выберите раздел.'}}}]

    def api(request):
        method = request.url.path.rsplit('/', 1)[-1]
        payload = __import__('json').loads(request.content)
        calls.append((method, payload))
        return httpx.Response(200, json={'ok': True, 'result': updates if method == 'getUpdates' else True})

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
            bot = Bot(engine, client, public_url='https://master.example')
            await bot.poll('test-token')
        assert [name for name, _ in calls] == [
            'getUpdates', 'sendMessage', 'answerCallbackQuery', 'editMessageText']
        assert calls[1][1]['chat_id'] == 12345
        assert 'Подписка пока не активна' in calls[1][1]['text']
        buttons = calls[3][1]['reply_markup']['inline_keyboard']
        link = buttons[0][0]['url']
        assert link.startswith('https://master.example/login#token=')
        token = link.partition('token=')[2]
        assert token and token not in calls[3][1]['text']
        assert bot.offset == 3
        with Session(engine) as db:
            assert db.scalar(select(Subscription)) is None
            assert db.scalar(select(Account)) is not None
    finally:
        engine.dispose()


@pytest.mark.anyio
async def test_stars_checkout_is_rejected_until_price_and_fulfillment_exist():
    Bot = import_module('vs_master.telegram_bot').Bot
    engine = account_fixture()
    calls = []

    def api(request):
        method = request.url.path.rsplit('/', 1)[-1]
        calls.append((method, __import__('json').loads(request.content)))
        return httpx.Response(200, json={'ok': True, 'result': [
            {'update_id': 5, 'pre_checkout_query': {
                'id': 'q5', 'from': {'id': 12345}, 'currency': 'XTR',
                'total_amount': 10, 'invoice_payload': 'unknown'}}]
            if method == 'getUpdates' else True})

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
            bot = Bot(engine, client, public_url='https://master.example')
            await bot.poll('test-token')
        assert [method for method, _ in calls] == ['getUpdates', 'answerPreCheckoutQuery']
        assert calls[1][1]['pre_checkout_query_id'] == 'q5'
        assert calls[1][1]['ok'] is False
        assert bot.offset == 6
        with Session(engine) as db:
            assert db.scalar(select(Subscription)) is None
    finally:
        engine.dispose()


@pytest.mark.anyio
async def test_unexpected_successful_payment_is_retained_once_without_entitlement():
    Bot = import_module('vs_master.telegram_bot').Bot
    engine = account_fixture()
    update = {'update_id': 7, 'message': {
        'chat': {'id': 12345, 'type': 'private'}, 'from': {'id': 12345},
        'successful_payment': {
            'currency': 'XTR', 'total_amount': 10,
            'invoice_payload': 'synthetic-unmatched-order',
            'telegram_payment_charge_id': 'synthetic-charge'}}}

    def api(request):
        method = request.url.path.rsplit('/', 1)[-1]
        return httpx.Response(200, json={'ok': True,
            'result': [update] if method == 'getUpdates' else True})

    try:
        async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as client:
            bot = Bot(engine, client, public_url='https://master.example')
            await bot.poll('test-token')
            assert bot.offset == 8
            await Bot(engine, client, public_url='https://master.example').poll('test-token')
        with Session(engine) as db:
            rows = db.scalars(select(PaymentReceipt)).all()
            assert len(rows) == 1
            assert rows[0].telegram_charge_id == 'synthetic-charge'
            assert rows[0].amount == 10
            assert db.scalar(select(Subscription)) is None
    finally:
        engine.dispose()


def test_bot_reads_encrypted_master_settings_not_environment(monkeypatch):
    Bot = import_module('vs_master.telegram_bot').Bot
    engine = make_engine('sqlite://')
    Base.metadata.create_all(engine)
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    token = '123456:synthetic-master-bot-token-not-live'
    with Session(engine) as db:
        db.add_all([Setting(key='master_bot_token', value='enc:' +
                            encrypt_secret(token, key).ciphertext),
                    Setting(key='master_public_url', value='https://my.example')])
        db.commit()
    try:
        bot = Bot(engine, None, public_url=None)
        assert bot.setting('master_bot_token') == token
        assert bot.setting('master_public_url') == 'https://my.example'
    finally:
        engine.dispose()
