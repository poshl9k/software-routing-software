"""Host-free portal Telegram worker tests."""
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
import httpx
import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vs_portal.app import create_app
from vs_portal.models import Account, Audit, Base, Device, Setting, Subscription, Tariff, TelegramLink, make_engine
from vs_router.telegram_bot import Bot, UNLINKED, _activity

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
def engine(tmp_path):
    db = make_engine(f'sqlite:///{tmp_path / "portal.db"}')
    Base.metadata.create_all(db)
    yield db
    db.dispose()


@pytest.fixture
def populated(engine):
    with Session(engine) as db:
        db.add_all([Account(subscriber_name='alice', password_hash='hash', status='active'),
                    Account(subscriber_name='disabled', password_hash='hash', status='disabled'),
                    Tariff(id=1, name='Базовый', device_limit=3, term_days=30)])
        db.flush()
        db.add_all([Subscription(subscriber_name='alice', tariff_id=1,
                                 expires_at=datetime(2030, 1, 2, tzinfo=timezone.utc)),
                    Device(subscriber_name='alice', name='peer-1', label='Телефон', status='active',
                           allowed_ips=[], created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)),
                    Device(subscriber_name='alice', name='peer-2', label='Старый', status='removed',
                           allowed_ips=[]),
                    Setting(key='support_url', value='https://t.me/support?x=<b>')])
        db.commit()
    return engine


async def test_token_missing_retries_30_seconds_without_network(engine, caplog):
    delays = []
    async def sleep(seconds):
        delays.append(seconds)
        raise asyncio.CancelledError
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: pytest.fail('network called'))) as client:
        with pytest.raises(asyncio.CancelledError):
            await Bot(engine, client, sleep=sleep).run()
    assert delays == [30]
    assert 'Bot token is not configured' in caplog.text

def test_console_wizard_encrypts_bot_token_for_worker(engine, monkeypatch):
    from vs_router.agent.setup_wizard import SetupWizard
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    token = '12345:some_bot_secret'
    SetupWizard(panel_engine=engine, portal_engine=engine).write_settings(
        token, 'https://t.me/support')
    with Session(engine) as db:
        assert token not in db.get(Setting, 'bot_token').value
    assert Bot(engine, None).setting('bot_token') == token

def test_console_wizard_allows_skipping_bot_token(engine, monkeypatch):
    from vs_router.agent.setup_wizard import SetupWizard
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    attempts = []
    def empty_once(prompt):
        attempts.append(prompt)
        assert len(attempts) == 1, 'blank token should not trigger another prompt'
        return ''
    wizard = SetupWizard(input_fn=lambda prompt: '', password_fn=empty_once,
                         panel_engine=engine, portal_engine=engine)
    assert wizard.prompt_token() == ''
    wizard.write_settings('', 'https://t.me/support')
    assert Bot(engine, None).setting('bot_token') == ''


async def test_link_requires_authenticated_one_use_code_not_a_username(engine):
    with Session(engine) as db:
        db.add(Account(subscriber_name='alice', password_hash=PasswordHasher().hash('correct-password'),
                       status='active'))
        db.commit()
    app = create_app(engine)
    bot = Bot(engine, None)
    assert bot.reply('11', '/status') == UNLINKED
    assert 'портал' in bot.reply('11', '/start').lower()
    assert bot.reply('11', 'alice') == UNLINKED
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://portal.test') as client:
        assert (await client.post('/api/portal/telegram/link')).status_code == 401
        login = await client.post('/api/portal/login', json={
            'username': 'alice', 'password': 'correct-password'})
        assert login.status_code == 200
        response = await client.post('/api/portal/telegram/link')
        assert response.status_code == 200, response.text
        assert response.headers['Cache-Control'] == 'no-store'
        code = response.json()['code']
        assert len(code) >= 32
    with Session(engine) as db:
        assert db.get(Account, 'alice').telegram_chat_id is None
        assert db.get(TelegramLink, hashlib.sha256(code.encode()).hexdigest()) is not None
        assert code not in str(db.execute(select(TelegramLink)).all())
    assert 'привязан' in bot.reply('11', f'/start {code}')
    assert 'уже привязан' in bot.reply('11', f'/start {code}')
    assert bot.reply('22', f'/start {code}') == UNLINKED
    assert bot.reply('22', 'alice') == UNLINKED
    with Session(engine) as db:
        assert db.get(Account, 'alice').telegram_chat_id == '11'
        assert db.get(TelegramLink, hashlib.sha256(code.encode()).hexdigest()) is None
        assert db.scalar(select(Audit).where(Audit.action == 'telegram.link')).actor == 'alice'

async def test_link_rotation_expiry_and_disabled_account(engine):
    with Session(engine) as db:
        db.add(Account(subscriber_name='alice', password_hash=PasswordHasher().hash('correct-password'),
                       status='active'))
        db.commit()
    bot = Bot(engine, None)
    async with AsyncClient(transport=ASGITransport(app=create_app(engine)),
                           base_url='https://portal.test') as client:
        assert (await client.post('/api/portal/login', json={
            'username': 'alice', 'password': 'correct-password'})).status_code == 200
        first = (await client.post('/api/portal/telegram/link')).json()['code']
        second = (await client.post('/api/portal/telegram/link')).json()['code']
    assert bot.reply('1', f'/start {first}') == UNLINKED
    assert bot.reply('1', '/start invalid') == UNLINKED
    with Session(engine) as db:
        db.get(TelegramLink, hashlib.sha256(second.encode()).hexdigest()).expires_at = (
            datetime.now(timezone.utc) - timedelta(seconds=1))
        db.commit()
    assert bot.reply('1', f'/start {second}') == UNLINKED
    with Session(engine) as db:
        assert db.get(Account, 'alice').telegram_chat_id is None
        db.get(TelegramLink, hashlib.sha256(second.encode()).hexdigest()).expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=5))
        db.get(Account, 'alice').status = 'disabled'
        db.commit()
    assert bot.reply('1', f'/start {second}') == UNLINKED


async def test_commands_and_missing_data(populated):
    bot = Bot(populated, None)
    assert 'Команды' in bot.reply('1', '/help')
    assert '<b>' in bot.reply('1', '/support')
    assert bot.reply('1', '/devices') == UNLINKED
    with Session(populated) as db:
        db.get(Account, 'alice').telegram_chat_id = '1'
        db.commit()
    status = bot.reply('1', '/status')
    assert 'Базовый' in status and '02.01.2030' in status and '1 / 3' in status
    devices = bot.reply('1', '/devices')
    assert 'Телефон' in devices and 'Старый' not in devices
    assert 'данных нет' in devices and 'создано 01.01.2026' in devices
    assert _activity(object()) == 'Последняя известная активность: данных нет'
    with Session(populated) as db:
        db.delete(db.get(Subscription, 'alice'))
        db.delete(db.get(Setting, 'support_url'))
        db.commit()
    assert 'не найдена' in bot.reply('1', '/status')
    assert 'не настроен' in bot.reply('1', '/support')
    with Session(populated) as db:
        db.get(Account, 'alice').status = 'disabled'
        db.commit()
    assert bot.reply('1', '/status') == UNLINKED


async def test_poll_offset_and_failures_do_not_leak_token(engine, caplog):
    calls = []
    rounds = iter([[{'update_id': 7, 'message': {'chat': {'id': 10, 'type': 'private'}, 'text': '/help'}},
                    {'update_id': 8, 'message': {'chat': {'id': -1, 'type': 'group'}, 'text': '/help'}}], []])
    def handler(request):
        assert request.method == 'POST'
        calls.append((request.url.path.rsplit('/', 1)[-1], __import__('json').loads(request.content)))
        if request.url.path.endswith('/getUpdates'):
            return httpx.Response(200, json={'ok': True, 'result': next(rounds)})
        return httpx.Response(200, json={'ok': True, 'result': {'message_id': 1}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(engine, client)
        await bot.poll('test-token')
        await bot.poll('test-token')
    assert [item[0] for item in calls] == ['getUpdates', 'sendMessage', 'getUpdates']
    assert calls[0][1]['offset'] is None and calls[2][1]['offset'] == 9
    assert calls[1][1]['chat_id'] == '10'
    assert calls[1][1]['text'].startswith('Команды')
    assert 'test-token' not in caplog.text


async def test_inline_menu_edits_one_message_and_ignores_unrequested_text(populated):
    with Session(populated) as db:
        account = db.get(Account, 'alice')
        assert account is not None
        account.telegram_chat_id = '10'
        db.commit()
    calls = []
    rounds = iter([
        [{'update_id': 1, 'message': {
            'chat': {'id': 10, 'type': 'private'}, 'text': '/start'}}],
        [{'update_id': 2, 'callback_query': {
            'id': 'cb-1', 'from': {'id': 10}, 'data': 'status',
            'message': {'message_id': 55, 'chat': {'id': 10, 'type': 'private'},
                        'text': 'Аккаунт уже привязан. Выберите раздел.'}}}],
        [{'update_id': 3, 'callback_query': {
            'id': 'cb-2', 'from': {'id': 10}, 'data': 'menu',
            'message': {'message_id': 55, 'chat': {'id': 10, 'type': 'private'},
                        'text': 'Тариф: Базовый'}}}],
        [{'update_id': 4, 'callback_query': {
            'id': 'cb-3', 'from': {'id': 11}, 'data': 'status',
            'message': {'message_id': 55, 'chat': {'id': 10, 'type': 'private'},
                        'text': 'Выберите раздел.'}}}],
        [{'update_id': 5, 'message': {
            'chat': {'id': 10, 'type': 'private'}, 'text': 'привет'}}],
    ])
    def handler(request):
        method = request.url.path.rsplit('/', 1)[-1]
        payload = json.loads(request.content)
        calls.append((method, payload))
        result = next(rounds) if method == 'getUpdates' else {'message_id': 55}
        return httpx.Response(200, json={'ok': True, 'result': result})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(populated, client)
        for _ in range(5):
            await bot.poll('test-token')
    assert [method for method, _ in calls] == [
        'getUpdates', 'sendMessage', 'getUpdates', 'answerCallbackQuery', 'editMessageText',
        'getUpdates', 'answerCallbackQuery', 'editMessageText', 'getUpdates',
        'answerCallbackQuery', 'getUpdates']
    assert calls[0][1]['allowed_updates'] == ['message', 'callback_query']
    assert calls[1][1]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'status'
    assert 'Базовый' in calls[4][1]['text']
    assert calls[4][1]['message_id'] == calls[7][1]['message_id'] == 55
    assert calls[4][1]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'menu'
    assert calls[7][1]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'status'
    assert calls[9][1]['callback_query_id'] == 'cb-3'
    assert bot.offset == 6


async def test_opt_in_registration_requires_explicit_action_and_never_grants_subscription(engine):
    bot = Bot(engine, None)
    assert bot.reply('123', '/register') == UNLINKED
    with Session(engine) as db:
        db.add(Setting(key='self_registration_enabled', value='1'))
        db.commit()
    assert bot.reply('123', '/start') == UNLINKED
    with Session(engine) as db:
        assert db.scalar(select(Account)) is None
    assert 'зарегистрирован' in bot.reply('123', '/register').lower()
    with Session(engine) as db:
        account = db.scalar(select(Account).where(Account.telegram_chat_id == '123'))
        assert account is not None
        assert account.subscriber_name.startswith('tg-')
        assert account.password_hash != '123'
        assert db.get(Subscription, account.subscriber_name) is None
        assert db.scalar(select(Audit).where(Audit.action == 'telegram.register')) is not None
    assert 'уже привязан' in bot.reply('123', '/register')
    with Session(engine) as db:
        assert len(db.scalars(select(Account)).all()) == 1


async def test_registration_cannot_claim_existing_name_or_disabled_identity(engine):
    with Session(engine) as db:
        db.add_all([Setting(key='self_registration_enabled', value='1'),
                    Account(subscriber_name='tg-123', telegram_chat_id='999',
                            password_hash='hash', status='active'),
                    Account(subscriber_name='disabled', telegram_chat_id='456',
                            password_hash='hash', status='disabled')])
        db.commit()
    bot = Bot(engine, None)
    assert 'поддержку' in bot.reply('123', '/register').lower()
    assert bot.reply('456', '/register') == UNLINKED
    with Session(engine) as db:
        assert len(db.scalars(select(Account)).all()) == 2


async def test_registration_button_requires_private_chat_and_matching_sender(engine):
    with Session(engine) as db:
        db.add(Setting(key='self_registration_enabled', value='1'))
        db.commit()
    calls = []
    rounds = iter([
        [{'update_id': 1, 'message': {'chat': {'id': 123, 'type': 'private'},
                                      'text': '/start'}}],
        [{'update_id': 2, 'callback_query': {
            'id': 'wrong', 'from': {'id': 456}, 'data': 'register',
            'message': {'message_id': 77, 'chat': {'id': 123, 'type': 'private'},
                        'text': UNLINKED}}}],
        [{'update_id': 3, 'callback_query': {
            'id': 'right', 'from': {'id': 123}, 'data': 'register',
            'message': {'message_id': 77, 'chat': {'id': 123, 'type': 'private'},
                        'text': UNLINKED}}}],
    ])
    def handler(request):
        method = request.url.path.rsplit('/', 1)[-1]
        calls.append((method, json.loads(request.content)))
        return httpx.Response(200, json={
            'ok': True, 'result': next(rounds) if method == 'getUpdates' else True})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(engine, client)
        for _ in range(3):
            await bot.poll('test-token')
    assert [method for method, _ in calls] == [
        'getUpdates', 'sendMessage', 'getUpdates', 'answerCallbackQuery',
        'getUpdates', 'answerCallbackQuery', 'editMessageText']
    assert calls[1][1]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'register'
    assert calls[-1][1]['reply_markup']['inline_keyboard'][0][0]['callback_data'] == 'status'
    with Session(engine) as db:
        assert db.scalar(select(Account).where(Account.telegram_chat_id == '123')) is not None


async def test_polling_conflict_backs_off_without_token_leak(engine, monkeypatch, caplog):
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    with Session(engine) as db:
        db.add(Setting(key='bot_token', value='12345:synthetic'))
        db.commit()
    delays = []
    async def sleep(seconds):
        delays.append(seconds)
        raise asyncio.CancelledError
    def handler(request):
        return httpx.Response(409, text='another getUpdates consumer')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(asyncio.CancelledError):
            await Bot(engine, client, sleep=sleep).run()
    assert delays == [60]
    assert '12345:synthetic' not in caplog.text


async def test_callback_rejects_invalid_data_and_does_not_edit_unchanged_view(populated):
    with Session(populated) as db:
        account = db.get(Account, 'alice')
        assert account is not None
        account.telegram_chat_id = '10'
        db.commit()
    status_text = Bot(populated, None).reply('10', '/status')
    calls = []
    rounds = iter([
        [{'update_id': 1, 'callback_query': {
            'id': 'bad', 'from': {'id': 10}, 'data': [],
            'message': {'message_id': 55, 'chat': {'id': 10, 'type': 'private'}}}}],
        [{'update_id': 2, 'callback_query': {
            'id': 'same', 'from': {'id': 10}, 'data': 'status',
            'message': {'message_id': 55, 'chat': {'id': 10, 'type': 'private'},
                        'text': status_text}}}],
    ])
    def handler(request):
        method = request.url.path.rsplit('/', 1)[-1]
        calls.append(method)
        return httpx.Response(200, json={
            'ok': True, 'result': next(rounds) if method == 'getUpdates' else True})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(populated, client)
        await bot.poll('test-token')
        await bot.poll('test-token')
    assert calls == ['getUpdates', 'answerCallbackQuery', 'getUpdates', 'answerCallbackQuery']
    assert bot.offset == 3


async def test_poll_failure_retries_and_keeps_offset(engine, caplog, monkeypatch):
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', Fernet.generate_key().decode())
    delays = []
    calls = []
    async def sleep(seconds):
        delays.append(seconds)
        raise asyncio.CancelledError
    def handler(request):
        calls.append(request)
        return httpx.Response(500, text='test-token')
    with Session(engine) as db:
        db.add(Setting(key='bot_token', value='test-token'))
        db.commit()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(engine, client, sleep=sleep)
        with pytest.raises(asyncio.CancelledError):
            await bot.run()
    assert delays == [2] and bot.offset is None
    assert len(calls) == 1 and 'test-token' not in caplog.text
    with Session(engine) as db:
        assert db.get(Setting, 'bot_token').value.startswith('enc:')


async def test_send_failure_retries_same_update(engine, caplog):
    calls = []
    sends = []
    def handler(request):
        method = request.url.path.rsplit('/', 1)[-1]
        if method == 'getUpdates':
            calls.append(__import__('json').loads(request.content)['offset'])
            return httpx.Response(200, json={'ok': True, 'result': [
                {'update_id': 7, 'message': {'chat': {'id': 10, 'type': 'private'}, 'text': '/help'}}]})
        sends.append(method)
        if len(sends) == 1:
            return httpx.Response(500)
        return httpx.Response(200, json={'ok': True, 'result': {'message_id': 1}})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        bot = Bot(engine, client)
        await bot.poll('test-token')
        assert bot.offset is None
        await bot.poll('test-token')
    assert calls == [None, None] and sends == ['sendMessage', 'sendMessage']
    assert bot.offset == 8 and 'test-token' not in caplog.text

def test_model_migration_and_service_install_contract(engine):
    root = Path(__file__).resolve().parents[1]
    cols = inspect(engine).get_columns('portal_accounts')
    chat = next(column for column in cols if column['name'] == 'telegram_chat_id')
    assert chat['nullable'] and chat['type'].length == 64
    assert any(index['unique'] and index['column_names'] == ['telegram_chat_id']
               for index in inspect(engine).get_indexes('portal_accounts')) is False
    migration = (root / 'alembic-portal/versions/0004_telegram_chat_id.py').read_text()
    assert "revision = '0004'" in migration and "down_revision = '0003'" in migration
    assert 'op.add_column' in migration and 'op.drop_column' in migration
    assert 'unique=True' in migration
    unit = (root / 'packaging/vs-router-telegram.service').read_text()
    for line in ('User=vs-router-telegram', 'Group=vs-router-portal',
                 'ExecStart=/usr/bin/python3 -m vs_router.telegram_bot',
                 'ReadWritePaths=/var/lib/vs-router/portal', 'Restart=on-failure'):
        assert line in unit
    install = (root / 'packaging/install.sh').read_text()
    block = install[install.index('# Telegram worker is panel-only;'):]
    assert 'if [ "$PROFILE" = panel ]; then' in block
    assert 'systemctl enable vs-router-telegram.service' in block
    assert 'systemctl restart vs-router-telegram.service' in block


def test_migration_upgrade_and_downgrade(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f'sqlite:///{tmp_path / "migrated.db"}'
    config = Config()
    config.set_main_option('script_location', str(root / 'alembic-portal'))
    config.set_main_option('sqlalchemy.url', url)
    command.upgrade(config, 'head')
    engine = make_engine(url)
    try:
        assert 'telegram_chat_id' in {column['name'] for column in inspect(engine).get_columns('portal_accounts')}
        assert any(index['column_names'] == ['telegram_chat_id'] and index['unique']
                   for index in inspect(engine).get_indexes('portal_accounts'))
        assert {'code_hash', 'subscriber_name', 'expires_at'} <= {
            column['name'] for column in inspect(engine).get_columns('portal_telegram_links')}
    finally:
        engine.dispose()
    command.downgrade(config, '0005')
    engine = make_engine(url)
    try:
        assert 'portal_telegram_links' not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
    command.downgrade(config, '0003')
    engine = make_engine(url)
    try:
        assert 'telegram_chat_id' not in {column['name'] for column in inspect(engine).get_columns('portal_accounts')}
    finally:
        engine.dispose()
