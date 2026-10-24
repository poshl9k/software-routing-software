"""Host-free portal Telegram worker tests."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
import httpx
import pytest
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vs_portal.models import Account, Base, Device, Setting, Subscription, Tariff, make_engine
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


async def test_linking_is_atomic_and_replaces_previous_chat(populated):
    bot = Bot(populated, None)
    assert bot.reply('11', '/status') == UNLINKED
    assert 'логин' in bot.reply('11', '/start')
    assert 'не найден' in bot.reply('11', 'disabled')
    assert 'не найден' in bot.reply('11', 'missing')
    assert 'привязан' in bot.reply('11', 'alice')
    assert 'уже привязан' in bot.reply('11', '/start')
    with Session(populated) as db:
        assert db.get(Account, 'alice').telegram_chat_id == '11'
        db.add(Account(subscriber_name='bob', password_hash='hash', status='active', telegram_chat_id='22'))
        db.commit()
    # Simulate a new /start flow after unbinding this chat, then replace bob's old binding.
    with Session(populated) as db:
        db.get(Account, 'alice').telegram_chat_id = None
        db.commit()
    bot.reply('22', '/start')  # already linked, so must not grant an alternate identity
    assert 'уже привязан' in bot.reply('22', '/start')
    with Session(populated) as db:
        assert db.get(Account, 'bob').telegram_chat_id == '22'
    # A pending flow can survive a binding made by another process; replace it atomically.
    bot.awaiting_login.add('22')
    assert 'привязан' in bot.reply('22', 'alice')
    with Session(populated) as db:
        assert db.get(Account, 'bob').telegram_chat_id is None
        assert db.get(Account, 'alice').telegram_chat_id == '22'
    assert bot.reply('11', '/devices') == UNLINKED


async def test_commands_and_missing_data(populated):
    bot = Bot(populated, None)
    assert 'Команды' in bot.reply('1', '/help')
    assert '<b>' in bot.reply('1', '/support')
    assert bot.reply('1', '/devices') == UNLINKED
    bot.reply('1', '/start')
    bot.reply('1', 'alice')
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


async def test_poll_failure_retries_and_keeps_offset(engine, caplog):
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
    finally:
        engine.dispose()
    command.downgrade(config, '0003')
    engine = make_engine(url)
    try:
        assert 'telegram_chat_id' not in {column['name'] for column in inspect(engine).get_columns('portal_accounts')}
    finally:
        engine.dispose()
