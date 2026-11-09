"""Master device bot acceptance: disposable DB, synthetic Telegram and bridge only."""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from email.parser import BytesParser
from email.policy import default

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_master.models import (Account, Audit, Base, Device, DeviceOp, Node,
                              Subscription, Tariff, make_engine)
from vs_master.telegram_bot import Bot
from vs_router.secrets import encrypt_secret

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)
PRIVATE = 'synthetic-private-never-in-message'
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return 'asyncio'


class Telegram:
    def __init__(self):
        self.updates = []
        self.calls = []
        self.fail = None
        self.ack_chat = 100

    def __call__(self, request):
        method = request.url.path.rsplit('/', 1)[-1]
        if 'multipart/form-data' in request.headers.get('content-type', ''):
            message = BytesParser(policy=default).parsebytes(
                b'Content-Type: ' + request.headers['content-type'].encode() + b'\r\n\r\n' + request.content)
            payload = {}
            for part in message.iter_parts():
                name = part.get_param('name', header='content-disposition')
                payload[name] = (part.get_filename(), part.get_payload(decode=True)) \
                    if part.get_filename() else part.get_content().strip()
        else:
            payload = json.loads(request.content)
        self.calls.append((method, payload))
        if method == self.fail:
            raise httpx.ReadTimeout('synthetic failure must not be logged with secret URL', request=request)
        result = self.updates if method == 'getUpdates' else {
            'message_id': 50, 'chat': {'id': self.ack_chat, 'type': 'private'}}
        return httpx.Response(200, json={'ok': True, 'result': result})


@pytest.fixture
async def rig(tmp_path, monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', key.decode())
    engine = make_engine('sqlite:///' + (tmp_path / 'master.db').as_posix())
    Base.metadata.create_all(engine)
    bridge_calls = []
    state = {'subscription': {'status': 'active'}, 'devices': [
        {'name': 'phone', 'applied': True, 'last_handshake': 1234}],
        'tunnel': {'name': 'wg0', 'protocol': 'wg', 'public_key': 'server-public',
                   'endpoint': 'vpn.example:51820', 'listen_port': 51820,
                   'subnet': '10.66.0.0/24', 'dns_servers': ['10.0.0.1'],
                   'allowed_ips': ['0.0.0.0/0']}}

    class Bridge:
        pending = False
        unavailable = False

        def state(self, subscriber):
            bridge_calls.append(('state', subscriber))
            if self.unavailable:
                raise ValueError(PRIVATE)
            return state

        def device_op(self, subscriber, payload):
            bridge_calls.append(('device_op', subscriber, payload))
            if self.pending:
                return {'status': 'pending'}
            if payload['op'] == 'create':
                return {'status': 'applied', 'device': {
                    'name': payload['name'], 'public_key': payload['keys']['public_key'],
                    'allowed_ips': ['10.66.0.3/32'], 'tunnel': 'wg0'}}
            return {'status': 'applied'}

    bridge = Bridge()
    with Session(engine) as db:
        db.add_all([
            Account(id=1, display_name='Alice', telegram_chat_id='100',
                    telegram_linked_chat_id='100', telegram_linked_at=NOW,
                    password_hash='unused', status='active'),
            Account(id=2, display_name='Bob', telegram_chat_id='200',
                    telegram_linked_chat_id='200', telegram_linked_at=NOW,
                    password_hash='unused', status='active'),
            Tariff(id=1, name='Base', device_limit=3, term_days=30),
            Node(id=1, name='hidden-node', bridge_url='https://node.invalid',
                 bridge_token=encrypt_secret('synthetic-bridge-token', key),
                 capacity=10, state='ok', enabled=True)])
        db.flush()
        for owner in (1, 2):
            db.add(Subscription(account_id=owner, tariff_id=1, status='active',
                                expires_at=NOW + timedelta(days=30)))
            db.add(Device(id=owner, account_id=owner, node_id=1, node_subscriber=f's{owner}',
                          name='phone' if owner == 1 else 'foreign', label='Phone' if owner == 1 else 'PRIVATE BOB',
                          status='active', public_key='client-public',
                          private_key=encrypt_secret(PRIVATE, key), allowed_ips=['10.66.0.2/32'],
                          tunnel_name='wg0'))
        db.commit()
    telegram = Telegram()
    clock = [NOW]
    async with httpx.AsyncClient(transport=httpx.MockTransport(telegram)) as client:
        bot = Bot(engine, client, public_url='https://master.example', clock=lambda: clock[0])
        # Factory is an explicit supported injection, never an HTTP portal session.
        bot.node_client_factory = lambda node: bridge
        yield bot, telegram, engine, bridge_calls, state, bridge, clock
    engine.dispose()


def command(text, update_id=1, *, identity=100, sender=None, chat_type='private'):
    return {'update_id': update_id, 'message': {
        'message_id': 10, 'chat': {'id': identity, 'type': chat_type},
        'from': {'id': identity if sender is None else sender}, 'text': text}}


def callback(data, update_id=1, *, identity=100, sender=None, chat_type='private'):
    return {'update_id': update_id, 'callback_query': {
        'id': f'q{update_id}', 'data': data,
        'from': {'id': identity if sender is None else sender},
        'message': {'message_id': 10, 'chat': {'id': identity, 'type': chat_type}}}}


async def send(rig, update):
    bot, telegram, *_ = rig
    telegram.updates = [update]
    telegram.calls.clear()
    await bot.poll('synthetic-token')
    return telegram.calls


def messages(calls):
    return [payload for method, payload in calls if method in ('sendMessage', 'editMessageText')]


def operations(engine):
    with Session(engine) as db:
        return [(op.op, op.status) for op in db.scalars(select(DeviceOp).order_by(DeviceOp.id))]


async def test_chat_keyboard_stays_available_and_labels_route_to_existing_actions(rig):
    calls = await send(rig, command('/start'))
    menu = messages(calls)[0]['reply_markup']
    assert menu == {'keyboard': [
        [{'text': 'Подписка'}, {'text': 'Личный кабинет'}],
        [{'text': 'Устройства'}]],
        'resize_keyboard': True, 'is_persistent': True}
    assert 'inline_keyboard' not in menu

    calls = await send(rig, command('Подписка', 2))
    assert 'Base' in messages(calls)[0]['text']
    assert 'reply_markup' not in messages(calls)[0]
    calls = await send(rig, command('Личный кабинет', 3))
    assert messages(calls)[0]['reply_markup']['inline_keyboard'][0][0]['url'].startswith(
        'https://master.example/login#token=')
    calls = await send(rig, command('Устройства', 4))
    assert 'Phone' in messages(calls)[0]['text']
    assert 'inline_keyboard' in messages(calls)[0]['reply_markup'], 'device-specific controls stay inline'
    assert all(button.get('callback_data') != 'menu'
               for row in messages(calls)[0]['reply_markup']['inline_keyboard'] for button in row)
    assert operations(rig[2]) == []

async def test_old_inline_menu_callback_opens_chat_keyboard_without_editing_it(rig):
    calls = await send(rig, callback('menu'))
    assert [method for method, _ in calls] == [
        'getUpdates', 'answerCallbackQuery', 'sendMessage']
    assert messages(calls)[0]['reply_markup']['is_persistent'] is True

async def test_empty_device_list_omits_empty_inline_keyboard(rig):
    with Session(rig[2]) as db:
        db.delete(db.get(Device, 1))
        db.commit()
    rig[4]['devices'] = []
    calls = await send(rig, command('Устройства'))
    assert 'Устройств пока нет' in messages(calls)[0]['text']
    assert 'reply_markup' not in messages(calls)[0]

@pytest.mark.parametrize('update', [command('Устройства', sender=200),
                                   command('Подписка', chat_type='group'),
                                   command('Личный кабинет', sender=200)])
async def test_chat_keyboard_text_never_bypasses_private_sender_check(rig, update):
    calls = await send(rig, update)
    assert not messages(calls) and not rig[3]

async def test_list_shows_own_status_and_actions_without_node_or_secret(rig):
    calls = await send(rig, command('/devices'))
    assert messages(calls), 'device list must be reachable from bot'
    text = json.dumps(messages(calls), ensure_ascii=False)
    assert 'Phone' in text and 'active' in text and '1234' in text
    assert 'PRIVATE BOB' not in text and PRIVATE not in text and 'hidden-node' not in text
    assert ('state', 's1') in rig[3] and ('state', 's2') not in rig[3]
    assert 'dev:conf:1' in text and 'dev:delete:1' in text


async def test_create_label_then_toggle_uses_durable_master_bridge_ops(rig):
    calls = await send(rig, command('/new Ноутбук'))
    assert messages(calls) and operations(rig[2]) == [('create', 'applied')]
    with Session(rig[2]) as db:
        created = db.scalar(select(Device).where(Device.label == 'Ноутбук'))
        assert created is not None and created.account_id == 1 and created.status == 'active'
    assert next(c for c in rig[3] if c[0] == 'device_op')[1] == 's1'
    await send(rig, callback('dev:deactivate:1', 2))
    await send(rig, command('/activate 1', 3))
    assert operations(rig[2]) == [('create', 'applied'), ('deactivate', 'applied'), ('activate', 'applied')]


@pytest.mark.parametrize('text', ['/devices', '/new Phone', '/activate 1', '/deactivate 1',
                                  '/delete 1', '/conf 1', '/qr 1', '/amnezia 1'])
@pytest.mark.parametrize('gate', ['expired', 'no_subscription', 'disabled', 'unlinked', 'relinked'])
async def test_all_device_paths_fail_closed_without_entitlement_or_verified_link(rig, text, gate):
    with Session(rig[2]) as db:
        account = db.get(Account, 1)
        subscription = db.scalar(select(Subscription).where(Subscription.account_id == 1))
        if gate == 'expired':
            subscription.expires_at = NOW
        elif gate == 'no_subscription':
            db.delete(subscription)
        elif gate == 'disabled':
            account.status = 'disabled'
        elif gate == 'unlinked':
            account.telegram_linked_at = None
        else:
            account.telegram_linked_chat_id = '999'
        db.commit()
    calls = await send(rig, command(text))
    assert messages(calls), 'deny explicitly rather than silently ignoring valid private commands'
    assert not rig[3] and not operations(rig[2])
    assert not any(method in ('sendDocument', 'sendPhoto') for method, _ in calls)
    assert PRIVATE not in json.dumps(messages(calls))


@pytest.mark.parametrize('update', [command('/new bad', sender=200),
    command('/new bad', chat_type='group'), callback('dev:deactivate:1', sender=200),
    callback('dev:conf:1', chat_type='supergroup')])
async def test_group_and_mismatched_senders_have_no_effect(rig, update):
    calls = await send(rig, update)
    assert not rig[3] and not operations(rig[2])
    assert not messages(calls)
    assert not any(method in ('sendDocument', 'sendPhoto') for method, _ in calls)


@pytest.mark.parametrize('action', ['activate', 'deactivate', 'delete', 'conf', 'qr', 'amnezia'])
async def test_foreign_device_never_reaches_bridge_or_exports(rig, action):
    calls = await send(rig, callback(f'dev:{action}:2'))
    assert messages(calls)
    assert not rig[3] and not operations(rig[2])
    assert not any(method in ('sendDocument', 'sendPhoto') for method, _ in calls)
    assert 'PRIVATE BOB' not in json.dumps(messages(calls))


async def test_device_limit_and_invalid_label_do_not_enqueue(rig):
    with Session(rig[2]) as db:
        db.get(Tariff, 1).device_limit = 1
        db.commit()
    calls = await send(rig, command('/new extra'))
    assert messages(calls) and 'лимит' in messages(calls)[0]['text'].lower()
    assert not operations(rig[2]) and not rig[3]
    calls = await send(rig, command('/new ' + 'x' * 129, 2))
    assert messages(calls) and not operations(rig[2])


async def test_delete_requires_one_use_confirmation_bound_to_account_and_expiry(rig):
    calls = await send(rig, callback('dev:delete:1'))
    assert not operations(rig[2])
    buttons = messages(calls)[0]['reply_markup']['inline_keyboard']
    proof = buttons[0][0]['callback_data']
    assert proof.startswith('dev:confirm:') and proof != 'dev:confirm:1'
    await send(rig, callback(proof, 2, identity=200))
    assert not operations(rig[2])
    await send(rig, callback(proof, 3))
    assert operations(rig[2]) == [('delete', 'applied')]
    await send(rig, callback(proof, 4))
    assert operations(rig[2]) == [('delete', 'applied')]


@pytest.mark.parametrize('change', ['expired_proof', 'expired_subscription', 'relinked', 'cancel', 'restart'])
async def test_delete_confirmation_revalidates_and_cancel_or_restart_invalidates(rig, change):
    calls = await send(rig, command('/delete 1'))
    proof = messages(calls)[0]['reply_markup']['inline_keyboard'][0][0]['callback_data']
    if change == 'expired_proof':
        rig[6][0] += timedelta(minutes=3)
    elif change == 'cancel':
        await send(rig, callback(proof.replace('confirm', 'cancel'), 2))
    elif change == 'restart':
        bot = Bot(rig[2], rig[0].client, clock=lambda: rig[6][0])
        rig = (bot, *rig[1:])
    else:
        with Session(rig[2]) as db:
            if change == 'relinked':
                db.get(Account, 1).telegram_linked_at = NOW + timedelta(seconds=1)
            else:
                db.scalar(select(Subscription).where(Subscription.account_id == 1)).expires_at = NOW
            db.commit()
    await send(rig, callback(proof, 3))
    assert not operations(rig[2])


@pytest.mark.parametrize('fmt,method,field,suffix', [('conf', 'sendDocument', 'document', '.conf'),
    ('qr', 'sendPhoto', 'photo', '.png'), ('amnezia', 'sendDocument', 'document', '-amnezia.txt')])
async def test_exports_only_as_protected_private_multipart_attachments(rig, fmt, method, field, suffix):
    if fmt == 'amnezia':
        rig[4]['tunnel'].update(protocol='awg', obfuscation={'Jc': 8, 'Jmin': 25, 'Jmax': 87,
            'S1': 97, 'S2': 60, 'H1': 462728319, 'H2': 1, 'H3': 2, 'H4': 3})
    calls = await send(rig, command(f'/{fmt} 1'))
    uploads = [payload for name, payload in calls if name == method]
    assert len(uploads) == 1
    payload = uploads[0]
    assert payload['chat_id'] == '100' and payload['protect_content'] == 'true'
    filename, content = payload[field]
    assert filename.endswith(suffix)
    if fmt == 'conf':
        assert ('PrivateKey = ' + PRIVATE).encode() in content
    elif fmt == 'qr':
        assert content.startswith(b'\x89PNG\r\n\x1a\n')
    else:
        assert content.startswith(b'vpn://')
    assert PRIVATE not in json.dumps(messages(calls))
    with Session(rig[2]) as db:
        assert PRIVATE not in repr([(a.action, a.detail) for a in db.scalars(select(Audit))])


async def test_wg_amnezia_and_bridge_failure_are_safe_errors(rig):
    calls = await send(rig, command('/amnezia 1'))
    assert messages(calls) and not any(m == 'sendDocument' for m, _ in calls)
    rig[5].unavailable = True
    calls = await send(rig, command('/conf 1', 2))
    assert messages(calls) and not any(m == 'sendDocument' for m, _ in calls)
    assert PRIVATE not in json.dumps(messages(calls))


async def test_telegram_failure_does_not_repeat_mutation_even_after_restart(rig, caplog):
    rig[1].fail = 'sendMessage'
    await send(rig, command('/new Once'))
    assert operations(rig[2]) == [('create', 'applied')]
    rig[1].fail = None
    # Telegram may redeliver the same update after loss of polling offset.
    bot = Bot(rig[2], rig[0].client, clock=lambda: NOW)
    bot.node_client_factory = rig[0].node_client_factory
    await send((bot, *rig[1:]), command('/new Once'))
    assert operations(rig[2]) == [('create', 'applied')]
    assert PRIVATE not in caplog.text and 'synthetic-token' not in caplog.text


async def test_pending_operation_is_reported_and_second_mutation_rejected(rig):
    rig[5].pending = True
    calls = await send(rig, command('/deactivate 1'))
    assert messages(calls) and 'очеред' in messages(calls)[0]['text'].lower()
    await send(rig, command('/activate 1', 2))
    assert operations(rig[2]) == [('deactivate', 'pending')]


async def test_attachment_failure_does_not_fallback_to_secret_text(rig, caplog):
    rig[1].fail = 'sendDocument'
    calls = await send(rig, command('/conf 1'))
    assert any(m == 'sendDocument' for m, _ in calls)
    assert PRIVATE not in json.dumps(messages(calls)) and PRIVATE not in caplog.text
    assert 'synthetic-token' not in caplog.text


async def test_waiting_for_bounded_io_does_not_use_stale_entitlement_time(rig):
    with Session(rig[2]) as db:
        subscription = db.scalar(select(Subscription).where(Subscription.account_id == 1))
        assert subscription is not None
        subscription.expires_at = NOW + timedelta(seconds=1)
        db.commit()
    async with rig[0].io_limit:
        task = asyncio.create_task(send(rig, command('/new TooLate')))
        await asyncio.sleep(0.02)
        rig[6][0] = NOW + timedelta(seconds=2)
    calls = await task
    assert messages(calls) and not operations(rig[2]) and not rig[3]


async def test_mutation_receipt_survives_rotation_of_same_bots_token(rig):
    rig[1].updates = [command('/new Once')]
    await rig[0].poll('42:old-synthetic-token')
    assert operations(rig[2]) == [('create', 'applied')]
    bot = Bot(rig[2], rig[0].client, clock=lambda: NOW,
              node_client_factory=rig[0].node_client_factory)
    await bot.poll('42:rotated-synthetic-token')
    assert operations(rig[2]) == [('create', 'applied')]


@pytest.mark.parametrize('change', ['disabled', 'expired', 'unlinked', 'removed'])
async def test_export_rechecks_authorization_after_slow_bridge_before_upload(rig, change):
    original_state = rig[5].state

    def state(subscriber):
        result = original_state(subscriber)
        with Session(rig[2]) as db:
            account = db.get(Account, 1)
            assert account is not None
            if change == 'disabled':
                account.status = 'disabled'
            elif change == 'unlinked':
                account.telegram_linked_at = NOW + timedelta(seconds=1)
            elif change == 'removed':
                device = db.get(Device, 1)
                assert device is not None
                device.status = 'removed'
            else:
                subscription = db.scalar(select(Subscription).where(Subscription.account_id == 1))
                assert subscription is not None
                subscription.expires_at = NOW
            db.commit()
        return result

    rig[5].state = state
    calls = await send(rig, command('/conf 1'))
    assert messages(calls) and not any(m in ('sendDocument', 'sendPhoto') for m, _ in calls)
    assert PRIVATE not in json.dumps(messages(calls))


async def test_wrong_attachment_acknowledgement_is_not_success(rig, caplog):
    rig[1].ack_chat = 200
    calls = await send(rig, command('/qr 1'))
    assert any(m == 'sendPhoto' for m, _ in calls)
    assert rig[0].offset is None and 'ValueError' in caplog.text
    assert PRIVATE not in caplog.text and not messages(calls)


async def test_delete_telegram_edit_failure_cannot_replay_destructive_action(rig):
    calls = await send(rig, command('/delete 1'))
    proof = messages(calls)[0]['reply_markup']['inline_keyboard'][0][0]['callback_data']
    rig[1].fail = 'editMessageText'
    await send(rig, callback(proof, 2))
    assert operations(rig[2]) == [('delete', 'applied')]
    rig[1].fail = None
    await send(rig, callback(proof, 2))
    assert operations(rig[2]) == [('delete', 'applied')]


async def test_device_io_is_off_loop_and_concurrency_is_bounded(rig):
    import threading

    entered = threading.Event()
    release = threading.Event()
    worker_threads = []
    original_state = rig[5].state

    def state(subscriber):
        worker_threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3), 'test must release synthetic bridge'
        return original_state(subscriber)

    rig[5].state = state
    first = asyncio.create_task(rig[0].device_interaction('synthetic-token', 100, 'devices', '', 1))
    second = None
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(.005)
        assert entered.is_set()
        second = asyncio.create_task(rig[0].device_interaction('synthetic-token', 100, 'devices', '', 2))
        await asyncio.sleep(.02)
        assert len(worker_threads) == 1 and worker_threads[0] != threading.get_ident()
    finally:
        release.set()
        await first
        if second is not None:
            await second
    assert len(worker_threads) == 2
