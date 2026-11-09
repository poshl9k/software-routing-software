"""Separate master Telegram Bot API consumer; no local portal state."""
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .accounts import issue_magic_token, register_telegram
from .models import Account, Audit, PaymentReceipt, Setting, Subscription, Tariff, make_engine
from .notifications import claim_notification, due_notifications, finish_notification
from .device_bot import ACTIONS, DeviceController, error_reply
from .worker import _default_node_client
from vs_router.api.errors import APIError
from vs_router.schema import EncryptedSecret
from vs_router.secrets import decrypt_secret

logger = logging.getLogger(__name__)
COMMANDS = {'/start', '/menu', '/status', '/login'}
VIEWS = {'menu', 'status', 'login'}
MENU_LABELS = {'Подписка': 'status', 'Личный кабинет': 'login', 'Устройства': 'devices'}
DEVICE_LABELS = {'Список устройств', 'Добавить устройство', 'Главное меню'}


def _menu():
    return {'keyboard': [
        [{'text': 'Подписка'}, {'text': 'Личный кабинет'}],
        [{'text': 'Устройства'}],
    ], 'resize_keyboard': True, 'is_persistent': True}

def _device_menu():
    return {'keyboard': [
        [{'text': 'Список устройств'}, {'text': 'Добавить устройство'}],
        [{'text': 'Главное меню'}],
    ], 'resize_keyboard': True, 'is_persistent': True}


def _private_sender(chat, sender):
    identity = chat.get('id') if isinstance(chat, dict) else None
    return (identity if isinstance(chat, dict) and chat.get('type') == 'private'
            and type(identity) is int and identity > 0 and isinstance(sender, dict)
            and type(sender.get('id')) is int and sender['id'] == identity else None)


class Bot:
    def __init__(self, engine, client, *, public_url=None, notifications_enabled=False, clock=None,
                 node_client_factory=None):
        self.engine = engine
        self.client = client
        self.public_url = self._public_url(public_url) if public_url else None
        self.offset = None
        self.notifications_enabled = notifications_enabled
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.node_client_factory = node_client_factory or _default_node_client
        self.device_controller = DeviceController(engine)
        self.io_limit = asyncio.Semaphore(1)
        self.pending_names = {}

    async def _io(self, function, *args):
        # DB/crypto/synchronous bridge work must not block the polling loop or
        # build an unbounded executor queue when handlers are invoked together.
        async with self.io_limit:
            return await asyncio.to_thread(function, *args)

    @staticmethod
    def _public_url(value):
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ('', '/')):
            raise ValueError('Master portal public URL must be HTTPS')
        return value.rstrip('/')

    def setting(self, key):
        with Session(self.engine) as db:
            row = db.get(Setting, key)
            value = row.value if row else None
        if key == 'master_bot_token' and value:
            if not value.startswith('enc:'):
                raise ValueError('Master bot token must be encrypted')
            return decrypt_secret(EncryptedSecret(ciphertext=value[4:]),
                                  os.environ['VS_ROUTER_SECRET_KEY'].encode())
        return value

    async def request(self, token, method, payload):
        response = await self.client.post(f'https://api.telegram.org/bot{token}/{method}', json=payload)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or data.get('ok') is not True:
            raise ValueError('Telegram Bot API rejected request')
        return data.get('result')

    def reply(self, identity, view, message=None):
        if view == 'start':
            registration = register_telegram(self.engine, message)
            if registration is None:
                return None
            account_id, created = registration
        else:
            with Session(self.engine) as db:
                account = db.scalar(select(Account).where(
                    Account.telegram_chat_id == str(identity), Account.status == 'active',
                    Account.telegram_linked_chat_id == str(identity),
                    Account.telegram_linked_at.is_not(None)))
                account_id = account.id if account else None
            created = False
        if account_id is None:
            return 'Аккаунт не найден. Отправьте /start.', None
        if view in ('start', 'menu'):
            text = ('Аккаунт зарегистрирован. Подписка пока не активна. '
                    if created else '') + 'Выберите раздел.'
            return text, _menu()
        if view == 'login':
            proof = issue_magic_token(self.engine, account_id, datetime.now(timezone.utc))
            return ('Ссылка действует 10 минут. Не пересылайте её.',
                    {'inline_keyboard': [
                        [{'text': 'Открыть кабинет',
                          'url': f'{self.public_url}/login#token={proof}'}],
                    ]})
        with Session(self.engine) as db:
            subscription = db.scalar(select(Subscription).where(
                Subscription.account_id == account_id).order_by(Subscription.id.desc()))
            if (subscription is None or subscription.status != 'active'
                    or subscription.expires_at <= datetime.now(timezone.utc)):
                text = 'Подписка пока не активна.'
            else:
                tariff = db.get(Tariff, subscription.tariff_id)
                text = (f'Тариф: {tariff.name if tariff else "неизвестен"}. '
                        f'Истекает: {subscription.expires_at:%d.%m.%Y}.')
        return text, None

    async def device_interaction(self, token, identity, action, argument, update_id,
                                 message_id=None, keyboard=None):
        receipt_key = 'tgdev:' + sha256(
            f'{token.partition(":")[0]}:{identity}:{update_id}'.encode()).hexdigest()[:56]
        try:
            answer = await self._io(lambda: self.device_controller.execute(
                identity, action, argument, self.clock(), self.node_client_factory, receipt_key))
            if answer.attachment:
                # Re-read the exact owner/link/subscription after slow bridge
                # I/O and immediately before disclosing key material.
                await self._io(lambda: self.device_controller.authorize_export(
                    identity, answer.authorization, self.clock()))
        except APIError as exc:
            answer = error_reply(exc)
            if keyboard is not None and exc.code in ('auth.forbidden', 'portal.subscription_expired'):
                keyboard = _menu()
        except Exception as exc:
            logger.error('Telegram device operation failed (%s)', type(exc).__name__)
            answer = error_reply(exc)
        if answer.attachment:
            kind, content, media_type, filename = answer.attachment
            field = 'photo' if kind == 'qr' else 'document'
            method = 'sendPhoto' if kind == 'qr' else 'sendDocument'
            # In-memory multipart bytes only: no URL/file-id reuse, temporary
            # files, captions with keys, or sendMessage fallback for a secret.
            response = await self.client.post(f'https://api.telegram.org/bot{token}/{method}',
                data={'chat_id': str(identity), 'protect_content': 'true'},
                files={field: (filename, content, media_type)})
            response.raise_for_status()
            data = response.json()
            result = data.get('result') if isinstance(data, dict) else None
            chat = result.get('chat') if isinstance(result, dict) else None
            if (not isinstance(data, dict) or data.get('ok') is not True
                    or not isinstance(result, dict) or type(result.get('message_id')) is not int
                    or result['message_id'] <= 0 or not isinstance(chat, dict)
                    or type(chat.get('id')) is not int or chat['id'] != identity
                    or chat.get('type') != 'private'):
                raise ValueError('Telegram returned an invalid attachment acknowledgement')
            return
        payload = {'chat_id': identity, 'text': answer.text}
        if keyboard is not None:
            payload['reply_markup'] = keyboard
        elif answer.markup:
            payload['reply_markup'] = answer.markup
        if message_id is not None:
            payload['message_id'] = message_id
        await self.request(token, 'editMessageText' if message_id is not None else 'sendMessage', payload)

    async def device_menu(self, token, identity):
        try:
            await self._io(lambda: self.device_controller.menu_access(identity, self.clock()))
        except APIError as exc:
            await self.request(token, 'sendMessage', {
                'chat_id': identity, 'text': error_reply(exc).text, 'reply_markup': _menu()})
            return
        await self.request(token, 'sendMessage', {
            'chat_id': identity, 'text': 'Устройства. Выберите действие.',
            'reply_markup': _device_menu()})

    async def ask_device_name(self, token, identity):
        try:
            owner = await self._io(lambda: self.device_controller.menu_access(identity, self.clock()))
        except APIError as exc:
            await self.request(token, 'sendMessage', {
                'chat_id': identity, 'text': error_reply(exc).text, 'reply_markup': _menu()})
            return
        now = self.clock()
        self.pending_names = {chat: pending for chat, pending in self.pending_names.items()
                              if pending[1] > now}
        if len(self.pending_names) >= 1000 and identity not in self.pending_names:
            await self.request(token, 'sendMessage', {
                'chat_id': identity, 'text': 'Бот занят. Попробуйте позже.'})
            return
        result = await self.request(token, 'sendMessage', {
            'chat_id': identity, 'text': 'Ответьте на это сообщение названием устройства (до 128 символов).',
            'reply_markup': {'force_reply': True}})
        chat = result.get('chat') if isinstance(result, dict) else None
        if (not isinstance(result, dict) or type(result.get('message_id')) is not int
                or result['message_id'] <= 0 or not isinstance(chat, dict)
                or type(chat.get('id')) is not int or chat['id'] != identity
                or chat.get('type') != 'private'):
            raise ValueError('Telegram returned an invalid device prompt acknowledgement')
        self.pending_names[identity] = (result['message_id'], self.clock() + timedelta(minutes=2), owner)

    async def receive_device_name(self, token, identity, message, update_id):
        pending = self.pending_names.get(identity)
        reply = message.get('reply_to_message')
        if (pending is None or not isinstance(reply, dict)
                or type(reply.get('message_id')) is not int or reply['message_id'] != pending[0]):
            return False
        del self.pending_names[identity]
        if pending[1] <= self.clock():
            await self.request(token, 'sendMessage', {
                'chat_id': identity, 'text': 'Время для названия истекло. Нажмите «Добавить устройство» ещё раз.',
                'reply_markup': _device_menu()})
            return True
        try:
            owner = await self._io(lambda: self.device_controller.menu_access(identity, self.clock()))
            if owner != pending[2]:
                raise APIError(403, 'auth.forbidden')
        except APIError as exc:
            await self.request(token, 'sendMessage', {
                'chat_id': identity, 'text': error_reply(exc).text, 'reply_markup': _menu()})
            return True
        await self.device_interaction(token, identity, 'new', message['text'].strip(), update_id,
                                      keyboard=_device_menu())
        return True

    async def handle_callback(self, token, query, update_id=None):
        query_id = query.get('id')
        if not isinstance(query_id, str) or not query_id:
            return
        message = query.get('message')
        message = message if isinstance(message, dict) else {}
        identity = _private_sender(message.get('chat'), query.get('from'))
        view = query.get('data')
        if identity is not None:
            self.pending_names.pop(identity, None)
        if isinstance(view, str) and view.startswith('dev:'):
            parts = view.split(':', 2)
            message_id = message.get('message_id')
            if (identity is None or len(parts) != 3 or parts[1] not in ACTIONS
                    or parts[1] == 'new' or len(view) > 64 or type(update_id) is not int
                    or type(message_id) is not int or message_id <= 0):
                await self.request(token, 'answerCallbackQuery', {
                    'callback_query_id': query_id, 'text': 'Недоступно.'})
                return
            await self.request(token, 'answerCallbackQuery', {'callback_query_id': query_id})
            await self.device_interaction(token, identity, parts[1], parts[2], update_id, message_id)
            return
        if identity is None or view not in VIEWS:
            await self.request(token, 'answerCallbackQuery', {
                'callback_query_id': query_id, 'text': 'Недоступно.'})
            return
        answer = await self._io(self.reply, identity, view)
        await self.request(token, 'answerCallbackQuery', {'callback_query_id': query_id})
        if answer is None:
            return
        message_id = message.get('message_id')
        if type(message_id) is not int or message_id <= 0:
            return
        text, markup = answer
        # Telegram can only edit inline keyboards; a chat-level reply keyboard
        # must arrive on a new message, including from older inline menus.
        payload = {'chat_id': identity, 'text': text}
        if view != 'menu':
            payload['message_id'] = message_id
        if markup:
            payload['reply_markup'] = markup
        await self.request(token, 'sendMessage' if view == 'menu' else 'editMessageText', payload)

    def retain_unexpected_payment(self, message):
        """Never grant access for a payment without a matching approved order."""
        payer = message.get('from')
        payment = message.get('successful_payment')
        if not isinstance(payer, dict) or not isinstance(payment, dict):
            raise ValueError('Invalid payment update')
        payer_id = payer.get('id')
        charge = payment.get('telegram_payment_charge_id')
        currency = payment.get('currency')
        amount = payment.get('total_amount')
        payload = payment.get('invoice_payload')
        if (type(payer_id) is not int or payer_id <= 0
                or not isinstance(charge, str) or not 1 <= len(charge) <= 255
                or not isinstance(currency, str) or len(currency) != 3
                or type(amount) is not int or amount <= 0
                or not isinstance(payload, str)):
            raise ValueError('Invalid payment update')
        digest = sha256(payload.encode()).hexdigest()
        with Session(self.engine) as db:
            if db.get_bind().dialect.name == 'sqlite':
                db.execute(text('BEGIN IMMEDIATE'))
            existing = db.get(PaymentReceipt, charge)
            if existing is not None:
                if (existing.payer_chat_id != str(payer_id) or existing.currency != currency
                        or existing.amount != amount or existing.payload_hash != digest):
                    raise ValueError('Conflicting payment update')
                return
            db.add(PaymentReceipt(telegram_charge_id=charge, payer_chat_id=str(payer_id),
                                  currency=currency, amount=amount, payload_hash=digest))
            db.add(Audit(actor='master', action='payment.unmatched'))
            db.commit()
        logger.warning('Unmatched Telegram payment recorded for manual review')

    async def poll(self, token):
        updates = await self.request(token, 'getUpdates', {
            'timeout': 25, 'offset': self.offset,
            'allowed_updates': ['message', 'callback_query', 'pre_checkout_query']})
        if not isinstance(updates, list):
            raise ValueError('Telegram Bot API returned invalid updates')
        for update in updates:
            if not isinstance(update, dict) or type(update.get('update_id')) is not int:
                continue
            update_id = update['update_id']
            if self.offset is not None and update_id < self.offset:
                continue
            try:
                checkout = update.get('pre_checkout_query')
                if isinstance(checkout, dict) and isinstance(checkout.get('id'), str):
                    await self.request(token, 'answerPreCheckoutQuery', {
                        'pre_checkout_query_id': checkout['id'], 'ok': False,
                        'error_message': 'Оплата пока недоступна.'})
                    self.offset = update_id + 1
                    continue
                query = update.get('callback_query')
                if isinstance(query, dict):
                    await self.handle_callback(token, query, update_id)
                else:
                    message = update.get('message')
                    message = message if isinstance(message, dict) else {}
                    if 'successful_payment' in message:
                        await self._io(self.retain_unexpected_payment, message)
                        self.offset = update_id + 1
                        continue
                    identity = _private_sender(message.get('chat'), message.get('from'))
                    content = message.get('text')
                    if identity is not None and isinstance(content, str):
                        selection = content.strip()
                        if selection in DEVICE_LABELS:
                            self.pending_names.pop(identity, None)
                            if selection == 'Список устройств':
                                await self.device_interaction(token, identity, 'devices', '', update_id)
                            elif selection == 'Добавить устройство':
                                await self.ask_device_name(token, identity)
                            else:
                                answer = await self._io(self.reply, identity, 'menu')
                                if answer is not None:
                                    await self.request(token, 'sendMessage', {
                                        'chat_id': identity, 'text': answer[0],
                                        'reply_markup': answer[1] or _menu()})
                            self.offset = update_id + 1
                            continue
                        view = MENU_LABELS.get(selection)
                        if view == 'devices':
                            self.pending_names.pop(identity, None)
                            await self.device_menu(token, identity)
                            self.offset = update_id + 1
                            continue
                        if view is not None:
                            self.pending_names.pop(identity, None)
                            answer = await self._io(self.reply, identity, view)
                            if answer is not None:
                                text, markup = answer
                                payload = {'chat_id': identity, 'text': text}
                                if markup:
                                    payload['reply_markup'] = markup
                                await self.request(token, 'sendMessage', payload)
                            self.offset = update_id + 1
                            continue
                        if selection.startswith('/'):
                            self.pending_names.pop(identity, None)
                        elif await self.receive_device_name(token, identity, message, update_id):
                            self.offset = update_id + 1
                            continue
                        parts = selection.split(maxsplit=1)
                        action = parts[0][1:] if parts and parts[0].startswith('/') else None
                        if action in ACTIONS - {'confirm', 'cancel'}:
                            argument = parts[1] if len(parts) == 2 else ''
                            await self.device_interaction(token, identity, action, argument, update_id)
                            self.offset = update_id + 1
                            continue
                    if identity is not None and isinstance(content, str) and content.strip() in COMMANDS:
                        view = 'start' if content.strip() == '/start' else content.strip()[1:]
                        answer = await self._io(self.reply, identity, view, message)
                        if answer is not None:
                            text, markup = answer
                            payload = {'chat_id': identity, 'text': text}
                            if markup:
                                payload['reply_markup'] = markup
                            await self.request(token, 'sendMessage', payload)
            except Exception as exc:
                # httpx exception text can include the token-bearing Bot API URL.
                logger.error('Telegram update failed (%s)', type(exc).__name__)
                break
            self.offset = update_id + 1

    async def deliver_notifications(self, token):
        """At-least-once sends: Telegram success precedes the durable local ACK."""
        if not self.notifications_enabled:
            return
        event_ids = await self._io(due_notifications, self.engine, self.clock())
        for event_id in event_ids:
            claim = await self._io(claim_notification, self.engine, event_id, self.clock())
            if claim is None:
                continue
            claim_token, payload = claim
            message_id = None
            try:
                result = await self.request(token, 'sendMessage', payload)
                chat = result.get('chat') if isinstance(result, dict) else None
                if (not isinstance(result, dict) or type(result.get('message_id')) is not int
                        or result['message_id'] <= 0 or not isinstance(chat, dict)
                        or type(chat.get('id')) is not int or chat['id'] != payload['chat_id']
                        or chat.get('type') != 'private'):
                    raise ValueError('Telegram returned an invalid notification acknowledgement')
                message_id = result['message_id']
            except Exception as exc:
                # Never log exception text/URLs, raw chat IDs, or message bodies.
                logger.error('Telegram notification failed (%s)', type(exc).__name__)
            await self._io(lambda: finish_notification(self.engine, event_id, claim_token,
                                                       self.clock(), message_id=message_id))

    async def run(self, token=None, *, sleep=asyncio.sleep):
        while True:
            try:
                current = token or await self._io(self.setting, 'master_bot_token')
                public = await self._io(self.setting, 'master_public_url')
                if not current or not public:
                    await sleep(30)
                    continue
                self.public_url = self._public_url(public)
                await self.deliver_notifications(current)
                await self.poll(current)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 409:
                    logger.warning('Telegram polling conflict (409)')
                    await sleep(60)
                    continue
                logger.error('Telegram polling failed (HTTP %s)', exc.response.status_code)
            except Exception as exc:
                logger.error('Telegram polling failed (%s)', type(exc).__name__)
            await sleep(2)


async def main():
    engine = make_engine()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=10.0)) as client:
            await Bot(engine, client, notifications_enabled=(
                os.environ.get('VS_MASTER_TELEGRAM_NOTIFICATIONS') == '1')).run()
    finally:
        engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())
