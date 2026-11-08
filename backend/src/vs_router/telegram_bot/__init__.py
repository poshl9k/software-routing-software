"""Standalone Telegram Bot API worker for the subscriber portal."""
import asyncio
import hashlib
import logging
import os
import re
import secrets
from datetime import datetime, timezone

import httpx
from argon2 import PasswordHasher
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from vs_portal.bot_token import PREFIX, decode_bot_token, encode_bot_token
from vs_portal.models import Account, Audit, Device, Setting, Subscription, Tariff, TelegramLink, make_engine
from vs_portal.security import get_secret_key

logger = logging.getLogger(__name__)
DATABASE_URL = 'sqlite:////var/lib/vs-router/portal/vs-portal.db'
HELP = 'Команды: /start, /menu, /status, /devices, /support, /help.'
UNLINKED = 'Войдите в портал и получите код привязки. Отправьте /start КОД.'
MENU = 'Выберите раздел.'
COMMANDS = {'/start', '/menu', '/register', '/status', '/devices', '/support', '/help'}
VIEWS = {'menu', 'register', 'status', 'devices', 'support', 'help'}


def menu_markup(view='menu'):
    if view == 'register':
        return {'inline_keyboard': [[{'text': 'Зарегистрироваться', 'callback_data': 'register'}]]}
    if view != 'menu':
        return {'inline_keyboard': [[{'text': 'Назад в меню', 'callback_data': 'menu'}]]}
    return {'inline_keyboard': [
        [{'text': 'Статус', 'callback_data': 'status'},
         {'text': 'Устройства', 'callback_data': 'devices'}],
        [{'text': 'Поддержка', 'callback_data': 'support'},
         {'text': 'Помощь', 'callback_data': 'help'}],
    ]}


def _activity(device):
    # created_at is not a handshake. Do not present it as a live activity timestamp.
    created = getattr(device, 'created_at', None)
    return (f'Последняя известная активность: данных нет (создано {created:%d.%m.%Y %H:%M} UTC)'
            if created else 'Последняя известная активность: данных нет')


class Bot:
    def __init__(self, engine, client, *, sleep=asyncio.sleep):
        self.engine = engine
        self.client = client
        self.sleep = sleep
        self.offset = None


    def setting(self, key):
        with Session(self.engine) as db:
            row = db.get(Setting, key)
            value = row.value.strip() if row and row.value else ''
            if key != 'bot_token' or not value:
                return value
            secret_key = get_secret_key()
            token = decode_bot_token(value, secret_key)
            if not value.startswith(PREFIX):
                db.execute(update(Setting).where(Setting.key == key, Setting.value == value)
                           .values(value=encode_bot_token(token, secret_key)))
                db.commit()
            return token

    def register(self, chat_id):
        if not re.fullmatch(r'[1-9][0-9]{0,19}', chat_id):
            return UNLINKED
        with Session(self.engine) as db:
            db.execute(text('BEGIN IMMEDIATE'))
            enabled = db.get(Setting, 'self_registration_enabled')
            if enabled is None or enabled.value != '1':
                return UNLINKED
            existing = db.scalar(select(Account).where(Account.telegram_chat_id == chat_id))
            if existing is not None:
                return ('Аккаунт уже привязан. ' + MENU if existing.status == 'active'
                        else UNLINKED)
            name = 'tg-' + chat_id
            if db.get(Account, name) is not None:
                return 'Не удалось зарегистрировать аккаунт. Обратитесь в поддержку.'
            # The Telegram identity cannot be used as a web password. A separate
            # one-use portal credential flow is required before web access.
            password_hash = PasswordHasher().hash(secrets.token_urlsafe(32))
            db.add(Account(subscriber_name=name, telegram_chat_id=chat_id,
                           password_hash=password_hash, status='active'))
            db.add(Audit(actor=name, action='telegram.register'))
            db.commit()
            return 'Аккаунт зарегистрирован. Подписка пока не активна. ' + MENU

    def reply(self, chat_id, message):
        if message == '/register':
            return self.register(chat_id)
        with Session(self.engine) as db:
            if message.startswith('/start '):
                code = message.partition(' ')[2].strip()
                if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', code):
                    return UNLINKED
                db.execute(text('BEGIN IMMEDIATE'))
                link = db.get(TelegramLink, hashlib.sha256(code.encode()).hexdigest())
                if link is None or link.expires_at <= datetime.now(timezone.utc):
                    linked = db.scalar(select(Account).where(Account.telegram_chat_id == chat_id,
                                                              Account.status == 'active'))
                    return 'Аккаунт уже привязан. ' + MENU if linked else UNLINKED
                target = db.get(Account, link.subscriber_name)
                if target is None or target.status != 'active':
                    return UNLINKED
                for previous in db.scalars(select(Account).where(Account.telegram_chat_id == chat_id)):
                    previous.telegram_chat_id = None
                db.flush()
                target.telegram_chat_id = chat_id
                db.delete(link)
                db.add(Audit(actor=target.subscriber_name, action='telegram.link'))
                db.commit()
                return 'Аккаунт привязан. ' + MENU
            account = db.scalar(select(Account).where(Account.telegram_chat_id == chat_id,
                                                      Account.status == 'active'))
            if message in ('/start', '/menu'):
                if account:
                    return ('Аккаунт уже привязан. ' if message == '/start' else '') + MENU
                return UNLINKED
            if message == '/help':
                return HELP
            if message == '/support':
                contact = db.get(Setting, 'support_url')
                return f'Поддержка: {contact.value}' if contact and contact.value.strip() else 'Контакт поддержки не настроен.'
            if message not in ('/status', '/devices'):
                return HELP if account else UNLINKED
            if account is None:
                return UNLINKED
            name = account.subscriber_name
            if message == '/status':
                subscription = db.get(Subscription, name)
                if subscription is None:
                    return 'Подписка не найдена. Тариф: нет данных. Устройства: нет данных.'
                tariff = db.get(Tariff, subscription.tariff_id)
                count = db.scalar(select(func.count(Device.id)).where(
                    Device.subscriber_name == name, Device.status != 'removed')) or 0
                return (f'Тариф: {tariff.name if tariff else "нет данных"}\n'
                        f'Истекает: {subscription.expires_at:%d.%m.%Y}\n'
                        f'Устройства: {count} / {tariff.device_limit if tariff else "нет данных"}')
            devices = db.scalars(select(Device).where(
                Device.subscriber_name == name, Device.status != 'removed').order_by(Device.id)).all()
            if not devices:
                return 'Устройств нет.'
            return '\n'.join(f'{item.label or item.name or "Без имени"} — статус: {item.status}; '
                             f'{_activity(item)}' for item in devices)

    async def request(self, token, method, payload):
        response = await self.client.post(f'https://api.telegram.org/bot{token}/{method}', json=payload)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or data.get('ok') is not True:
            raise ValueError('Telegram Bot API rejected request')
        return data.get('result')

    async def handle_callback(self, token, query):
        query_id = query.get('id')
        if not isinstance(query_id, str) or not query_id:
            return
        message = query.get('message')
        message = message if isinstance(message, dict) else {}
        chat = message.get('chat')
        chat = chat if isinstance(chat, dict) else {}
        sender = query.get('from')
        sender = sender if isinstance(sender, dict) else {}
        view = query.get('data')
        chat_id = chat.get('id')
        if (chat.get('type') != 'private' or not isinstance(chat_id, int)
                or sender.get('id') != chat_id or not isinstance(view, str)
                or view not in VIEWS):
            await self.request(token, 'answerCallbackQuery', {
                'callback_query_id': query_id, 'text': 'Недоступно.'})
            return
        command = '/menu' if view == 'menu' else '/' + view
        answer = await asyncio.to_thread(self.reply, str(chat_id), command)
        await self.request(token, 'answerCallbackQuery', {'callback_query_id': query_id})
        message_id = message.get('message_id')
        if (not isinstance(message_id, int) or message_id <= 0
                or not isinstance(message.get('text'), str) or message['text'] == answer):
            return
        payload = {'chat_id': str(chat_id), 'message_id': message_id, 'text': answer}
        if answer != UNLINKED:
            payload['reply_markup'] = menu_markup('menu' if view == 'register' else view)
        await self.request(token, 'editMessageText', payload)

    async def poll(self, token):
        updates = await self.request(token, 'getUpdates', {
            'timeout': 25, 'offset': self.offset, 'allowed_updates': ['message', 'callback_query']})
        if not isinstance(updates, list):
            raise ValueError('Telegram Bot API returned invalid updates')
        for update in updates:
            if not isinstance(update, dict) or not isinstance(update.get('update_id'), int):
                continue
            update_id = update['update_id']
            if self.offset is not None and update_id < self.offset:
                continue
            try:
                if isinstance(update.get('callback_query'), dict):
                    await self.handle_callback(token, update['callback_query'])
                    self.offset = update_id + 1
                    continue
                message = update.get('message') or {}
                chat = message.get('chat') or {}
                if chat.get('type') != 'private' or not isinstance(chat.get('id'), int):
                    self.offset = update_id + 1
                    continue
                content = message.get('text')
                if not isinstance(content, str):
                    self.offset = update_id + 1
                    continue
                content = content.strip()
                if content not in COMMANDS and not content.startswith('/start '):
                    self.offset = update_id + 1
                    continue
                chat_id = str(chat['id'])
                answer = await asyncio.to_thread(self.reply, chat_id, content)
                payload = {'chat_id': chat_id, 'text': answer}
                if answer == UNLINKED and content in ('/start', '/menu'):
                    enabled = await asyncio.to_thread(self.setting, 'self_registration_enabled')
                    if enabled == '1':
                        payload['reply_markup'] = menu_markup('register')
                elif answer != UNLINKED:
                    payload['reply_markup'] = menu_markup(
                        'menu' if content in ('/start', '/menu', '/register') or content.startswith('/start ')
                        else content[1:])
                await self.request(token, 'sendMessage', payload)
            except Exception as exc:
                # Exception text may contain token-bearing URL; never include it.
                logger.exception('Update failed (%s)', type(exc).__name__, exc_info=False)
                break  # Telegram redelivers this update at the unchanged offset.
            self.offset = update_id + 1

    async def run(self):
        while True:
            try:
                token = await asyncio.to_thread(self.setting, 'bot_token')
                if not token:
                    logger.warning('Bot token is not configured')
                    await self.sleep(30)
                    continue
                await self.poll(token)
            except Exception as exc:
                # httpx exception strings may embed the Bot API token.
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 409:
                    logger.warning('Telegram polling conflict (409): another consumer is active')
                    await self.sleep(60)
                    continue
                logger.error('Polling failed (%s)', type(exc).__name__)
            await self.sleep(2)


async def main():
    engine = make_engine(os.environ.get('VS_PORTAL_DATABASE_URL', DATABASE_URL))
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=10.0)) as client:
            await Bot(engine, client).run()
    finally:
        engine.dispose()
