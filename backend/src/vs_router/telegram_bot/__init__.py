"""Standalone Telegram Bot API worker for the subscriber portal."""
import asyncio
import logging
import os

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vs_portal.models import Account, Device, Setting, Subscription, Tariff, make_engine

logger = logging.getLogger(__name__)
DATABASE_URL = 'sqlite:////var/lib/vs-router/portal/vs-portal.db'
HELP = 'Команды: /start, /status, /devices, /support, /help.'
UNLINKED = 'Сначала привяжите аккаунт: отправьте /start.'


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
        self.awaiting_login = set()

    def setting(self, key):
        with Session(self.engine) as db:
            row = db.get(Setting, key)
            return row.value.strip() if row and row.value else ''

    def reply(self, chat_id, message):
        with Session(self.engine) as db:
            account = db.scalar(select(Account).where(Account.telegram_chat_id == chat_id,
                                                      Account.status == 'active'))
            if message == '/start':
                if account:
                    self.awaiting_login.discard(chat_id)
                    return 'Аккаунт уже привязан. ' + HELP
                self.awaiting_login.add(chat_id)
                return 'Отправьте логин вашего аккаунта портала следующим сообщением.'
            if message == '/help':
                return HELP
            if message == '/support':
                contact = db.get(Setting, 'support_url')
                return f'Поддержка: {contact.value}' if contact and contact.value.strip() else 'Контакт поддержки не настроен.'
            if chat_id in self.awaiting_login and not message.startswith('/'):
                name = message.strip()
                if not name or len(name) > 64:
                    return 'Аккаунт не найден или отключён.'
                # Serialize lookup, previous binding removal and new binding across workers.
                db.execute(text('BEGIN IMMEDIATE'))
                target = db.get(Account, name)
                if target is None or target.status != 'active':
                    return 'Аккаунт не найден или отключён.'
                for previous in db.scalars(select(Account).where(Account.telegram_chat_id == chat_id)):
                    previous.telegram_chat_id = None
                db.flush()
                target.telegram_chat_id = chat_id
                db.commit()
                self.awaiting_login.discard(chat_id)
                return 'Аккаунт привязан. ' + HELP
            if message not in ('/status', '/devices'):
                return HELP
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

    async def poll(self, token):
        updates = await self.request(token, 'getUpdates', {
            'timeout': 25, 'offset': self.offset, 'allowed_updates': ['message']})
        if not isinstance(updates, list):
            raise ValueError('Telegram Bot API returned invalid updates')
        for update in updates:
            if not isinstance(update, dict) or not isinstance(update.get('update_id'), int):
                continue
            update_id = update['update_id']
            if self.offset is not None and update_id < self.offset:
                continue
            try:
                message = update.get('message') or {}
                chat = message.get('chat') or {}
                if chat.get('type') != 'private' or not isinstance(chat.get('id'), int):
                    continue
                content = message.get('text')
                if not isinstance(content, str):
                    continue
                chat_id = str(chat['id'])
                answer = self.reply(chat_id, content.strip())
                await self.request(token, 'sendMessage', {'chat_id': chat_id, 'text': answer})
            except Exception as exc:
                # Exception text may contain token-bearing URL; never include it.
                logger.exception('Update failed (%s)', type(exc).__name__, exc_info=False)
            finally:
                self.offset = update_id + 1

    async def run(self):
        while True:
            try:
                token = self.setting('bot_token')
                if not token:
                    logger.warning('Bot token is not configured')
                    await self.sleep(30)
                    continue
                await self.poll(token)
            except Exception as exc:
                # httpx exception strings may embed the Bot API token.
                logger.error('Polling failed (%s)', type(exc).__name__)
            await self.sleep(2)


async def main():
    engine = make_engine(os.environ.get('VS_PORTAL_DATABASE_URL', DATABASE_URL))
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(35.0, connect=10.0)) as client:
            await Bot(engine, client).run()
    finally:
        engine.dispose()
