"""Private Telegram device interaction adapter over the master's shared domain."""
import secrets
from dataclasses import dataclass
from datetime import timedelta
from threading import RLock

from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from . import device_service as devices
from .exports import device_export
from .models import Account

ACTIONS = {'devices', 'new', 'activate', 'deactivate', 'delete', 'conf', 'qr', 'amnezia',
           'mihomo', 'confirm', 'cancel'}
PAGE_SIZE = 5


@dataclass
class DeviceReply:
    text: str = ''
    markup: dict | None = None
    attachment: tuple | None = None
    authorization: tuple | None = None


def verified_account(db, identity):
    account = db.scalar(select(Account).where(
        Account.telegram_chat_id == str(identity), Account.status == 'active',
        Account.telegram_linked_chat_id == str(identity),
        Account.telegram_linked_at.is_not(None)))
    if account is None:
        raise APIError(403, 'auth.forbidden')
    return account


def _device_id(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() \
            or not 1 <= len(value) <= 18 or int(value) <= 0:
        raise APIError(422, 'portal.device_not_found')
    return int(value)


def error_reply(exc):
    # Allowlisted messages only: never include bridge response/exception text,
    # URLs, keys, or details from a failed persisted DeviceOp.
    text = {
        'auth.forbidden': 'Недоступно. Отправьте /start в личном чате; аккаунт должен быть активен.',
        'portal.subscription_expired': 'Нужна активная подписка для устройств и конфигов.',
        'portal.device_limit': 'Достигнут лимит устройств тарифа.',
        'portal.device_not_found': 'Устройство не найдено.',
        'portal.device_label': 'Метка должна содержать от 1 до 128 символов: /new Телефон',
        'portal.operation_pending': 'Операция уже в очереди. Проверьте /devices.',
        'portal.device_active': 'Устройство уже активно.',
        'portal.device_inactive': 'Устройство уже неактивно.',
        'bot.confirmation_invalid': 'Подтверждение недействительно. Запросите удаление заново.',
        'amnezia.role_unsupported': 'Amnezia недоступна для этого протокола. Используйте .conf или QR.',
    }.get(getattr(exc, 'code', ''), 'Операция недоступна. Проверьте /devices и повторите позже.')
    return DeviceReply(text, {'inline_keyboard': [[{'text': 'Устройства', 'callback_data': 'dev:devices:0'}]]})


class DeviceController:
    def __init__(self, engine):
        self.engine = engine
        self.lock = RLock()
        self.confirmations = {}

    def menu_access(self, identity, now):
        with Session(self.engine) as db:
            account = verified_account(db, identity)
            devices.live_subscription(db, account.id, now)
            return account.id, account.telegram_linked_at

    def authorize_export(self, identity, authorization, now):
        with Session(self.engine) as db:
            account = verified_account(db, identity)
            if (account.id, account.telegram_linked_at) != authorization[:2]:
                raise APIError(403, 'auth.forbidden')
            devices.live_subscription(db, account.id, now)
            devices.device_owned(db, authorization[2], account.id)

    def execute(self, identity, action, argument, now, node_client_factory, receipt_key):
        # One device interaction per controller, including confirmation consume.
        # There is no DB writer transaction spanning Telegram I/O.
        with self.lock, Session(self.engine) as db:
            account = verified_account(db, identity)
            devices.live_subscription(db, account.id, now)
            context = dict(engine=self.engine, node_client_factory=node_client_factory,
                           device_lock=self.lock, now=now, receipt_key=receipt_key)
            if action == 'devices':
                page = int(argument) if isinstance(argument, str) and argument.isascii() \
                    and argument.isdecimal() and len(argument) <= 6 else 0
                return self._list(devices.list_devices(db, account, node_client_factory)['devices'], page)
            if action == 'new':
                return self._operation(devices.create_device(db, account, argument, **context))
            if action in ('confirm', 'cancel'):
                proof = self.confirmations.get(identity)
                if (proof is None or not secrets.compare_digest(proof[0], argument)
                        or proof[1] <= now or proof[2:4] != (account.id, account.telegram_linked_at)):
                    raise APIError(403, 'bot.confirmation_invalid')
                del self.confirmations[identity]
                if action == 'cancel':
                    return DeviceReply('Удаление отменено.')
                return self._operation(devices.change_device(db, account, proof[4], 'delete', **context))
            device_id = _device_id(argument)
            device = devices.device_owned(db, device_id, account.id)
            if action == 'delete':
                if devices.pending_operation(db, device_id) is not None:
                    raise APIError(409, 'portal.operation_pending')
                self.confirmations = {key: proof for key, proof in self.confirmations.items()
                                      if proof[1] > now}
                if len(self.confirmations) >= 1000 and identity not in self.confirmations:
                    raise APIError(429, 'bot.busy')
                nonce = secrets.token_urlsafe(18)
                self.confirmations[identity] = (nonce, now + timedelta(minutes=2), account.id,
                                                account.telegram_linked_at, device_id)
                return DeviceReply(f'Удалить устройство #{device_id} «{device.label}»? '
                                   'Ключи будут удалены. Подтвердите в течение 2 минут.',
                    {'inline_keyboard': [
                        [{'text': 'Удалить навсегда', 'callback_data': f'dev:confirm:{nonce}'}],
                        [{'text': 'Отмена', 'callback_data': f'dev:cancel:{nonce}'}]]})
            if action in ('activate', 'deactivate'):
                return self._operation(devices.change_device(db, account, device_id, action, **context))
            if action in ('conf', 'qr', 'amnezia', 'mihomo'):
                content, media_type, _ = device_export(db, account, device_id, action, now, node_client_factory)
                suffix = {'conf': '.conf', 'qr': '.png', 'amnezia': '-amnezia.txt',
                          'mihomo': '.yaml'}[action]
                return DeviceReply(attachment=(action, content, media_type, f'device-{device_id}{suffix}'),
                                   authorization=(account.id, account.telegram_linked_at, device_id))
            raise APIError(422, 'portal.operation_invalid')

    @staticmethod
    def _operation(result):
        text = ('Операция в очереди; применение ещё не подтверждено.' if result['status'] == 'pending'
                else 'Операция применена.')
        return DeviceReply(f"{text} Устройство #{result['device_id']}. Проверьте /devices.")

    @staticmethod
    def _list(items, offset):
        offset = min(offset, max(len(items) - 1, 0))
        lines = ['Устройства. Создать: «Добавить устройство» или /new Метка']
        rows = []
        for item in items[offset:offset + PAGE_SIZE]:
            device_id = item['id']
            label = item['label'].replace('\r', ' ').replace('\n', ' ')
            handshake = item['last_handshake']
            handshake = str(handshake) if type(handshake) is int else 'нет данных'
            lines.append(f"#{device_id} {label} — {item['status']}; "
                         f"применено: {'да' if item['applied'] else 'нет'}; handshake: {handshake}")
            if item['status'] == 'pending':
                lines.append(f"В очереди: {item['pending_op']}.")
            toggle = 'deactivate' if item['status'] == 'active' else 'activate'
            rows.extend([
                [{'text': f'#{device_id} ' + ('Выключить' if toggle == 'deactivate' else 'Включить'),
                  'callback_data': f'dev:{toggle}:{device_id}'},
                 {'text': 'Удалить', 'callback_data': f'dev:delete:{device_id}'}],
                [{'text': '.conf', 'callback_data': f'dev:conf:{device_id}'},
                 {'text': 'QR', 'callback_data': f'dev:qr:{device_id}'},
                 {'text': 'Amnezia', 'callback_data': f'dev:amnezia:{device_id}'}],
                [{'text': 'Clash', 'callback_data': f'dev:mihomo:{device_id}'}]])
        if not items:
            lines.append('Устройств пока нет.')
        nav = []
        if offset:
            nav.append({'text': 'Ранее', 'callback_data': f'dev:devices:{max(0, offset - PAGE_SIZE)}'})
        if offset + PAGE_SIZE < len(items):
            nav.append({'text': 'Далее', 'callback_data': f'dev:devices:{offset + PAGE_SIZE}'})
        if nav:
            rows.append(nav)
        return DeviceReply('\n'.join(lines), {'inline_keyboard': rows} if rows else None)
