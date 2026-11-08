"""Master subscription outbox. No Telegram/network access in producer transactions."""
from datetime import timedelta
import secrets

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import Account, Subscription, SubscriptionNotification


def private_chat(value):
    """Fail closed on placeholders, group IDs, usernames and noncanonical IDs."""
    return (isinstance(value, str) and value.isascii() and value.isdecimal()
            and len(value) <= 16 and value[0] != '0')


def enqueue_subscription(db, subscription, kind, now):
    """Caller serializes mutation and commits both entitlement and event together."""
    account = db.get(Account, subscription.account_id)
    if (account is None or account.status != 'active' or account.telegram_linked_at is None
            or account.telegram_linked_chat_id != account.telegram_chat_id
            or not private_chat(account.telegram_chat_id)):
        return
    db.flush()
    existing = db.scalar(select(SubscriptionNotification.id).where(
        SubscriptionNotification.subscription_id == subscription.id,
        SubscriptionNotification.revision == subscription.notification_revision,
        SubscriptionNotification.kind == kind))
    if existing is None:
        db.add(SubscriptionNotification(
            subscription_id=subscription.id, revision=subscription.notification_revision,
            kind=kind, chat_id=account.telegram_chat_id, linked_at=account.telegram_linked_at,
            expires_at=subscription.expires_at, next_attempt_at=now, created_at=now))


LEASE_SECONDS = 60  # Longer than the bot's bounded HTTP request timeout (35 s).


def due_notifications(engine, now, limit=20):
    with Session(engine) as db:
        return list(db.scalars(select(SubscriptionNotification.id).where(
            SubscriptionNotification.status == 'pending',
            SubscriptionNotification.next_attempt_at <= now).order_by(
                SubscriptionNotification.next_attempt_at, SubscriptionNotification.id).limit(limit)))


def claim_notification(engine, event_id, now):
    """Short writer transaction, committed before returning a network payload."""
    with Session(engine) as db:
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        event = db.get(SubscriptionNotification, event_id)
        if event is None or event.status != 'pending' or event.next_attempt_at > now:
            return None
        subscription = db.get(Subscription, event.subscription_id)
        account = db.get(Account, subscription.account_id) if subscription else None
        valid = (account is not None and account.status == 'active'
                 and account.telegram_linked_at == event.linked_at
                 and account.telegram_linked_chat_id == event.chat_id
                 and account.telegram_chat_id == event.chat_id and private_chat(event.chat_id)
                 and subscription is not None
                 and subscription.notification_revision == event.revision
                 # An expiry notice describes the inactive entitlement, not its
                 # exact deadline. Past-to-past corrections keep this revision.
                 and (event.kind == 'expired' or subscription.expires_at == event.expires_at))
        if valid and subscription is not None:
            active = subscription.status == 'active' and subscription.expires_at > now
            valid = active if event.kind == 'active' else not active
        if not valid:
            event.status = 'suppressed'
            event.claim_token = None
            db.commit()
            return None
        event.claim_token = secrets.token_hex(16)
        event.attempts += 1
        event.next_attempt_at = now + timedelta(seconds=LEASE_SECONDS)
        text_value = (f'Подписка активна до {event.expires_at:%d.%m.%Y %H:%M} UTC.'
                      if event.kind == 'active' else
                      'Срок подписки истёк. Для продления обратитесь к администратору.')
        result = (event.claim_token, {'chat_id': int(event.chat_id), 'text': text_value})
        db.commit()
        return result


def finish_notification(engine, event_id, claim_token, now, *, message_id=None):
    """Only the current lease owner may acknowledge or reschedule an attempt."""
    with Session(engine) as db:
        if db.get_bind().dialect.name == 'sqlite':
            db.execute(text('BEGIN IMMEDIATE'))
        event = db.get(SubscriptionNotification, event_id)
        if event is None or event.status != 'pending' or event.claim_token != claim_token:
            return
        event.claim_token = None
        if message_id is not None:
            event.status = 'delivered'
            event.delivered_at = now
            event.message_id = message_id
        else:
            delay = min(3600, 30 * 2 ** min(event.attempts - 1, 7))
            event.next_attempt_at = now + timedelta(seconds=delay)
        db.commit()
