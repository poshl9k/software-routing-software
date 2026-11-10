"""Master-owned subscriber database schema (ADR-0035).

Divergences from the per-node portal schema (`vs_portal.models`), per D3/D4/D5:

- ``Account`` carries a surrogate integer primary key; the Telegram ID is the
  unique identity; the display name is plain text without uniqueness (the node
  portal treats ``subscriber_name`` as the key — that contract ends here).
- ``Subscription`` belongs to an account (one active per account), not to a
  display name.
- ``Device`` and ``DeviceOp`` carry ``node_id``: the node is an attribute of the
  device, and the master worker executes device operations against the node's
  bridge.
- ``Node`` is the master-side registry: bridge base URL, bearer token
  (encrypted), admin-set capacity, telemetry cache.

``Tariff`` matches the portal model field-for-field, but it is redeclared on
this package's own declarative base: sharing the portal Base would drag the
whole per-node portal schema into the master database. Reuse stays at the
column-type helpers (`UTCDateTime`, `SecretJSON`), which are shared by import.
"""
from datetime import datetime
import os

from sqlalchemy import (JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String,
                        Text, Index, UniqueConstraint, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool

from vs_portal.models import SecretJSON, UTCDateTime, utcnow
from vs_router.schema import EncryptedSecret


class Base(DeclarativeBase):
    pass


class Node(Base):
    """A registered vs-panel node; the master's only way to reach subscriber data."""
    __tablename__ = 'master_nodes'
    __table_args__ = (CheckConstraint("state IN ('ok', 'stale', 'down')", name='ck_master_node_state'),
                      UniqueConstraint('name', name='uq_master_node_name'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    # Base URL of the node's internal bridge (https://host/...).
    bridge_url: Mapped[str] = mapped_column(String(255), nullable=False)
    # Long-lived bearer token for (master, node); rotated via token-rotate.
    bridge_token: Mapped[EncryptedSecret] = mapped_column(SecretJSON(), nullable=False)
    # Admin-set capacity in active devices; the load-balancing metric (D4).
    capacity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    # Topology role: the node a subscriber connects to ("entry"), a foreign exit
    # ("egress"), or both. Existing installations default to "both" so device
    # placement keeps working until roles are assigned explicitly.
    role: Mapped[str] = mapped_column(String(6), nullable=False, default='both',
                                      server_default='both')
    # Client-facing address (host or host:port) when this node accepts entries.
    public_entry: Mapped[str | None] = mapped_column(String(255))
    # Telemetry cache (D7): master polls ~every 30-60 s.
    state: Mapped[str] = mapped_column(String(8), nullable=False, default='down')
    active_peers: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Account(Base):
    """Subscriber identity: Telegram ID is the unique key, name is display text."""
    __tablename__ = 'master_accounts'
    __table_args__ = (CheckConstraint("status IN ('active', 'disabled')", name='ck_master_account_status'),
                      UniqueConstraint('telegram_chat_id', name='uq_master_account_tg'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Display text only; uniqueness is NOT required (D4).
    display_name: Mapped[str] = mapped_column(String(64), nullable=False)
    telegram_chat_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Only a verified private /start establishes notification consent/routing.
    telegram_linked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    telegram_linked_chat_id: Mapped[str | None] = mapped_column(String(64))
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='active')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class MagicLogin(Base):
    """Short-lived, single-use proof sent only to the account's Telegram chat."""
    __tablename__ = 'master_magic_logins'
    __table_args__ = (Index('ix_master_magic_account', 'account_id'),)
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey('master_accounts.id'), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class PaymentReceipt(Base):
    """Unexpected Telegram charges; no entitlement until manual reconciliation."""
    __tablename__ = 'master_payment_receipts'
    __table_args__ = (CheckConstraint('amount > 0', name='ck_master_receipt_amount'),)
    telegram_charge_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    payer_chat_id: Mapped[str] = mapped_column(String(64), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class StarsOrder(Base):
    """Two fixed pilot attempts; immutable first order, never a sale catalogue."""
    __tablename__ = 'master_stars_orders'
    __table_args__ = (
        UniqueConstraint('test_slot', name='uq_master_stars_slot'),
        UniqueConstraint('payload_hash', name='uq_master_stars_payload'),
        UniqueConstraint('paid_charge_id', name='uq_master_stars_charge'),
        CheckConstraint("test_slot IN ('super-30d-1xtr-v1', 'super-30d-1xtr-retry-v1')",
                        name='ck_master_stars_slot'),
        CheckConstraint("currency = 'XTR' AND amount = 1 AND term_days = 30 AND device_limit = 50 AND tariff_id = 3",
                        name='ck_master_stars_product'),
        CheckConstraint("state IN ('sending', 'sent', 'paid', 'review')", name='ck_master_stars_state'),
        CheckConstraint("fulfillment_status IN ('pending', 'applied', 'review')", name='ck_master_stars_fulfillment'),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_slot: Mapped[str] = mapped_column(String(64), nullable=False)
    bot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    account_id: Mapped[int] = mapped_column(ForeignKey('master_accounts.id'), nullable=False)
    subscription_id: Mapped[int] = mapped_column(ForeignKey('master_subscriptions.id'), nullable=False)
    tariff_id: Mapped[int] = mapped_column(ForeignKey('master_tariffs.id'), nullable=False)
    tariff_name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    payer_chat_id: Mapped[str] = mapped_column(String(64), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    term_days: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    state: Mapped[str] = mapped_column(String(8), nullable=False, default='sending')
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    message_id: Mapped[int | None] = mapped_column(Integer)
    checkout_id: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    paid_charge_id: Mapped[str | None] = mapped_column(ForeignKey('master_payment_receipts.telegram_charge_id'))
    paid_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    granted_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    fulfillment_status: Mapped[str] = mapped_column(String(8), nullable=False, default='pending')


class StarsPaymentEvent(Base):
    """Immutable observations, including altered replays retained for review."""
    __tablename__ = 'master_stars_payment_events'
    __table_args__ = (
        CheckConstraint("status IN ('granted', 'review', 'unmatched')", name='ck_master_stars_event_status'),
        CheckConstraint('amount > 0', name='ck_master_stars_event_amount'),
    )
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    telegram_charge_id: Mapped[str] = mapped_column(
        ForeignKey('master_payment_receipts.telegram_charge_id'), nullable=False)
    order_id: Mapped[int | None] = mapped_column(ForeignKey('master_stars_orders.id'))
    payer_chat_id: Mapped[str] = mapped_column(String(64), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(9), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)


class StarsFulfillment(Base):
    """Each paid order/node points at its durable existing worker reconcile ticket."""
    __tablename__ = 'master_stars_fulfillments'
    __table_args__ = (UniqueConstraint('op_id', name='uq_master_stars_fulfillment_op'),)
    order_id: Mapped[int] = mapped_column(ForeignKey('master_stars_orders.id'), primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey('master_nodes.id'), primary_key=True)
    op_id: Mapped[int] = mapped_column(ForeignKey('master_device_ops.id'), nullable=False)


class Tariff(Base):
    """Rule for issuing access: device limit and term. Same shape as the portal tariff."""
    __tablename__ = 'master_tariffs'
    __table_args__ = (CheckConstraint('device_limit >= 1', name='ck_master_tariff_device_limit'),
                      CheckConstraint('term_days >= 1', name='ck_master_tariff_term_days'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    term_days: Mapped[int] = mapped_column(Integer, nullable=False)
    price_amount: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Subscription(Base):
    """Access grant belonging to the ACCOUNT; may cover devices on several nodes (D6)."""
    __tablename__ = 'master_subscriptions'
    __table_args__ = (CheckConstraint("status IN ('active', 'expired')", name='ck_master_subscription_status'),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey('master_accounts.id'), nullable=False)
    tariff_id: Mapped[int] = mapped_column(ForeignKey('master_tariffs.id'), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='active')
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    notification_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default='0')


class SubscriptionNotification(Base):
    """Transactional outbox; claims expire so a crashed sender cannot lose events."""
    __tablename__ = 'master_subscription_notifications'
    __table_args__ = (
        UniqueConstraint('subscription_id', 'revision', 'kind', name='uq_master_notification_event'),
        CheckConstraint("kind IN ('active', 'expired')", name='ck_master_notification_kind'),
        CheckConstraint("status IN ('pending', 'delivered', 'suppressed')", name='ck_master_notification_status'),
        CheckConstraint('revision >= 0 AND attempts >= 0', name='ck_master_notification_counters'),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey('master_subscriptions.id'), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    chat_id: Mapped[str] = mapped_column(String(64), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default='pending')
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    claim_token: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    delivered_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    message_id: Mapped[int | None] = mapped_column(Integer)


class Device(Base):
    """Subscriber device (peer) attached to exactly one node (D6); no auto-migration."""
    __tablename__ = 'master_devices'
    __table_args__ = (UniqueConstraint('account_id', 'name', name='uq_master_device_owner_name'),
                      CheckConstraint("status IN ('active', 'inactive', 'removed')", name='ck_master_device_status'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey('master_accounts.id'), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey('master_nodes.id'), nullable=False)
    # The subscriber NAME in the node's router configuration: the node bridge
    # addresses device operations by name, so the master carries the mapping.
    node_subscriber: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str | None] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key: Mapped[str | None] = mapped_column(String(128))
    private_key: Mapped[EncryptedSecret | None] = mapped_column(SecretJSON())
    preshared_key: Mapped[EncryptedSecret | None] = mapped_column(SecretJSON())
    allowed_ips: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='inactive')
    # Preferred foreign exit for this device's chain; None keeps the node default.
    egress_node_id: Mapped[int | None] = mapped_column(ForeignKey('master_nodes.id'))
    tunnel_name: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class DeviceOp(Base):
    """Pending device operation; the master worker executes it against Device.node_id's bridge."""
    __tablename__ = 'master_device_ops'
    __table_args__ = (CheckConstraint("op IN ('create', 'delete', 'activate', 'deactivate', 'expire')", name='ck_master_op_kind'),
                      CheckConstraint("status IN ('pending', 'applied', 'failed')", name='ck_master_op_status'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey('master_accounts.id'), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey('master_nodes.id'), nullable=False)
    op: Mapped[str] = mapped_column(String(12), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey('master_devices.id'))
    label: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='pending')
    detail: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Audit(Base):
    __tablename__ = 'master_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(128))
    at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Setting(Base):
    """Admin-editable master settings (key/value); e.g. the bot token (encrypted at the API layer)."""
    __tablename__ = 'master_settings'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256), nullable=False)


class DeviceSubscription(Base):
    """Revocable per-device subscription link; only the token hash is stored.

    The raw token is shown once at issue time and travels only inside the URL a
    client fetches, so deleting the device or reissuing makes the old link dead.
    """
    __tablename__ = 'master_device_subscriptions'
    device_id: Mapped[int] = mapped_column(ForeignKey('master_devices.id'), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class RuleSetSource(Base):
    """Auto-refreshing upstream list (e.g. the panel's built-in geoip/domain sources).

    The master keeps only the URL and interval; content lives in immutable
    ``RuleSet`` versions, so a refresh publishes a new version instead of
    rewriting history.
    """
    __tablename__ = 'master_rule_set_sources'
    __table_args__ = (UniqueConstraint('name', name='uq_master_ruleset_source_name'),
                      CheckConstraint("kind IN ('domain', 'ipcidr')",
                                      name='ck_master_ruleset_source_kind'),
                      CheckConstraint('interval_seconds >= 3600',
                                      name='ck_master_ruleset_source_interval'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    version: Mapped[str | None] = mapped_column(String(32))
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class RuleSet(Base):
    """Immutable rule-set version served to clients by exact version (ADR-0035 split rules).

    Clients fetch a pinned version through a `rule-provider`, so a published row
    must never change: a correction is a new version, and the served hash is
    verified on read.
    """
    __tablename__ = 'master_rule_sets'
    __table_args__ = (UniqueConstraint('kind', 'version', name='uq_master_ruleset_version'),
                      CheckConstraint("kind IN ('domain', 'ipcidr')", name='ck_master_ruleset_kind'),
                      CheckConstraint('entries > 0', name='ck_master_ruleset_entries'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    entries: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


def make_engine(database_url=None):
    url = database_url or os.environ.get('VS_MASTER_DATABASE_URL', 'sqlite:///vs-master.db')
    sqlite = url.startswith('sqlite:')
    options = {'connect_args': {'check_same_thread': False}} if sqlite else {}
    if url in ('sqlite://', 'sqlite:///:memory:'):
        options['poolclass'] = StaticPool
    engine = create_engine(url, **options)
    if sqlite:
        @event.listens_for(engine, 'connect')
        def sqlite_pragmas(connection, record):
            cursor = connection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON')
            # Shared in-memory databases cannot use WAL.
            if url not in ('sqlite://', 'sqlite:///:memory:'):
                cursor.execute('PRAGMA journal_mode=WAL')
            cursor.close()
    return engine
