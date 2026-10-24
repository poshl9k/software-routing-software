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
                        UniqueConstraint, create_engine, event)
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
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='active')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


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
