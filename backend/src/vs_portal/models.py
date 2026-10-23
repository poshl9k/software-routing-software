"""Portal-owned SQLite schema. Datetimes are aware UTC at the Python boundary."""
import os
from datetime import datetime, timezone

from sqlalchemy import (JSON, CheckConstraint, DateTime, ForeignKey, Integer, String,
                        UniqueConstraint, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator

from vs_router.schema import EncryptedSecret


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class UTCDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise ValueError('datetime.required')
        # SQLite has no timezone storage; normalize before serializing.
        return as_utc(value).replace(tzinfo=None) if dialect.name == 'sqlite' else as_utc(value)

    def process_result_value(self, value, dialect):
        return as_utc(value) if value is not None else None


class SecretJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return EncryptedSecret.model_validate(value).model_dump(mode='json') if value is not None else None

    def process_result_value(self, value, dialect):
        return EncryptedSecret.model_validate(value) if value is not None else None


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = 'portal_accounts'
    __table_args__ = (CheckConstraint("status IN ('active', 'disabled')", name='ck_portal_account_status'),)
    subscriber_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='active')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Invite(Base):
    __tablename__ = 'portal_invites'
    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    subscriber_name: Mapped[str] = mapped_column(String(64), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Tariff(Base):
    __tablename__ = 'portal_tariffs'
    __table_args__ = (CheckConstraint('device_limit >= 1', name='ck_portal_tariff_device_limit'),
                      CheckConstraint('term_days >= 1', name='ck_portal_tariff_term_days'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    term_days: Mapped[int] = mapped_column(Integer, nullable=False)
    price_amount: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Subscription(Base):
    __tablename__ = 'portal_subscriptions'
    __table_args__ = (CheckConstraint("status IN ('active', 'expired')", name='ck_portal_subscription_status'),)
    subscriber_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    tariff_id: Mapped[int] = mapped_column(ForeignKey('portal_tariffs.id'), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='active')
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Device(Base):
    __tablename__ = 'portal_devices'
    __table_args__ = (UniqueConstraint('subscriber_name', 'name', name='uq_portal_device_owner_name'),
                      CheckConstraint("status IN ('active', 'inactive', 'removed')", name='ck_portal_device_status'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subscriber_name: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str | None] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key: Mapped[str | None] = mapped_column(String(128))
    private_key: Mapped[EncryptedSecret | None] = mapped_column(SecretJSON())
    preshared_key: Mapped[EncryptedSecret | None] = mapped_column(SecretJSON())
    allowed_ips: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='inactive')
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class DeviceOp(Base):
    __tablename__ = 'portal_device_ops'
    __table_args__ = (CheckConstraint("op IN ('create', 'delete', 'activate', 'deactivate', 'expire')", name='ck_portal_op_kind'),
                      CheckConstraint("status IN ('pending', 'applied', 'failed')", name='ck_portal_op_status'))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subscriber_name: Mapped[str] = mapped_column(String(64), nullable=False)
    op: Mapped[str] = mapped_column(String(12), nullable=False)
    device_id: Mapped[int | None] = mapped_column(ForeignKey('portal_devices.id'))
    label: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(8), nullable=False, default='pending')
    detail: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    applied_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Audit(Base):
    __tablename__ = 'portal_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(String(128))
    at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


def make_engine(database_url=None):
    url = database_url or os.environ.get('VS_PORTAL_DATABASE_URL', 'sqlite:///vs-portal.db')
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
