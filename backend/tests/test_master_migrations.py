"""Alembic contract for the standalone ADR-0035 master database."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vs_master.models import (Account, Audit, Device, DeviceOp, MagicLogin, Node, PaymentReceipt, Setting,
                              Subscription, Tariff, make_engine)
from vs_router.schema import EncryptedSecret


MASTER_TABLES = {
    "master_nodes",
    "master_accounts",
    "master_tariffs",
    "master_subscriptions",
    "master_devices",
    "master_device_ops",
    "master_audit",
    "master_settings",
    "master_magic_logins",
    "master_payment_receipts",
    "master_subscription_notifications",
    "master_stars_orders",
    "master_stars_payment_events",
    "master_stars_fulfillments",
}


def test_master_migration_round_trip(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'master.db'}"
    monkeypatch.setenv("VS_MASTER_DATABASE_URL", database_url)
    config = Config(str(Path(__file__).parents[1] / "alembic-master" / "alembic.ini"))

    command.upgrade(config, "head")

    engine = make_engine(database_url)
    now = datetime.now(timezone.utc)
    bridge_token = EncryptedSecret(ciphertext="gAAAA-master-bridge-token")
    private_key = EncryptedSecret(ciphertext="gAAAA-master-private-key")
    preshared_key = EncryptedSecret(ciphertext="gAAAA-master-preshared-key")
    with Session(engine) as db:
        node = Node(
            name="node-1",
            bridge_url="https://node-1.example/internal",
            bridge_token=bridge_token,
            capacity=25,
            enabled=True,
            state="ok",
            active_peers=1,
            last_seen=now,
        )
        account = Account(
            display_name="Subscriber",
            telegram_chat_id="10001",
            password_hash="password-hash",
        )
        tariff = Tariff(
            name="basic",
            device_limit=2,
            term_days=30,
            price_amount="9.99",
        )
        audit = Audit(actor="admin", action="master.created", detail="initial row")
        setting = Setting(key="feedback_contact", value="support")
        db.add_all([node, account, tariff, audit, setting])
        db.flush()

        subscription = Subscription(
            account_id=account.id,
            tariff_id=tariff.id,
            expires_at=now + timedelta(days=30),
        )
        device = Device(
            account_id=account.id,
            node_id=node.id,
            node_subscriber="subscriber-10001",
            name="phone",
            label="Phone",
            public_key="public-key",
            private_key=private_key,
            preshared_key=preshared_key,
            allowed_ips=["10.0.0.2/32"],
            status="active",
            tunnel_name="awg0",
        )
        db.add_all([subscription, device])
        db.flush()
        operation = DeviceOp(
            account_id=account.id,
            node_id=node.id,
            op="create",
            device_id=device.id,
            label="Phone",
            status="applied",
            detail="created",
            applied_at=now,
        )
        db.add(operation)
        db.commit()

        assert db.execute(select(Node)).scalar_one().bridge_token == bridge_token
        assert db.execute(select(Account)).scalar_one().telegram_chat_id == "10001"
        assert db.execute(select(Tariff)).scalar_one().name == "basic"
        assert db.execute(select(Subscription)).scalar_one().account_id == account.id
        stored_device = db.execute(select(Device)).scalar_one()
        assert stored_device.private_key == private_key
        assert stored_device.preshared_key == preshared_key
        assert stored_device.allowed_ips == ["10.0.0.2/32"]
        assert db.execute(select(DeviceOp)).scalar_one().device_id == device.id
        assert db.execute(select(Audit)).scalar_one().action == "master.created"
        assert db.execute(select(Setting)).scalar_one().value == "support"
        db.add(MagicLogin(token_hash='a' * 64, account_id=account.id,
                          expires_at=now + timedelta(minutes=10)))
        db.commit()
        assert db.execute(select(MagicLogin)).scalar_one().account_id == account.id
        db.add(PaymentReceipt(telegram_charge_id='synthetic-id', payer_chat_id='10001',
                              currency='XTR', amount=1, payload_hash='b' * 64))
        db.commit()
        assert db.execute(select(PaymentReceipt)).scalar_one().amount == 1

    engine.dispose()
    command.downgrade(config, "base")

    inspected = make_engine(database_url)
    try:
        assert MASTER_TABLES.isdisjoint(inspect(inspected).get_table_names())
    finally:
        inspected.dispose()


def test_master_keeps_unexpected_payment_receipts_for_manual_review(tmp_path, monkeypatch):
    database_url = f"sqlite:///{tmp_path / 'master.db'}"
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', database_url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master' / 'alembic.ini'))
    command.upgrade(config, 'head')
    engine = make_engine(database_url)
    try:
        assert 'master_payment_receipts' in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_subscription_notifications_upgrade_preserves_prior_rows_and_guards_downgrade(tmp_path, monkeypatch):
    import pytest
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    from vs_master.models import Base, SubscriptionNotification

    url = f"sqlite:///{tmp_path / 'notifications-upgrade.db'}"
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master' / 'alembic.ini'))
    command.upgrade(config, '0003_master')
    engine = make_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO master_accounts (id, display_name, telegram_chat_id, "
                                    "password_hash, status, created_at) VALUES "
                                    "(1, 'Prior', '12345', 'x', 'active', '2026-11-08')"))
            connection.execute(text("INSERT INTO master_tariffs (id, name, device_limit, term_days, created_at) "
                                    "VALUES (1, 'Prior', 2, 30, '2026-11-08')"))
            connection.execute(text("INSERT INTO master_subscriptions (id, account_id, tariff_id, "
                                    "expires_at, status, updated_at) VALUES "
                                    "(1, 1, 1, '2026-12-08', 'active', '2026-11-08')"))
        command.upgrade(config, 'head')
        assert 'master_subscription_notifications' in inspect(engine).get_table_names(), \
            'Upgrade must add the durable outbox'
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0006_master'
            assert connection.execute(text('SELECT display_name, telegram_linked_at FROM master_accounts')).one() == ('Prior', None)
            assert connection.execute(text('SELECT status, notification_revision FROM master_subscriptions')).one() == ('active', 0)
            assert connection.scalar(text('PRAGMA journal_mode')) == 'wal'
            assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
        # Empty-outbox rollback is safe and keeps the original subscriber data.
        command.downgrade(config, '0003_master')
        command.upgrade(config, 'head')
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        with Session(engine) as db:
            event = SubscriptionNotification(subscription_id=1, revision=0, kind='expired',
                                             chat_id='12345', linked_at=now, expires_at=now,
                                             next_attempt_at=now, created_at=now)
            db.add(event)
            db.commit()
        values = dict(subscription_id=1, revision=0, kind='expired', chat_id='12345', linked_at=now,
                      expires_at=now, next_attempt_at=now, created_at=now)
        for override in ({}, {'revision': 1, 'kind': 'invalid'}, {'revision': 1, 'status': 'invalid'},
                         {'revision': 1, 'attempts': -1}, {'subscription_id': 999}):
            with Session(engine) as db:
                db.add(SubscriptionNotification(**(values | override)))
                with pytest.raises(IntegrityError):
                    db.commit()
        with pytest.raises(RuntimeError, match='backup'):
            command.downgrade(config, '0003_master')
        with engine.connect() as connection:
            assert connection.scalar(text('SELECT version_num FROM alembic_version')) == '0004_master'
            assert connection.scalar(text('SELECT COUNT(*) FROM master_subscription_notifications')) == 1
    finally:
        engine.dispose()
