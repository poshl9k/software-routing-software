"""A second invoice needs a new durable order without rewriting the first."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from vs_master.models import (Account, Base, PaymentReceipt, StarsOrder, StarsPaymentEvent,
                              Subscription, Tariff, make_engine)


def _order(now, slot, payload):
    return StarsOrder(test_slot=slot, bot_id='900', account_id=1, subscription_id=1,
                      tariff_id=3, tariff_name='Super', device_limit=50, payer_chat_id='100',
                      linked_at=now, currency='XTR', amount=1, term_days=30,
                      prior_expires_at=now + timedelta(days=30), payload_hash=payload * 64,
                      expires_at=now + timedelta(minutes=10), created_at=now,
                      state='sent', sent_at=now, message_id=10)


def test_retry_migration_preserves_original_order_and_related_event(tmp_path, monkeypatch):
    url = 'sqlite:///' + (tmp_path / 'master.db').as_posix()
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master' / 'alembic.ini'))
    command.upgrade(config, '0005_master')
    engine = make_engine(url)
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    try:
        with Session(engine) as db:
            db.add_all([Account(id=1, display_name='Synthetic', telegram_chat_id='100', password_hash='x'),
                        Tariff(id=3, name='Super', device_limit=50, term_days=30)])
            db.flush()
            db.add(Subscription(id=1, account_id=1, tariff_id=3,
                                expires_at=now + timedelta(days=30)))
            db.add(PaymentReceipt(telegram_charge_id='synthetic-unmatched', payer_chat_id='100',
                                  currency='XTR', amount=1, payload_hash='b' * 64))
            db.flush()
            db.add(_order(now, 'super-30d-1xtr-v1', 'a'))
            db.flush()
            db.add(StarsPaymentEvent(fingerprint='f' * 64, telegram_charge_id='synthetic-unmatched',
                                     order_id=1, payer_chat_id='100', currency='XTR', amount=1,
                                     payload_hash='b' * 64, status='unmatched', received_at=now))
            db.commit()
        command.upgrade(config, 'head')
        with engine.connect() as db:
            assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0006_master'
            assert db.scalar(text('SELECT COUNT(*) FROM master_stars_orders')) == 1
            assert db.scalar(text('SELECT order_id FROM master_stars_payment_events')) == 1
            assert db.scalar(text('PRAGMA foreign_key_check')) is None
            assert compare_metadata(MigrationContext.configure(db), Base.metadata) == []
        constraints = inspect(engine).get_check_constraints('master_stars_orders')
        assert any(c['name'] == 'ck_master_stars_slot' and 'super-30d-1xtr-retry-v1' in c['sqltext']
                   for c in constraints)
    finally:
        engine.dispose()


def test_retry_history_blocks_downgrade_but_old_order_remains(tmp_path, monkeypatch):
    url = 'sqlite:///' + (tmp_path / 'master.db').as_posix()
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master' / 'alembic.ini'))
    command.upgrade(config, 'head')
    engine = make_engine(url)
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    try:
        with Session(engine) as db:
            db.add_all([Account(id=1, display_name='Synthetic', telegram_chat_id='100', password_hash='x'),
                        Tariff(id=3, name='Super', device_limit=50, term_days=30)])
            db.flush()
            db.add(Subscription(id=1, account_id=1, tariff_id=3,
                                expires_at=now + timedelta(days=30)))
            db.flush()
            db.add(_order(now, 'super-30d-1xtr-v1', 'a'))
            db.add(_order(now + timedelta(minutes=11), 'super-30d-1xtr-retry-v1', 'b'))
            db.commit()
        with pytest.raises(RuntimeError, match='backup'):
            command.downgrade(config, '0005_master')
        with engine.connect() as db:
            assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0006_master'
            assert db.scalar(text('SELECT COUNT(*) FROM master_stars_orders')) == 2
            assert db.scalar(text('PRAGMA foreign_key_check')) is None
    finally:
        engine.dispose()
