"""Upgrade real prior-state SQLite; immutable test ledger must not be dropped."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_master.models import (Account, Base, PaymentReceipt, StarsOrder, StarsPaymentEvent,
                              Subscription, Tariff, make_engine)


def test_stars_migration_prior_data_metadata_constraints_and_guard(tmp_path, monkeypatch):
    url = 'sqlite:///' + (tmp_path / 'upgrade.db').as_posix()
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', url)
    config = Config(str(Path(__file__).parents[1] / 'alembic-master' / 'alembic.ini'))
    command.upgrade(config, '0004_master')
    engine = make_engine(url)
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    try:
        with Session(engine) as db:
            db.add(PaymentReceipt(telegram_charge_id='old-unmatched', payer_chat_id='100',
                                  currency='XTR', amount=1, payload_hash='a' * 64))
            db.commit()
        command.upgrade(config, 'head')
        assert 'master_stars_orders' in inspect(engine).get_table_names()
        with engine.connect() as db:
            assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0005_master'
            assert compare_metadata(MigrationContext.configure(db), Base.metadata) == []
            assert db.scalar(text('PRAGMA journal_mode')) == 'wal'
            assert db.scalar(text('SELECT COUNT(*) FROM master_payment_receipts')) == 1
        command.downgrade(config, '0004_master')
        command.upgrade(config, 'head')
        with Session(engine) as db:
            db.add_all([Account(id=1, display_name='Synthetic', telegram_chat_id='100', password_hash='x'),
                        Tariff(id=3, name='Super', device_limit=50, term_days=30)])
            db.flush()
            db.add(Subscription(id=1, account_id=1, tariff_id=3, expires_at=now + timedelta(days=30)))
            db.commit()
        values = dict(test_slot='super-30d-1xtr-v1', bot_id='900', account_id=1,
                      subscription_id=1, tariff_id=3, tariff_name='Super', device_limit=50,
                      payer_chat_id='100', linked_at=now, currency='XTR', amount=1, term_days=30,
                      prior_expires_at=now + timedelta(days=30), payload_hash='b' * 64,
                      expires_at=now + timedelta(minutes=10), created_at=now)
        for changes in ({'amount': 2}, {'currency': 'USD'}, {'term_days': 1}, {'tariff_id': 1},
                        {'device_limit': 3}, {'account_id': 999}, {'subscription_id': 999},
                        {'state': 'invalid'}, {'fulfillment_status': 'invalid'}, {'test_slot': 'another'}):
            with Session(engine) as db:
                db.add(StarsOrder(**(values | changes)))
                with pytest.raises(IntegrityError):
                    db.commit()
        with Session(engine) as db:
            db.add(StarsOrder(**values))
            db.commit()
        with Session(engine) as db:
            db.add(StarsOrder(**(values | {'payload_hash': 'c' * 64})))
            with pytest.raises(IntegrityError):
                db.commit()
        for changes in ({'status': 'invalid'}, {'amount': 0}, {'telegram_charge_id': 'missing'}, {'order_id': 999}):
            with Session(engine) as db:
                db.add(StarsPaymentEvent(**(dict(fingerprint='f' * 64, telegram_charge_id='old-unmatched',
                    order_id=1, payer_chat_id='100', currency='XTR', amount=1, payload_hash='a' * 64,
                    status='review', received_at=now) | changes)))
                with pytest.raises(IntegrityError):
                    db.commit()
        with pytest.raises(RuntimeError, match='backup'):
            command.downgrade(config, '0004_master')
        with engine.connect() as db:
            assert db.scalar(text('SELECT version_num FROM alembic_version')) == '0005_master'
            assert db.scalar(text('SELECT COUNT(*) FROM master_stars_orders')) == 1
            assert db.scalar(text('PRAGMA foreign_key_check')) is None
    finally:
        engine.dispose()
