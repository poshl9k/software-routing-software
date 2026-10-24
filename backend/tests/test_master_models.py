"""Master database schema invariants (ADR-0035 stage 1)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vs_master.models import (Account, Device, DeviceOp, Node, Subscription, Tariff,
                              make_engine)
from vs_router.secrets import EncryptedSecret


@pytest.fixture()
def engine():
    engine = make_engine('sqlite://')
    from vs_master.models import Base
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def node(engine):
    with Session(engine) as db:
        node = Node(name='rg2', bridge_url='https://rg2.example/internal',
                    bridge_token=EncryptedSecret(ciphertext='gAAAA-node-token'),
                    capacity=20, enabled=True)
        db.add(node)
        db.commit()
        return db.scalar(select(Node))


def test_identity_is_telegram_id_not_name(engine, node):
    """Surrogate PK + unique tg id; display names may repeat (D4)."""
    with Session(engine) as db:
        db.add_all([Account(display_name='Иван', telegram_chat_id='100', password_hash='x'),
                    Account(display_name='Иван', telegram_chat_id='200', password_hash='x')])
        db.commit()
        assert db.scalars(select(Account.id).order_by(Account.id)).first() == 1
        with pytest.raises(IntegrityError):
            db.add(Account(display_name='Дубль', telegram_chat_id='100', password_hash='x'))
            db.commit()
        db.rollback()


def test_subscription_belongs_to_account(engine, node):
    with Session(engine) as db:
        account = Account(display_name='Иван', telegram_chat_id='100', password_hash='x')
        tariff = Tariff(name='base', device_limit=3, term_days=30)
        db.add_all([account, tariff])
        db.flush()
        db.add(Subscription(account_id=account.id, tariff_id=tariff.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
        db.commit()


def test_device_carries_node_and_op_targets_node(engine, node):
    """Device.node_id decides where the worker executes the op (D6)."""
    with Session(engine) as db:
        account = Account(display_name='Иван', telegram_chat_id='100', password_hash='x')
        db.add(account)
        db.flush()
        device = Device(account_id=account.id, node_id=node.id, label='Телефон',
                        private_key=EncryptedSecret(ciphertext='gAAAA-priv'))
        db.add(device)
        db.flush()
        db.add(DeviceOp(account_id=account.id, node_id=node.id, op='create', device_id=device.id))
        db.commit()
        assert device.private_key.ciphertext.startswith('gAAAA')
        # Node deletion must not orphan devices silently: FK enforcement is on.
        with pytest.raises(IntegrityError):
            db.delete(node)
            db.commit()
        db.rollback()


def test_node_state_and_telemetry_defaults(engine, node):
    assert node.state == 'down' and node.active_peers == 0 and node.last_seen is None
