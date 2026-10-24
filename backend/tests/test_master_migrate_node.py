"""Node portal-DB → master migration script (ADR-0035 D5)."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from vs_master.migrate_node import migrate_portal_db, placeholder_identity
from vs_master.models import Account, Base as MasterBase, Device, Node, Subscription
from vs_portal.models import Account as PortalAccount
from vs_portal.models import Base as PortalBase
from vs_portal.models import Device as PortalDevice
from vs_portal.models import Subscription as PortalSubscription
from vs_portal.models import Tariff as PortalTariff
from vs_router.secrets import decrypt_secret, encrypt_secret


def _secret(value, key):
    return encrypt_secret(value, key)


@pytest.fixture
def keys(monkeypatch):
    node_key = Fernet.generate_key().decode()
    master_key = Fernet.generate_key().decode()
    monkeypatch.setenv('VS_ROUTER_SECRET_KEY', master_key)
    return node_key.encode(), master_key.encode()


@pytest.fixture
def engines(keys):
    node_key, master_key = keys
    portal = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    master = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    PortalBase.metadata.create_all(portal)
    MasterBase.metadata.create_all(master)
    with Session(portal) as db:
        db.add_all([PortalAccount(subscriber_name='alice', password_hash='h1'),
                    PortalAccount(subscriber_name='bob', password_hash='h2',
                                  telegram_chat_id='200')])
        db.flush()
        tariff = PortalTariff(name='Base', device_limit=3, term_days=30)
        db.add(tariff)
        db.flush()
        now = datetime.now(timezone.utc)
        db.add(PortalSubscription(subscriber_name='alice', tariff_id=tariff.id,
                                  expires_at=now + timedelta(days=10), status='active'))
        db.add(PortalSubscription(subscriber_name='bob', tariff_id=tariff.id,
                                  expires_at=now - timedelta(days=1), status='expired'))
        db.add(PortalDevice(subscriber_name='alice', name='portal_1', label='Телефон',
                            status='active', allowed_ips=['10.66.0.2/32'], tunnel_name='vpn',
                            private_key=_secret('client-private', node_key),
                            preshared_key=_secret('client-psk', node_key)))
        db.commit()
    with Session(master) as db:
        node = Node(name='rg2', bridge_url='https://rg2.example/internal',
                    bridge_token=_secret('tok', master_key), capacity=20)
        db.add(node)
        db.commit()
        node_id = node.id
    return portal, master, node_id, keys


def test_migrates_accounts_tariffs_subscriptions_devices(engines):
    portal, master, node_id, keys = engines
    node_key, master_key = keys
    with Session(master) as db:
        node = db.get(Node, node_id)
    result = migrate_portal_db(portal, master, node, node_key, master_key)
    assert result == {'accounts': 2, 'tariffs': 1, 'subscriptions': 2, 'devices': 1, 'updated': 0}
    with Session(master) as db:
        alice = db.scalar(select(Account).where(Account.telegram_chat_id == placeholder_identity('alice')))
        assert alice is not None and alice.display_name == 'alice'
        bob = db.scalar(select(Account).where(Account.telegram_chat_id == '200'))
        subscription = db.scalar(select(Subscription).where(Subscription.account_id == bob.id))
        assert subscription.status == 'expired'
        device = db.scalar(select(Device).where(Device.account_id == alice.id))
        assert (device.node_id, device.node_subscriber, device.name) == (node_id, 'alice', 'portal_1')
        assert device.allowed_ips == ['10.66.0.2/32']
        # Re-encrypted under the MASTER key, decryptable with it only.
        assert decrypt_secret(device.private_key, master_key) == 'client-private'
        assert decrypt_secret(device.preshared_key, master_key) == 'client-psk'


def test_rerun_is_idempotent(engines):
    portal, master, node_id, keys = engines
    node_key, master_key = keys
    with Session(master) as db:
        node = db.get(Node, node_id)
    migrate_portal_db(portal, master, node, node_key, master_key)
    again = migrate_portal_db(portal, master, node, node_key, master_key)
    assert again['accounts'] == 0 and again['devices'] == 0 and again['updated'] == 2
    with Session(master) as db:
        assert len(list(db.scalars(select(Account)))) == 2
        assert len(list(db.scalars(select(Device)))) == 1
        assert len(list(db.scalars(select(Subscription)))) == 2
