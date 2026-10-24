"""Alembic contract for the standalone ADR-0035 master database."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from vs_master.models import (Account, Audit, Device, DeviceOp, Node, Setting,
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

    engine.dispose()
    command.downgrade(config, "base")

    inspected = make_engine(database_url)
    try:
        assert MASTER_TABLES.isdisjoint(inspect(inspected).get_table_names())
    finally:
        inspected.dispose()
