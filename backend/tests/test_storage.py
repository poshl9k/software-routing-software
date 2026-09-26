from pathlib import Path
import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet, InvalidToken
import asyncio
from httpx import AsyncClient, ASGITransport
from pydantic import ValidationError
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session
from vs_router.app import create_app
from vs_router.db import ConfigurationRow, save_version
from vs_router.schema import ConfigurationVersion, EncryptedSecret
from vs_router.secrets import encrypt_secret, decrypt_secret
from scenarios import scenario


@pytest.fixture
def database(tmp_path):
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'router.db'}")
    command.upgrade(config, "head")
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    yield engine, config
    engine.dispose()


def test_migration_roundtrip_and_single_draft(database):
    engine, config = database
    with Session(engine) as session:
        save_version(session, scenario("edge"))
        session.commit()
    with Session(engine) as session:
        row = session.get(ConfigurationRow, 1)
        assert row.snapshot() == scenario("edge")
        session.add(ConfigurationRow(id=2, status="draft", configuration=row.configuration))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(ConfigurationRow(id=2, status="confirmed", configuration=row.configuration))
        session.commit()
    command.check(config)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM configuration_versions")).scalar_one() == 0


def test_db_rejects_invalid_status(database):
    engine, _ = database
    with Session(engine) as session:
        session.add(ConfigurationRow(status="applied", configuration={}))
        with pytest.raises(IntegrityError):
            session.commit()


def test_db_validates_json(database):
    engine, _ = database
    with Session(engine) as session:
        session.add(ConfigurationRow(status="draft", configuration={"interfaces": [{"name": "bad name"}]}))
        with pytest.raises(StatementError):
            session.commit()


def test_encrypted_secret_storage(database):
    key = Fernet.generate_key()
    secret = encrypt_secret("private-key-material", key)
    assert decrypt_secret(secret, key) == "private-key-material"
    with pytest.raises(InvalidToken):
        decrypt_secret(secret, Fernet.generate_key())
    with pytest.raises(ValidationError):
        EncryptedSecret(ciphertext="plaintext")
    engine, _ = database
    version = ConfigurationVersion(configuration={
        "interfaces": [{"name": "wg0", "zone": "lan"}],
        "tunnels": [{"name": "vpn", "interface": "wg0", "role": "server", "protocol": "wg",
                     "listen_port": 51820, "private_key": secret.model_dump()}],
    })
    with Session(engine) as session:
        save_version(session, version)
        session.commit()
    with engine.connect() as conn:
        raw = conn.execute(text("SELECT configuration FROM configuration_versions")).scalar_one()
        assert "private-key-material" not in raw
        assert '"encrypted": true' in raw


def test_health():
    async def check():
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test") as client:
            assert (await client.get("/health")).json() == {"status": "ok"}
    asyncio.run(check())


def test_tunnel_role_cannot_change_between_versions(database):
    engine, _ = database
    secret = encrypt_secret("key", Fernet.generate_key()).model_dump()
    config = {"interfaces": [{"name": "wg0"}], "tunnels": [
        {"name": "vpn", "interface": "wg0", "role": "server", "protocol": "wg",
         "listen_port": 51820, "private_key": secret}]}
    with Session(engine) as session:
        save_version(session, ConfigurationVersion(id=1, status="confirmed", configuration=config))
        session.commit()
        config["tunnels"][0].update(role="client", endpoint="vpn.example:51820", server_public_key="public-key")
        with pytest.raises(ValueError, match="role_immutable"):
            save_version(session, ConfigurationVersion(id=2, configuration=config))
