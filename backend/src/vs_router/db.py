"""One authoritative JSON document per version, validated on every ORM write/read."""
from datetime import datetime, timezone
from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, String, text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.types import JSON, TypeDecorator
from .schema import Configuration, ConfigurationVersion, EncryptedSecret


class BridgeSecretJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return EncryptedSecret.model_validate(value).model_dump(mode='json') if value is not None else None

    def process_result_value(self, value, dialect):
        return EncryptedSecret.model_validate(value) if value is not None else None


class BridgeUTCDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return value.replace(tzinfo=None) if dialect.name == 'sqlite' else value

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value





class ConfigurationJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return Configuration.model_validate(value).model_dump(mode="json")

    def process_result_value(self, value, dialect):
        return Configuration.model_validate(value)


class Base(DeclarativeBase):
    pass


class ConfigurationRow(Base):
    __tablename__ = "configuration_versions"
    __table_args__ = (
        CheckConstraint("status IN ('draft', 'confirmed')", name="ck_version_status"),
        Index("uq_single_draft", "status", unique=True, sqlite_where=text("status = 'draft'")),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(String(9), nullable=False, default="draft")
    profile: Mapped[str] = mapped_column(String(6), nullable=False, default="router", server_default="router")
    configuration: Mapped[Configuration] = mapped_column(ConfigurationJSON(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def snapshot(self) -> ConfigurationVersion:
        return ConfigurationVersion(
            id=self.id,
            status=self.status,
            profile=self.profile,
            configuration=self.configuration,
            created_at=self.created_at,
        )


def save_version(session: Session, version: ConfigurationVersion) -> ConfigurationRow:
    """Persist a new snapshot; tunnel identities retain their creation role."""
    previous = session.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if previous:
        roles = {t.name: t.role for t in previous.configuration.tunnels}
        if any(t.name in roles and roles[t.name] != t.role for t in version.configuration.tunnels):
            raise ValueError("tunnel.role_immutable")
    row = ConfigurationRow(id=version.id, status=version.status, profile=version.profile,
                           configuration=version.configuration)
    session.add(row)
    session.flush()
    return row


class MasterBridgeSetting(Base):
    """Node-owned encrypted bearer generations, independent of portal SQLite."""
    __tablename__ = 'master_bridge_settings'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, nullable=False)


class MasterBridgeEntitlement(Base):
    """Execution grant cache, accepted only from the authenticated master."""
    __tablename__ = 'master_bridge_entitlements'
    subscriber_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(BridgeUTCDateTime(), nullable=False)


class MasterBridgeDevice(Base):
    """Execution material only, not a second subscriber/account store."""
    __tablename__ = 'master_bridge_devices'
    last_operation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default='0')
    last_action: Mapped[str] = mapped_column(String(12), nullable=False, default='', server_default='')
    __table_args__ = (CheckConstraint("status IN ('active', 'inactive', 'removed')",
                                     name='ck_master_bridge_device_status'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    subscriber_name: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    tunnel_name: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key: Mapped[str] = mapped_column(String(128), nullable=False)
    private_key: Mapped[EncryptedSecret | None] = mapped_column(BridgeSecretJSON())
    preshared_key: Mapped[EncryptedSecret | None] = mapped_column(BridgeSecretJSON())
    allowed_ips: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(8), nullable=False)


class UserRow(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'operator')", name="ck_user_role"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(8), nullable=False, default="admin")
    totp_secret: Mapped[str | None] = mapped_column(String(), nullable=True)
