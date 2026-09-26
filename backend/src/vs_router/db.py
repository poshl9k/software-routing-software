"""One authoritative JSON document per version, validated on every ORM write/read."""
from datetime import datetime, timezone
from sqlalchemy import CheckConstraint, DateTime, Index, String, text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.types import JSON, TypeDecorator
from .schema import Configuration, ConfigurationVersion


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
    configuration: Mapped[Configuration] = mapped_column(ConfigurationJSON(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def snapshot(self) -> ConfigurationVersion:
        return ConfigurationVersion(id=self.id, status=self.status, configuration=self.configuration)


def save_version(session: Session, version: ConfigurationVersion) -> ConfigurationRow:
    """Persist a new snapshot; tunnel identities retain their creation role."""
    previous = session.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if previous:
        roles = {t.name: t.role for t in previous.configuration.tunnels}
        if any(t.name in roles and roles[t.name] != t.role for t in version.configuration.tunnels):
            raise ValueError("tunnel.role_immutable")
    row = ConfigurationRow(id=version.id, status=version.status, configuration=version.configuration)
    session.add(row)
    session.flush()
    return row


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
