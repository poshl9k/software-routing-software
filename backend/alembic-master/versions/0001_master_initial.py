"""Initial master-owned subscriber database (ADR-0035)."""
from alembic import op
import sqlalchemy as sa

revision = "0001_master"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "master_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("bridge_url", sa.String(255), nullable=False),
        sa.Column("bridge_token", sa.JSON(), nullable=False),
        sa.Column("capacity", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(8), nullable=False),
        sa.Column("active_peers", sa.Integer(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("state IN ('ok', 'stale', 'down')", name="ck_master_node_state"),
        sa.UniqueConstraint("name", name="uq_master_node_name"),
    )
    op.create_table(
        "master_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("display_name", sa.String(64), nullable=False),
        sa.Column("telegram_chat_id", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_master_account_status"),
        sa.UniqueConstraint("telegram_chat_id", name="uq_master_account_tg"),
    )
    op.create_table(
        "master_tariffs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("device_limit", sa.Integer(), nullable=False),
        sa.Column("term_days", sa.Integer(), nullable=False),
        sa.Column("price_amount", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("device_limit >= 1", name="ck_master_tariff_device_limit"),
        sa.CheckConstraint("term_days >= 1", name="ck_master_tariff_term_days"),
    )
    op.create_table(
        "master_audit",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("detail", sa.String(128), nullable=True),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "master_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.String(256), nullable=False),
    )
    op.create_table(
        "master_subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("master_accounts.id"), nullable=False),
        sa.Column("tariff_id", sa.Integer(), sa.ForeignKey("master_tariffs.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('active', 'expired')", name="ck_master_subscription_status"),
    )
    op.create_table(
        "master_devices",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("master_accounts.id"), nullable=False),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("master_nodes.id"), nullable=False),
        sa.Column("node_subscriber", sa.String(64), nullable=False),
        sa.Column("name", sa.String(64), nullable=True),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("public_key", sa.String(128), nullable=True),
        sa.Column("private_key", sa.JSON(), nullable=True),
        sa.Column("preshared_key", sa.JSON(), nullable=True),
        sa.Column("allowed_ips", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("tunnel_name", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("account_id", "name", name="uq_master_device_owner_name"),
        sa.CheckConstraint("status IN ('active', 'inactive', 'removed')", name="ck_master_device_status"),
    )
    op.create_table(
        "master_device_ops",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_id", sa.Integer(), sa.ForeignKey("master_accounts.id"), nullable=False),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("master_nodes.id"), nullable=False),
        sa.Column("op", sa.String(12), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("master_devices.id"), nullable=True),
        sa.Column("label", sa.String(128), nullable=True),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("detail", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("applied_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("op IN ('create', 'delete', 'activate', 'deactivate', 'expire')", name="ck_master_op_kind"),
        sa.CheckConstraint("status IN ('pending', 'applied', 'failed')", name="ck_master_op_status"),
    )


def downgrade():
    op.drop_table("master_device_ops")
    op.drop_table("master_devices")
    op.drop_table("master_subscriptions")
    op.drop_table("master_settings")
    op.drop_table("master_audit")
    op.drop_table("master_tariffs")
    op.drop_table("master_accounts")
    op.drop_table("master_nodes")
