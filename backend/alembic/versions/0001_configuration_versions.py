"""Versioned JSON desired state and single persisted draft."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "configuration_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", sa.String(9), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('draft', 'confirmed')", name="ck_version_status"),
    )
    op.create_index("uq_single_draft", "configuration_versions", ["status"], unique=True,
                    sqlite_where=sa.text("status = 'draft'"))


def downgrade():
    op.drop_index("uq_single_draft", table_name="configuration_versions")
    op.drop_table("configuration_versions")
