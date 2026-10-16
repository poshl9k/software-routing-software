"""Профиль продукта в снимке; существующие записи остаются router."""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("configuration_versions", sa.Column(
        "profile", sa.String(6), nullable=False, server_default="router"))


def downgrade():
    op.drop_column("configuration_versions", "profile")
