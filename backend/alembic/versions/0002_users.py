"""Local users; TOTP is reserved for a later phase (encrypted at rest)."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(8), nullable=False),
        sa.Column("totp_secret", sa.String(), nullable=True),
        sa.UniqueConstraint("username"),
        sa.CheckConstraint("role IN ('admin', 'operator')", name="ck_user_role"),
    )


def downgrade():
    op.drop_table("users")
