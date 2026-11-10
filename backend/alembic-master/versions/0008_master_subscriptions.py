"""Revocable per-device subscription links (hash-only storage)."""
from alembic import op
import sqlalchemy as sa

revision = '0008_master'
down_revision = '0007_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_device_subscriptions',
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['master_devices.id']),
        sa.PrimaryKeyConstraint('device_id'),
        sa.UniqueConstraint('token_hash', name='uq_master_subscription_token'),
    )


def downgrade():
    op.drop_table('master_device_subscriptions')
