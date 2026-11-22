"""Per-device registration cap instead of per-IP (ADR-0036)."""
from alembic import op
import sqlalchemy as sa

revision = '0018_master'
down_revision = '0017_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_registration_devices',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('device_hash', sa.String(64), nullable=False),
        sa.Column('day', sa.Date(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('device_hash', 'day', name='uq_master_reg_device_day'),
    )
    op.create_index('ix_master_reg_device_day', 'master_registration_devices', ['day'])


def downgrade():
    op.drop_index('ix_master_reg_device_day', table_name='master_registration_devices')
    op.drop_table('master_registration_devices')
