"""Cumulative peer counters for daily traffic deltas and enforcement markers."""
from alembic import op
import sqlalchemy as sa

revision = '0017_master'
down_revision = '0016_master'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('master_traffic_usage') as batch:
        batch.add_column(sa.Column('rx_total', sa.BigInteger(), nullable=False, server_default='0'))
        batch.add_column(sa.Column('tx_total', sa.BigInteger(), nullable=False, server_default='0'))


def downgrade():
    with op.batch_alter_table('master_traffic_usage') as batch:
        batch.drop_column('tx_total')
        batch.drop_column('rx_total')
