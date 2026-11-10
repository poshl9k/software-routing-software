"""Node roles (entry/egress) and a per-device egress preference.

SQLite cannot add a CHECK constraint in place, so the allowed role values are
enforced by the administrator API and its tests rather than by the schema.
"""
from alembic import op
import sqlalchemy as sa

revision = '0009_master'
down_revision = '0008_master'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('master_nodes') as batch:
        batch.add_column(sa.Column('role', sa.String(length=6), nullable=False,
                                   server_default='both'))
        batch.add_column(sa.Column('public_entry', sa.String(length=255), nullable=True))
    with op.batch_alter_table('master_devices') as batch:
        batch.add_column(sa.Column('egress_node_id', sa.Integer(), nullable=True))
        batch.create_foreign_key('fk_master_device_egress', 'master_nodes',
                                 ['egress_node_id'], ['id'])


def downgrade():
    with op.batch_alter_table('master_devices') as batch:
        batch.drop_constraint('fk_master_device_egress', type_='foreignkey')
        batch.drop_column('egress_node_id')
    with op.batch_alter_table('master_nodes') as batch:
        batch.drop_column('public_entry')
        batch.drop_column('role')
