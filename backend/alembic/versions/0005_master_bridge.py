"""Node-owned master bridge execution cache; no portal account data."""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('master_bridge_settings',
                    sa.Column('key', sa.String(64), primary_key=True),
                    sa.Column('value', sa.JSON(), nullable=False))
    op.create_table('master_bridge_entitlements',
                    sa.Column('subscriber_name', sa.String(64), primary_key=True),
                    sa.Column('version', sa.BigInteger(), nullable=False),
                    sa.Column('status', sa.String(8), nullable=False),
                    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))
    op.create_table('master_bridge_devices',
                    sa.Column('last_operation', sa.BigInteger(), nullable=False, server_default='0'),
                    sa.Column('last_action', sa.String(12), nullable=False, server_default=''),
                    sa.Column('id', sa.Integer(), primary_key=True),
                    sa.Column('subscriber_name', sa.String(64), nullable=False),
                    sa.Column('name', sa.String(64), unique=True, nullable=False),
                    sa.Column('label', sa.String(128), nullable=False),
                    sa.Column('tunnel_name', sa.String(64), nullable=False),
                    sa.Column('public_key', sa.String(128), nullable=False),
                    sa.Column('private_key', sa.JSON()),
                    sa.Column('preshared_key', sa.JSON()),
                    sa.Column('allowed_ips', sa.JSON(), nullable=False),
                    sa.Column('status', sa.String(8), nullable=False),
                    sa.CheckConstraint("status IN ('active', 'inactive', 'removed')",
                                       name='ck_master_bridge_device_status'))


def downgrade():
    op.drop_table('master_bridge_devices')
    op.drop_table('master_bridge_entitlements')
    op.drop_table('master_bridge_settings')
