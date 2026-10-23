"""Initial portal schema; deliberately independent of the panel migration chain."""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('portal_accounts',
        sa.Column('subscriber_name', sa.String(64), primary_key=True),
        sa.Column('password_hash', sa.String(255), nullable=False),
        sa.Column('email', sa.String(320)),
        sa.Column('status', sa.String(8), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('active', 'disabled')", name='ck_portal_account_status'))
    op.create_table('portal_invites',
        sa.Column('token', sa.String(128), primary_key=True),
        sa.Column('subscriber_name', sa.String(64), nullable=False),
        sa.Column('password_hash', sa.String(255)),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime(), nullable=False))
    op.create_table('portal_tariffs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(128), nullable=False, unique=True),
        sa.Column('device_limit', sa.Integer(), nullable=False),
        sa.Column('term_days', sa.Integer(), nullable=False),
        sa.Column('price_amount', sa.String(64)),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint('device_limit >= 1', name='ck_portal_tariff_device_limit'),
        sa.CheckConstraint('term_days >= 1', name='ck_portal_tariff_term_days'))
    op.create_table('portal_subscriptions',
        sa.Column('subscriber_name', sa.String(64), primary_key=True),
        sa.Column('tariff_id', sa.Integer(), sa.ForeignKey('portal_tariffs.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(8), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('active', 'expired')", name='ck_portal_subscription_status'))
    op.create_table('portal_devices',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subscriber_name', sa.String(64), nullable=False),
        sa.Column('name', sa.String(64)),
        sa.Column('label', sa.String(128), nullable=False),
        sa.Column('public_key', sa.String(128)),
        sa.Column('private_key', sa.JSON()),
        sa.Column('preshared_key', sa.JSON()),
        sa.Column('allowed_ips', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(8), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('subscriber_name', 'name', name='uq_portal_device_owner_name'),
        sa.CheckConstraint("status IN ('active', 'inactive', 'removed')", name='ck_portal_device_status'))
    op.create_table('portal_device_ops',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subscriber_name', sa.String(64), nullable=False),
        sa.Column('op', sa.String(12), nullable=False),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('portal_devices.id')),
        sa.Column('label', sa.String(128)),
        sa.Column('status', sa.String(8), nullable=False),
        sa.Column('detail', sa.String(128)),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('applied_at', sa.DateTime()),
        sa.CheckConstraint("op IN ('create', 'delete', 'activate', 'deactivate', 'expire')", name='ck_portal_op_kind'),
        sa.CheckConstraint("status IN ('pending', 'applied', 'failed')", name='ck_portal_op_status'))
    op.create_table('portal_audit',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('actor', sa.String(64), nullable=False),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('detail', sa.String(128)),
        sa.Column('at', sa.DateTime(), nullable=False))


def downgrade():
    for name in ('portal_audit', 'portal_device_ops', 'portal_devices',
                 'portal_subscriptions', 'portal_tariffs', 'portal_invites', 'portal_accounts'):
        op.drop_table(name)
