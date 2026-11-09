"""One-off approved Stars test orders, immutable observations and node tickets."""
from alembic import op
import sqlalchemy as sa

revision = '0005_master'
down_revision = '0004_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_stars_orders',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('test_slot', sa.String(64), nullable=False),
        sa.Column('bot_id', sa.String(64), nullable=False),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=False),
        sa.Column('subscription_id', sa.Integer(), sa.ForeignKey('master_subscriptions.id'), nullable=False),
        sa.Column('tariff_id', sa.Integer(), sa.ForeignKey('master_tariffs.id'), nullable=False),
        sa.Column('tariff_name', sa.String(128), nullable=False),
        sa.Column('device_limit', sa.Integer(), nullable=False),
        sa.Column('payer_chat_id', sa.String(64), nullable=False),
        sa.Column('linked_at', sa.DateTime(), nullable=False),
        sa.Column('currency', sa.String(3), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('term_days', sa.Integer(), nullable=False),
        sa.Column('prior_expires_at', sa.DateTime(), nullable=False),
        sa.Column('payload_hash', sa.String(64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('state', sa.String(8), nullable=False),
        sa.Column('sent_at', sa.DateTime()),
        sa.Column('message_id', sa.Integer()),
        sa.Column('checkout_id', sa.String(255)),
        sa.Column('approved_at', sa.DateTime()),
        sa.Column('paid_charge_id', sa.String(255), sa.ForeignKey('master_payment_receipts.telegram_charge_id')),
        sa.Column('paid_at', sa.DateTime()),
        sa.Column('granted_expires_at', sa.DateTime()),
        sa.Column('fulfillment_status', sa.String(8), nullable=False),
        sa.UniqueConstraint('test_slot', name='uq_master_stars_slot'),
        sa.UniqueConstraint('payload_hash', name='uq_master_stars_payload'),
        sa.UniqueConstraint('paid_charge_id', name='uq_master_stars_charge'),
        sa.CheckConstraint("test_slot = 'super-30d-1xtr-v1'", name='ck_master_stars_slot'),
        sa.CheckConstraint("currency = 'XTR' AND amount = 1 AND term_days = 30 AND device_limit = 50 AND tariff_id = 3",
                           name='ck_master_stars_product'),
        sa.CheckConstraint("state IN ('sending', 'sent', 'paid', 'review')", name='ck_master_stars_state'),
        sa.CheckConstraint("fulfillment_status IN ('pending', 'applied', 'review')", name='ck_master_stars_fulfillment'),
    )
    op.create_table(
        'master_stars_payment_events',
        sa.Column('fingerprint', sa.String(64), primary_key=True),
        sa.Column('telegram_charge_id', sa.String(255), sa.ForeignKey('master_payment_receipts.telegram_charge_id'), nullable=False),
        sa.Column('order_id', sa.Integer(), sa.ForeignKey('master_stars_orders.id')),
        sa.Column('payer_chat_id', sa.String(64), nullable=False),
        sa.Column('currency', sa.String(3), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('payload_hash', sa.String(64), nullable=False),
        sa.Column('status', sa.String(9), nullable=False),
        sa.Column('reason', sa.String(64)),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('granted', 'review', 'unmatched')", name='ck_master_stars_event_status'),
        sa.CheckConstraint('amount > 0', name='ck_master_stars_event_amount'),
    )
    op.create_table(
        'master_stars_fulfillments',
        sa.Column('order_id', sa.Integer(), sa.ForeignKey('master_stars_orders.id'), primary_key=True),
        sa.Column('node_id', sa.Integer(), sa.ForeignKey('master_nodes.id'), primary_key=True),
        sa.Column('op_id', sa.Integer(), sa.ForeignKey('master_device_ops.id'), nullable=False),
        sa.UniqueConstraint('op_id', name='uq_master_stars_fulfillment_op'),
    )


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite' and not bind.connection.driver_connection.in_transaction:
        bind.exec_driver_sql('BEGIN IMMEDIATE')
    if any(bind.scalar(sa.text(f'SELECT COUNT(*) FROM {table}')) for table in (
            'master_stars_orders', 'master_stars_payment_events', 'master_stars_fulfillments')):
        raise RuntimeError('Stars order/payment history exists; restore a reviewed backup instead of downgrading')
    op.drop_table('master_stars_fulfillments')
    op.drop_table('master_stars_payment_events')
    op.drop_table('master_stars_orders')
