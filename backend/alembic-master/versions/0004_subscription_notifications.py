"""Verified Telegram links and durable master subscription notification outbox."""
from alembic import op
import sqlalchemy as sa

revision = '0004_master'
down_revision = '0003_master'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('master_accounts', sa.Column('telegram_linked_at', sa.DateTime(), nullable=True))
    op.add_column('master_accounts', sa.Column('telegram_linked_chat_id', sa.String(64), nullable=True))
    op.add_column('master_subscriptions', sa.Column(
        'notification_revision', sa.Integer(), server_default='0', nullable=False))
    op.create_table(
        'master_subscription_notifications',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subscription_id', sa.Integer(), sa.ForeignKey('master_subscriptions.id'), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(8), nullable=False),
        sa.Column('chat_id', sa.String(64), nullable=False),
        sa.Column('linked_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(12), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(), nullable=False),
        sa.Column('claim_token', sa.String(64)),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('delivered_at', sa.DateTime()),
        sa.Column('message_id', sa.Integer()),
        sa.CheckConstraint("kind IN ('active', 'expired')", name='ck_master_notification_kind'),
        sa.CheckConstraint("status IN ('pending', 'delivered', 'suppressed')", name='ck_master_notification_status'),
        sa.CheckConstraint('revision >= 0 AND attempts >= 0', name='ck_master_notification_counters'),
        sa.UniqueConstraint('subscription_id', 'revision', 'kind', name='uq_master_notification_event'),
    )


def downgrade():
    bind = op.get_bind()
    # Keep the check and DDL atomic against SQLite writers in a maintenance window.
    if bind.dialect.name == 'sqlite' and not bind.connection.driver_connection.in_transaction:
        bind.exec_driver_sql('BEGIN IMMEDIATE')
    if (bind.scalar(sa.text('SELECT COUNT(*) FROM master_subscription_notifications'))
            or bind.scalar(sa.text('SELECT COUNT(*) FROM master_accounts WHERE '
                                   'telegram_linked_at IS NOT NULL OR telegram_linked_chat_id IS NOT NULL'))
            or bind.scalar(sa.text('SELECT COUNT(*) FROM master_subscriptions WHERE notification_revision != 0'))):
        raise RuntimeError('Notification/link state exists; restore a reviewed backup instead of downgrading')
    op.drop_table('master_subscription_notifications')
    op.drop_column('master_subscriptions', 'notification_revision')
    op.drop_column('master_accounts', 'telegram_linked_at')
    op.drop_column('master_accounts', 'telegram_linked_chat_id')
