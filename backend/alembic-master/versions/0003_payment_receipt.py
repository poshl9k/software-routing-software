"""Retain unsolicited Telegram payments for manual review, without entitlement."""
from alembic import op
import sqlalchemy as sa

revision = '0003_master'
down_revision = '0002_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_payment_receipts',
        sa.Column('telegram_charge_id', sa.String(255), primary_key=True),
        sa.Column('payer_chat_id', sa.String(64), nullable=False),
        sa.Column('currency', sa.String(3), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=False),
        sa.Column('payload_hash', sa.String(64), nullable=False),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint('amount > 0', name='ck_master_receipt_amount'),
    )


def downgrade():
    op.drop_table('master_payment_receipts')
