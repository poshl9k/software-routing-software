"""Bind portal accounts to Telegram private chats."""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('portal_accounts', sa.Column('telegram_chat_id', sa.String(length=64), nullable=True))
    op.create_index('uq_portal_accounts_telegram_chat_id', 'portal_accounts', ['telegram_chat_id'], unique=True)


def downgrade() -> None:
    op.drop_index('uq_portal_accounts_telegram_chat_id', table_name='portal_accounts')
    op.drop_column('portal_accounts', 'telegram_chat_id')
