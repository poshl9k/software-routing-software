"""One-use Telegram binding proofs for authenticated portal accounts."""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'portal_telegram_links',
        sa.Column('code_hash', sa.String(length=64), primary_key=True),
        sa.Column('subscriber_name', sa.String(length=64),
                  sa.ForeignKey('portal_accounts.subscriber_name'), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
    )

def downgrade() -> None:
    op.drop_table('portal_telegram_links')
