"""Seed Telegram bot token setting for portal administration."""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Empty until an administrator configures the Telegram Bot API token.
    op.execute(sa.text(
        "INSERT INTO portal_settings (key, value) VALUES ('bot_token', '')"
    ))


def downgrade() -> None:
    op.execute(sa.text(
        "DELETE FROM portal_settings WHERE key = 'bot_token'"
    ))
