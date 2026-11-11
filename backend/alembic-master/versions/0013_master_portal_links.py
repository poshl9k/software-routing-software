"""Stable cabinet links (one per account) replacing the one-shot magic proof.

The bot used to mint a 10-minute single-use proof on every "Личный кабинет"
tap. A permanent link is now stored per account: hashed for lookup, encrypted
so the bot can re-send it. Rotation is explicit.
"""
from alembic import op
import sqlalchemy as sa

revision = '0013_master'
down_revision = '0012_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_portal_links',
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), primary_key=True),
        sa.Column('token_hash', sa.String(length=64), nullable=False, unique=True),
        sa.Column('token_secret', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('master_portal_links')
