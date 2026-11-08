"""Single-use Telegram magic sign-in proofs for master subscribers."""
from alembic import op
import sqlalchemy as sa

revision = '0002_master'
down_revision = '0001_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_magic_logins',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('consumed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_master_magic_account', 'master_magic_logins', ['account_id'])


def downgrade():
    op.drop_index('ix_master_magic_account', table_name='master_magic_logins')
    op.drop_table('master_magic_logins')
