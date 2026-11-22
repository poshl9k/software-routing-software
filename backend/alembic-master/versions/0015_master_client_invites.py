"""One-time invites for registration from the native client."""
from alembic import op
import sqlalchemy as sa

revision = '0015_master'
down_revision = '0014_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_client_invites',
        sa.Column('token_hash', sa.String(length=64), primary_key=True),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=True),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_master_client_invite_account', 'master_client_invites', ['account_id'])


def downgrade():
    op.drop_index('ix_master_client_invite_account', table_name='master_client_invites')
    op.drop_table('master_client_invites')
