"""Demo allows one device; scoped share tokens and peer fingerprints.

Downstream of ADR-0036/0037: paid tariffs can share the account with other
devices, while every app instance gets its own peer and scoped credential.
"""
from alembic import op
import sqlalchemy as sa

revision = '0019_master'
down_revision = '0018_master'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute(sa.text("UPDATE master_tariffs SET device_limit = 1 WHERE name = 'Demo'"))

    with op.batch_alter_table('master_devices') as batch:
        batch.add_column(sa.Column('client_fingerprint', sa.String(64)))

    with op.batch_alter_table('master_portal_links') as batch:
        batch.add_column(sa.Column('device_fingerprint', sa.String(64)))

    op.create_table(
        'master_client_device_links',
        sa.Column('token_hash', sa.String(64), primary_key=True, nullable=False),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=False),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('master_devices.id'), nullable=False),
        sa.Column('device_fingerprint', sa.String(64), nullable=False),
        sa.Column('token_secret', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime()),
    )
    op.create_index('ix_master_client_device_account', 'master_client_device_links', ['account_id'])

    op.create_table(
        'master_client_shares',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False),
        sa.Column('token_secret', sa.JSON(), nullable=False),
        sa.Column('max_uses', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('used_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('token_hash', name='uq_master_client_share_hash'),
    )
    op.create_index('ix_master_client_share_account', 'master_client_shares', ['account_id'])


def downgrade():
    op.drop_index('ix_master_client_share_account', table_name='master_client_shares')
    op.drop_table('master_client_shares')
    op.drop_index('ix_master_client_device_account', table_name='master_client_device_links')
    op.drop_table('master_client_device_links')
    with op.batch_alter_table('master_devices') as batch:
        batch.drop_column('client_fingerprint')
    with op.batch_alter_table('master_portal_links') as batch:
        batch.drop_column('device_fingerprint')
