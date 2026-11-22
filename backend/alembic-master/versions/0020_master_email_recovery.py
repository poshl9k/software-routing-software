"""Verified subscriber email, reset proofs and encrypted durable mail outbox."""
from alembic import op
import sqlalchemy as sa

revision = '0020_master'
down_revision = '0019_master'
branch_labels = None
depends_on = None


def upgrade():
    # ADD COLUMN avoids rebuilding the heavily referenced accounts table.
    op.add_column('master_accounts', sa.Column('email', sa.String(254)))
    op.add_column('master_accounts', sa.Column('password_revision', sa.Integer(), nullable=False, server_default='0'))
    op.create_index('uq_master_account_email', 'master_accounts', ['email'], unique=True)
    op.create_table(
        'master_email_proofs',
        sa.Column('token_hash', sa.String(64), primary_key=True),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('kind', sa.String(6), nullable=False),
        sa.Column('email', sa.String(254), nullable=False),
        sa.Column('password_revision', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('consumed_at', sa.DateTime()),
        sa.UniqueConstraint('account_id', 'kind', name='uq_master_email_proof_account_kind'),
        sa.CheckConstraint("kind IN ('verify', 'reset')", name='ck_master_email_proof_kind'),
    )
    op.create_table(
        'master_email_outbox',
        sa.Column('token_hash', sa.String(64), sa.ForeignKey('master_email_proofs.token_hash', ondelete='CASCADE'), primary_key=True),
        sa.Column('body_secret', sa.JSON()),
        sa.Column('status', sa.String(12), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(), nullable=False),
        sa.Column('claim_token', sa.String(64)),
        sa.Column('delivered_at', sa.DateTime()),
        sa.CheckConstraint("status IN ('pending', 'delivered', 'suppressed')", name='ck_master_email_status'),
        sa.CheckConstraint('attempts >= 0', name='ck_master_email_attempts'),
    )
    op.create_index('ix_master_email_due', 'master_email_outbox', ['status', 'next_attempt_at'])
    op.create_table(
        'master_email_rate_limits',
        sa.Column('key', sa.String(64), primary_key=True),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
    )


def downgrade():
    conn = op.get_bind()
    # Do not silently discard confirmed identities or an in-flight credential.
    if (conn.scalar(sa.text('SELECT count(*) FROM master_accounts WHERE email IS NOT NULL OR password_revision != 0'))
            or conn.scalar(sa.text('SELECT count(*) FROM master_email_proofs'))):
        raise RuntimeError('Email recovery data exists; restore a reviewed backup instead of downgrading')
    op.drop_table('master_email_outbox')
    op.drop_table('master_email_proofs')
    op.drop_table('master_email_rate_limits')
    op.drop_index('uq_master_account_email', table_name='master_accounts')
    # Supported SQLite versions can remove these unreferenced columns in place.
    op.drop_column('master_accounts', 'password_revision')
    op.drop_column('master_accounts', 'email')
