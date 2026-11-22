"""Demo tariff, daily traffic counters and PoW challenges for open registration."""
from alembic import op
import sqlalchemy as sa

revision = '0016_master'
down_revision = '0015_master'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('master_accounts') as batch:
        batch.add_column(sa.Column('registration_ip', sa.String(length=64), nullable=True))
    with op.batch_alter_table('master_tariffs') as batch:
        batch.add_column(sa.Column('daily_traffic_limit_mb', sa.Integer(), nullable=True))
    op.create_table(
        'master_client_challenges',
        sa.Column('token_hash', sa.String(length=64), primary_key=True),
        sa.Column('difficulty', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
    )
    op.create_table(
        'master_traffic_usage',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('account_id', sa.Integer(), sa.ForeignKey('master_accounts.id'), nullable=False),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('master_devices.id'), nullable=False),
        sa.Column('day', sa.Date(), nullable=False),
        sa.Column('bytes', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('device_id', 'day', name='uq_master_traffic_day'),
    )
    op.create_index('ix_master_traffic_account_day', 'master_traffic_usage', ['account_id', 'day'])
    conn = op.get_bind()
    existing = conn.execute(sa.text("SELECT id FROM master_tariffs WHERE name = 'Demo'")).fetchone()
    if existing is None:
        conn.execute(sa.text(
            "INSERT INTO master_tariffs (name, device_limit, term_days, daily_traffic_limit_mb, "
            "price_amount, created_at) VALUES ('Demo', 1, 7, 500, NULL, CURRENT_TIMESTAMP)"
        ))


def downgrade():
    conn = op.get_bind()
    conn.execute(sa.text(
        "DELETE FROM master_tariffs WHERE name = 'Demo' AND id NOT IN "
        "(SELECT tariff_id FROM master_subscriptions)"
    ))
    op.drop_index('ix_master_traffic_account_day', table_name='master_traffic_usage')
    op.drop_table('master_traffic_usage')
    op.drop_table('master_client_challenges')
    with op.batch_alter_table('master_tariffs') as batch:
        batch.drop_column('daily_traffic_limit_mb')
    with op.batch_alter_table('master_accounts') as batch:
        batch.drop_column('registration_ip')
