"""Publish an immutable rule-set version (migration after 0009_master).

Auto-refreshing sources keep their URL/interval in ``master_rule_set_sources``;
every refresh writes a new ``master_rule_sets`` row, so clients pinned to a
version never see content change under them.
"""
from alembic import op
import sqlalchemy as sa

revision = '0010_master'
down_revision = '0009_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_rule_set_sources',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=8), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('interval_seconds', sa.Integer(), nullable=False, server_default='86400'),
        sa.Column('version', sa.String(length=32), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_master_ruleset_source_name'),
        sa.CheckConstraint("kind IN ('domain', 'ipcidr')", name='ck_master_ruleset_source_kind'),
        sa.CheckConstraint('interval_seconds >= 3600', name='ck_master_ruleset_source_interval'),
    )


def downgrade():
    op.drop_table('master_rule_set_sources')
