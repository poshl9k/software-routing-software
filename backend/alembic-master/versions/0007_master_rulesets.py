"""Versioned, immutable client rule-sets served by exact version."""
from alembic import op
import sqlalchemy as sa

revision = '0007_master'
down_revision = '0006_master'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'master_rule_sets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=8), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('entries', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('kind', 'version', name='uq_master_ruleset_version'),
        sa.CheckConstraint("kind IN ('domain', 'ipcidr')", name='ck_master_ruleset_kind'),
        sa.CheckConstraint('entries > 0', name='ck_master_ruleset_entries'),
    )


def downgrade():
    op.drop_table('master_rule_sets')
