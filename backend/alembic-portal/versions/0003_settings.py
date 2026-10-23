"""Portal settings table (support contact etc.)."""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('portal_settings',
                    sa.Column('key', sa.String(length=64), primary_key=True),
                    sa.Column('value', sa.String(length=256), nullable=False))


def downgrade() -> None:
    op.drop_table('portal_settings')