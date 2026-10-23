"""Portal devices record the tunnel they were created in (ADR-0033 renewal)."""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('portal_devices', sa.Column('tunnel_name', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('portal_devices', 'tunnel_name')
