"""Keep the subscription token encrypted so the same link can be shown again.

Until now the master stored only ``token_hash``, so the cabinet had to reissue
a token to display the link — every visit rotated the link. The token is now
also stored encrypted (the same master key that protects bridge tokens and
device keys), so the link and its QR are stable until the user rotates them.
"""
from alembic import op
import sqlalchemy as sa

revision = '0012_master'
down_revision = '0011_master'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('master_device_subscriptions') as batch:
        batch.add_column(sa.Column('token_secret', sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table('master_device_subscriptions') as batch:
        batch.drop_column('token_secret')
