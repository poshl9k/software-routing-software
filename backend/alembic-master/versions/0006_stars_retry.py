"""Allow one separately reviewed retry while retaining the expired first order."""
from alembic import op
import sqlalchemy as sa

revision = '0006_master'
down_revision = '0005_master'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'sqlite':
        raise RuntimeError('Stars pilot requires SQLite')
    if bind.exec_driver_sql('PRAGMA foreign_keys').scalar() != 0:
        raise RuntimeError('SQLite foreign keys must be disabled during order-table rebuild')
    with op.batch_alter_table('master_stars_orders', recreate='always') as batch:
        batch.drop_constraint('ck_master_stars_slot', type_='check')
        batch.create_check_constraint('ck_master_stars_slot',
                                      "test_slot IN ('super-30d-1xtr-v1', 'super-30d-1xtr-retry-v1')")
    if bind.exec_driver_sql('PRAGMA foreign_key_check').first() is not None:
        raise RuntimeError('Stars order foreign key check failed after migration')


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'sqlite':
        raise RuntimeError('Stars pilot requires SQLite')
    if bind.exec_driver_sql('PRAGMA foreign_keys').scalar() != 0:
        raise RuntimeError('SQLite foreign keys must be disabled during order-table rebuild')
    if bind.scalar(sa.text("SELECT COUNT(*) FROM master_stars_orders "
                           "WHERE test_slot = 'super-30d-1xtr-retry-v1'")):
        raise RuntimeError('Stars retry history exists; restore a reviewed backup instead of downgrading')
    with op.batch_alter_table('master_stars_orders', recreate='always') as batch:
        batch.drop_constraint('ck_master_stars_slot', type_='check')
        batch.create_check_constraint('ck_master_stars_slot', "test_slot = 'super-30d-1xtr-v1'")
    if bind.exec_driver_sql('PRAGMA foreign_key_check').first() is not None:
        raise RuntimeError('Stars order foreign key check failed after downgrade')
