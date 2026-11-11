"""Tag published rule-sets with their source and seed the Telegram lists.

The exporter resolves mihomo rule-providers by source name, so several sets of
one kind can coexist: Russian lists go DIRECT, the Telegram lists are forced
through the tunnel. Migration 0011 seeded the RU sources; this one adds the
Telegram pair and backfills the source of the versions published before the
column existed.
"""
from alembic import op
import sqlalchemy as sa

revision = '0014_master'
down_revision = '0013_master'
branch_labels = None
depends_on = None

TELEGRAM_SOURCES = (
    ('tg-ips', 'ipcidr', 'https://core.telegram.org/resources/cidr.txt'),
    ('tg-domains', 'domain',
     'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/telegram'),
)


def upgrade():
    with op.batch_alter_table('master_rule_sets') as batch:
        batch.add_column(sa.Column('source', sa.String(length=64), nullable=True))
    bind = op.get_bind()
    # Versions published before this migration belong to the RU defaults.
    bind.execute(sa.text(
        "UPDATE master_rule_sets SET source = 'ru-ips' WHERE kind = 'ipcidr' AND source IS NULL"))
    bind.execute(sa.text(
        "UPDATE master_rule_sets SET source = 'ru-domains' WHERE kind = 'domain' AND source IS NULL"))
    for name, kind, url in TELEGRAM_SOURCES:
        exists = bind.execute(sa.text(
            'SELECT 1 FROM master_rule_set_sources WHERE name = :name'), {'name': name}).first()
        if exists is None:
            bind.execute(sa.text(
                'INSERT INTO master_rule_set_sources '
                '(name, kind, url, interval_seconds, version, last_checked_at, last_error, created_at) '
                'VALUES (:name, :kind, :url, 86400, NULL, NULL, NULL, CURRENT_TIMESTAMP)'),
                {'name': name, 'kind': kind, 'url': url})


def downgrade():
    bind = op.get_bind()
    for name, _kind, _url in TELEGRAM_SOURCES:
        bind.execute(sa.text('DELETE FROM master_rule_set_sources WHERE name = :name'),
                     {'name': name})
    bind.execute(sa.text("UPDATE master_rule_sets SET source = NULL"))
    with op.batch_alter_table('master_rule_sets') as batch:
        batch.drop_column('source')
