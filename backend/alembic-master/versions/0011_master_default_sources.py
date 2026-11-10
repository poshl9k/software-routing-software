"""Seed the two default rule-set sources (RU addresses and RU domains).

Rows only: the worker fetches and publishes versions on its next pass, so the
migration performs no network I/O and stays safe to run offline.
"""
from alembic import op
import sqlalchemy as sa

revision = '0011_master'
down_revision = '0010_master'
branch_labels = None
depends_on = None

DEFAULTS = (
    ('ru-ips', 'ipcidr', 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'),
    ('ru-domains', 'domain',
     'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/tld-ru'),
)


def upgrade():
    bind = op.get_bind()
    for name, kind, url in DEFAULTS:
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
    for name, _kind, _url in DEFAULTS:
        bind.execute(sa.text('DELETE FROM master_rule_set_sources WHERE name = :name'),
                     {'name': name})
