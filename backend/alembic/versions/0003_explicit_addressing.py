"""Explicit addressing: legacy addressless WAN interfaces become DHCP clients.

The implicit rule "an addressless (physical) WAN uses DHCP" is replaced by the
explicit `addressing` field. Existing configurations predate the field, so an
interface that the old rule would have made a DHCP client — zone `wan` with no
static addresses — is marked `addressing="dhcp"`, preserving behaviour.
`schema_version` stays 1: the field is optional with a `static` default.
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _load(value):
    return json.loads(value) if isinstance(value, str) else value


def _rows(bind):
    return bind.execute(sa.text(
        "select id, configuration from configuration_versions")).fetchall()


def _store(bind, row_id, data):
    bind.execute(sa.text(
        "update configuration_versions set configuration = :c where id = :i"),
        {"c": json.dumps(data, separators=(",", ":")), "i": row_id})


def upgrade():
    bind = op.get_bind()
    for row_id, configuration in _rows(bind):
        data = _load(configuration)
        changed = False
        for interface in data.get("interfaces", []):
            if (interface.get("zone") == "wan" and not interface.get("addresses")
                    and "addressing" not in interface):
                interface["addressing"] = "dhcp"
                changed = True
        if changed:
            _store(bind, row_id, data)


def downgrade():
    bind = op.get_bind()
    for row_id, configuration in _rows(bind):
        data = _load(configuration)
        changed = False
        for interface in data.get("interfaces", []):
            if interface.get("addressing") == "dhcp" and not interface.get("addresses"):
                interface.pop("addressing", None)
                changed = True
        if changed:
            _store(bind, row_id, data)
