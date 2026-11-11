"""Versioned client rule-sets: normalization, hashing and read-only serving.

Clients consume these through a mihomo `rule-provider` pinned to an exact
version, so a published version is immutable. Validation lives here (not in the
router) so the administrator API and the serving endpoint agree on one contract.
"""
import hashlib
import re
from ipaddress import ip_network

from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.api.errors import APIError

from .models import RuleSet, Setting

KINDS = ('domain', 'ipcidr')
MAX_ENTRIES = 50_000
MAX_BYTES = 2 * 1024 * 1024

_VERSION = re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$')
_DOMAIN = re.compile(r'^(\+\.|\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9])?)*$')


def valid_version(value):
    return isinstance(value, str) and bool(_VERSION.match(value))


def normalize(kind, content):
    """Return (normalized_text, entries, sha256) or raise a typed 422."""
    if kind not in KINDS:
        raise APIError(422, 'master.ruleset_kind')
    if not isinstance(content, str):
        raise APIError(422, 'master.ruleset_content')
    if len(content.encode('utf-8')) > MAX_BYTES:
        raise APIError(422, 'master.ruleset_content')
    entries = []
    seen = set()
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if len(line) > 253:
            raise APIError(422, 'master.ruleset_entry')
        if kind == 'domain':
            value = line.lower()
            if not _DOMAIN.match(value):
                raise APIError(422, 'master.ruleset_entry')
        else:
            try:
                value = str(ip_network(line, strict=False))
            except ValueError:
                raise APIError(422, 'master.ruleset_entry') from None
        if value in seen:
            continue
        seen.add(value)
        entries.append(value)
        if len(entries) > MAX_ENTRIES:
            raise APIError(422, 'master.ruleset_content')
    if not entries:
        raise APIError(422, 'master.ruleset_content')
    text = '\n'.join(entries) + '\n'
    return text, len(entries), hashlib.sha256(text.encode('utf-8')).hexdigest()


def view(row):
    return {'id': row.id, 'kind': row.kind, 'source': row.source, 'version': row.version,
            'entries': row.entries, 'sha256': row.sha256, 'created_at': row.created_at}


def current(db: Session, kind, source=None):
    """The newest published version of one kind (optionally of one source), or None."""
    query = select(RuleSet).where(RuleSet.kind == kind)
    if source is not None:
        query = query.where(RuleSet.source == source)
    return db.scalar(query.order_by(RuleSet.id.desc()))


def public_url(db: Session):
    """The HTTPS origin clients must use for rule-provider URLs, if configured."""
    row = db.get(Setting, 'master_public_url')
    return row.value.rstrip('/') if row is not None and row.value else None
