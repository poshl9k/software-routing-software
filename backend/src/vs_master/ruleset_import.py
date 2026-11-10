"""Import a declared rule-set source into an immutable master version.

The node panel already declares rule-set sources (name, format, https URL,
caps). The master does not talk to the node for this: the administrator pastes
the source URL, the master fetches it once with its own guards and stores the
normalized payload. Fetching here is deliberate but narrow: HTTPS only, no
redirects, every resolved address must be public, bounded size and timeout.
"""
import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

from vs_router.api.errors import APIError

from . import rulesets

MAX_BYTES = rulesets.MAX_BYTES
TIMEOUT = 10.0
USER_AGENT = 'vs-master-ruleset-import/1'


def _public_address(host):
    """Resolve once and reject anything that is not a global unicast address."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise APIError(422, 'master.ruleset_fetch') from None
    if not infos:
        raise APIError(422, 'master.ruleset_fetch')
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise APIError(422, 'master.ruleset_fetch') from None
        if not address.is_global or address.is_multicast:
            raise APIError(422, 'master.ruleset_source_forbidden')


def validate_source_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise APIError(422, 'master.ruleset_source_invalid')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise APIError(422, 'master.ruleset_source_invalid')
    try:
        port = parsed.port
    except ValueError:
        raise APIError(422, 'master.ruleset_source_invalid') from None
    if port == 0:
        raise APIError(422, 'master.ruleset_source_invalid')
    _public_address(parsed.hostname)
    return value


def fetch_source(url):
    """One guarded GET; a redirect is an explicit failure, not a silent hop."""
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=False,
                          headers={'User-Agent': USER_AGENT}) as client:
            response = client.get(url)
    except httpx.HTTPError:
        raise APIError(422, 'master.ruleset_fetch') from None
    if response.status_code != 200:
        raise APIError(422, 'master.ruleset_fetch')
    body = response.content
    if not body or len(body) > MAX_BYTES:
        raise APIError(422, 'master.ruleset_content')
    try:
        return body.decode('utf-8')
    except UnicodeDecodeError:
        raise APIError(422, 'master.ruleset_format_unsupported') from None


def parse_entries(kind, text):
    """Accept plain lines and the line-oriented geosite/geoip grammars.

    ``srs`` (binary sing-box rule-set) and other binary formats are rejected
    explicitly: guessing here would publish an empty or wrong list.
    """
    if kind not in rulesets.KINDS:
        raise APIError(422, 'master.ruleset_kind')
    entries = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        if line.startswith(('{', '[')) or line.startswith('SRS'):
            raise APIError(422, 'master.ruleset_format_unsupported')
        if ':' in line and line.split(':', 1)[0] in ('domain', 'full', 'include', 'keyword',
                                                     'regexp', 'regex', 'cidr', 'ip'):
            head, _, value = line.partition(':')
            value = value.split('@', 1)[0].strip()
            if head in ('keyword', 'regexp', 'regex'):
                # mihomo rule-providers of behaviour "domain" cannot express
                # these; publishing them silently would change matching.
                raise APIError(422, 'master.ruleset_format_unsupported')
            if head == 'full':
                entries.append(value)
            elif head in ('domain', 'include'):
                entries.append(value)
            elif head in ('cidr', 'ip'):
                entries.append(value)
            continue
        entries.append(line)
    return '\n'.join(entries) + ('\n' if entries else '')


def import_source(db, kind, version, url, now):
    """Publish the fetched source as a new immutable version."""
    if not rulesets.valid_version(version):
        raise APIError(422, 'master.ruleset_version')
    validate_source_url(url)
    text = parse_entries(kind, fetch_source(url))
    normal, entries, digest = rulesets.normalize(kind, text)
    from .models import RuleSet
    row = RuleSet(kind=kind, version=version, sha256=digest, entries=entries,
                  content=normal, created_at=now)
    db.add(row)
    return row


def source_view(row):
    return {'id': row.id, 'name': row.name, 'kind': row.kind, 'url': row.url,
            'interval_seconds': row.interval_seconds, 'version': row.version,
            'last_checked_at': row.last_checked_at, 'last_error': row.last_error}


def refresh_source(db, source, now):
    """Publish a new immutable version when the upstream content changed."""
    from sqlalchemy import select

    from .models import RuleSet

    validate_source_url(source.url)
    text = parse_entries(source.kind, fetch_source(source.url))
    normal, entries, digest = rulesets.normalize(source.kind, text)
    current = None
    if source.version:
        current = db.scalar(select(RuleSet).where(
            RuleSet.kind == source.kind, RuleSet.version == source.version))
    if current is not None and current.sha256 == digest:
        return None
    label = f'{source.name[:20]}-{now:%Y%m%d%H%M}'
    if db.scalar(select(RuleSet.id).where(
            RuleSet.kind == source.kind, RuleSet.version == label)) is not None:
        label = f'{label}-{int(now.timestamp()) % 1000}'
    row = RuleSet(kind=source.kind, version=label, sha256=digest, entries=entries,
                  content=normal, created_at=now)
    db.add(row)
    source.version = label
    return row


def refresh_due_sources(engine, now, limit=3):
    """Worker hook: refresh at most ``limit`` due sources; never raise."""
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from .models import RuleSetSource

    published = 0
    with Session(engine) as db:
        for source in db.scalars(select(RuleSetSource).order_by(RuleSetSource.id)):
            if published >= limit:
                break
            if (source.last_checked_at is not None
                    and (now - source.last_checked_at).total_seconds() < source.interval_seconds):
                continue
            try:
                if refresh_source(db, source, now) is not None:
                    published += 1
                source.last_error = None
            except APIError as exc:
                db.rollback()
                source = db.get(RuleSetSource, source.id)
                if source is None:
                    continue
                source.last_error = str(exc.code)[:64]
            except Exception:
                db.rollback()
                source = db.get(RuleSetSource, source.id)
                if source is None:
                    continue
                source.last_error = 'master.ruleset_fetch'
            source.last_checked_at = now
            db.commit()
    return published
