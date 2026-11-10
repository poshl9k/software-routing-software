"""Import a declared rule-set source into an immutable master version.

The node panel already declares rule-set sources (name, format, https URL,
caps). The master does not talk to the node for this: the administrator pastes
the source URL, the master fetches it once with its own guards and stores the
normalized payload. Fetching here is deliberate but narrow: HTTPS only, no
redirects, every resolved address must be public, bounded size and timeout.
"""
import ipaddress
import json
import socket
from urllib.parse import urlsplit

import httpx

from vs_router.api.errors import APIError

from . import rulesets

MAX_BYTES = 16 * 1024 * 1024  # RIPE delegated stats is ~8 MiB; payload caps still apply
TIMEOUT = 20.0
USER_AGENT = 'vs-master-ruleset-import/1'

#: Default sources seeded by migration 0011: the authoritative RU registry data
#: for addresses and the v2fly category list for domains (the same upstream
#: family the panel's own catalog already references).
RIPE_URL = 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'
V2FLY_RU_URL = 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/tld-ru'


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


def _parse_json(kind, text):
    """Accept a sing-box rule-set document (``{"version": 3, "rules": [...]}``).

    Only matchers mihomo's ``behavior: domain``/``ipcidr`` can express are
    taken: ``domain`` (exact upstream, plain payload entry here), ``domain_suffix``
    (``+.suffix``) and ``ip_cidr``. Anything else is rejected rather than
    silently dropped, because dropping a matcher changes routing.
    """
    try:
        document = json.loads(text)
    except ValueError:
        raise APIError(422, 'master.ruleset_format_unsupported') from None
    if not isinstance(document, dict) or not isinstance(document.get('rules'), list):
        raise APIError(422, 'master.ruleset_format_unsupported')
    domain_keys = {'domain', 'domain_suffix'}
    ip_keys = {'ip_cidr'}
    entries = []
    for rule in document['rules']:
        if not isinstance(rule, dict):
            raise APIError(422, 'master.ruleset_format_unsupported')
        for key, value in rule.items():
            if key in domain_keys:
                if kind != 'domain':
                    continue
                if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                    raise APIError(422, 'master.ruleset_format_unsupported')
                for item in value:
                    entries.append(item if key == 'domain' else f'+.{item.lstrip(".")}')
            elif key in ip_keys:
                if kind != 'ipcidr':
                    continue
                if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                    raise APIError(422, 'master.ruleset_format_unsupported')
                entries.extend(value)
            else:
                # A matcher we cannot publish faithfully (domain_keyword,
                # domain_regex, process_name, ports, …).
                raise APIError(422, 'master.ruleset_format_unsupported')
    return '\n'.join(entries) + ('\n' if entries else '')


def _parse_ripe(text):
    """RIPE delegated stats → RU CIDRs (official registry data, no licence issue).

    Records carry a start address and a count that is not always a power of two,
    so ranges are summarized into minimal CIDRs instead of assuming /24s.
    """
    entries = []
    for raw in text.splitlines():
        parts = raw.strip().split('|')
        if len(parts) < 7 or parts[0] != 'ripencc' or parts[1] != 'RU':
            continue
        kind, start, count = parts[2], parts[3], parts[4]
        if not count.isdigit() or int(count) <= 0:
            continue
        try:
            if kind == 'ipv4':
                first = ipaddress.IPv4Address(start)
                last = ipaddress.IPv4Address(int(first) + int(count) - 1)
            elif kind == 'ipv6':
                # For IPv6 the count field is the prefix length, not an address count.
                prefix = int(count)
                if not 1 <= prefix <= 128:
                    continue
                entries.append(f'{ipaddress.IPv6Address(start)}/{prefix}')
                continue
            else:
                continue
        except ValueError:
            continue
        entries.extend(str(net) for net in ipaddress.summarize_address_range(first, last))
    return '\n'.join(entries) + ('\n' if entries else '')


def parse_entries(kind, text):
    """Accept plain lines, geosite/geoip grammars, sing-box JSON and RIPE stats.

    ``srs`` (binary sing-box rule-set) is rejected explicitly: neither the
    master nor the node decodes it, guessing would publish an empty or wrong
    list.
    """
    if kind not in rulesets.KINDS:
        raise APIError(422, 'master.ruleset_kind')
    if text.lstrip().startswith('{'):
        return _parse_json(kind, text.lstrip())
    head = [line.strip() for line in text.splitlines()[:5] if line.strip()]
    if any(line.startswith('ripencc|') for line in head) and kind == 'ipcidr':
        return _parse_ripe(text)
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
            if head == 'include':
                # An include pulls in another upstream file; resolving it here
                # would silently change the set, so it is an explicit failure.
                raise APIError(422, 'master.ruleset_format_unsupported')
            if head in ('domain', 'full', 'cidr', 'ip'):
                entries.append(value)
            continue
        # A single-label entry is a TLD (e.g. "ru"), which must become a suffix
        # rule: a bare "ru" in a mihomo domain payload is ambiguous.
        entries.append(line if '.' in line else f'+.{line}')
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
