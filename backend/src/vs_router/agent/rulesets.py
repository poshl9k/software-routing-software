"""Rule-set source profiles: strict format↔content validation, limits, staleness.

Scope
-----
This is the *rule-set handling* required by ``docs/sing-box-tproxy-plan.md``
§«Источники списков и обновления»: a source profile **strictly determines** the
expected format, the content is validated against it, a size/record cap is
enforced, and every accepted payload carries a hash/version plus a staleness view.

It is pure, offline data handling: no network, no shell, no writes. The
downloader (``agent/downloader.py``) is what fetches bytes; this module decides
whether those bytes are the shape the profile promised.

Formats
-------
* ``text-domain`` — one domain per line (optionally prefixed ``domain:``/``full:``
  /``keyword:``/``regexp:``), comments with ``#``/``//``/``;``. A CIDR line is a
  **mismatch**, not a domain.
* ``text-cidr`` — one IPv4/IPv6 address or CIDR per line. A domain line is a
  **mismatch**, not a CIDR.
* ``json`` — a sing-box rule-set document (``{"version": …, "rules": [...]}``).
* ``geosite`` — a domain list (text-domain grammar) in v2fly/geosite form; it is
  accepted but flagged as needing materialization into a sing-box rule-set.
* ``geoip`` — an address list (text-cidr grammar) in geoip form; same caveat.
* ``srs`` — a binary sing-box rule-set. It is *recognized* (by its ``SRS``
  magic) but honestly reported as **not activatable** here: byte-exact storage
  and a pinned compiler are out of scope, so it never claims to be usable.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Literal, get_args

from pydantic import Field, model_validator

from ..schema import Model
from .apply import ApplyError

RuleSetFormat = Literal["text-domain", "text-cidr", "json", "geosite", "geoip", "srs"]
RULE_SET_FORMATS: tuple[str, ...] = get_args(RuleSetFormat)

DEFAULT_MAX_RECORDS = 200_000
DEFAULT_MAX_BYTES = 5_000_000
DEFAULT_STALE_AFTER_SECONDS = 7 * 24 * 3600

#: sing-box binary rule-set magic.
SRS_MAGIC = b"SRS"

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}$", re.IGNORECASE)
_DOMAIN_PREFIXES = ("domain:", "full:", "keyword:", "regexp:")


class RuleSetError(ApplyError):
    """A rule-set validation failure carrying a stable ``ruleset.*`` code."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.detail = detail


class SourceProfile(Model):
    """A source's declared identity: format, url and caps. Strict by design.

    The format is a closed set; ``https`` is mandatory. ``max_records`` and
    ``max_bytes`` bound the payload before it can be considered for activation.
    """

    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_]{0,30}$")
    format: RuleSetFormat
    url: str
    max_records: int = Field(default=DEFAULT_MAX_RECORDS, ge=1, le=5_000_000)
    max_bytes: int = Field(default=DEFAULT_MAX_BYTES, ge=1024, le=50_000_000)

    @model_validator(mode="after")
    def _check(self):
        if not self.url.lower().startswith("https://"):
            raise ValueError("ruleset.https_required")
        return self


@dataclass(frozen=True)
class RuleSetInfo:
    """What a validated payload is: hash, size, record count, activatability."""

    name: str
    format: str
    sha256: str
    size: int
    records: int
    activatable: bool = True
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Staleness:
    stale: bool
    age_seconds: float | None


# ---------------------------------------------------------------------------
# Line-oriented grammars
# ---------------------------------------------------------------------------

def _iter_lines(content: str):
    for raw in content.splitlines():
        token = raw.split("#", 1)[0]
        token = token.split("//", 1)[0].strip()
        if token.startswith(";"):
            continue
        if token:
            yield token


def _is_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def _domain_token(token: str) -> str | None:
    for prefix in _DOMAIN_PREFIXES:
        if token.startswith(prefix):
            token = token[len(prefix):].strip()
            break
    return token or None


def _count_domains(content: str) -> int:
    records = 0
    for token in _iter_lines(content):
        if _is_cidr(token):
            raise RuleSetError("ruleset.format_mismatch",
                               f"CIDR line in a domain set: {token!r}")
        candidate = _domain_token(token)
        if candidate is None or not _DOMAIN_RE.match(candidate):
            raise RuleSetError("ruleset.invalid_record", f"not a domain: {token!r}")
        records += 1
    if records == 0:
        raise RuleSetError("ruleset.empty")
    return records


def _count_cidrs(content: str) -> int:
    records = 0
    for token in _iter_lines(content):
        candidate = _domain_token(token)  # tolerate 'ip:' style prefixes
        if candidate is not None and not _is_cidr(candidate):
            raise RuleSetError("ruleset.format_mismatch",
                               f"non-CIDR line in an address set: {token!r}")
        if candidate is None or not _is_cidr(candidate):
            raise RuleSetError("ruleset.invalid_record", f"not a CIDR: {token!r}")
        records += 1
    if records == 0:
        raise RuleSetError("ruleset.empty")
    return records


def _count_json_rules(content: str) -> int:
    try:
        value = json.loads(content)
    except (ValueError, TypeError) as exc:
        raise RuleSetError("ruleset.invalid_record", "not valid JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("rules"), list):
        raise RuleSetError("ruleset.format_mismatch",
                           "JSON set must be a sing-box rule-set document")
    for rule in value["rules"]:
        if not isinstance(rule, dict):
            raise RuleSetError("ruleset.invalid_record", "rule entry is not an object")
    return len(value["rules"])


def _check_srs(content: bytes) -> RuleSetInfo:
    # Recognized but not activatable: honest, not a silent pass.
    magic_ok = content[:len(SRS_MAGIC)] == SRS_MAGIC
    warnings = ("ruleset.srs_requires_pinned_tool",)
    if not magic_ok:
        warnings = warnings + ("ruleset.srs_magic_missing",)
    return RuleSetInfo(name="", format="srs",
                       sha256=hashlib.sha256(content).hexdigest(), size=len(content),
                       records=0, activatable=False, warnings=warnings)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def validate_ruleset(content: str | bytes, profile: SourceProfile) -> RuleSetInfo:
    """Validate ``content`` as ``profile.format``; raise :class:`RuleSetError`.

    Returns a :class:`RuleSetInfo` on success. ``.srs`` never raises for a
    well-formed payload — it returns ``activatable=False`` with an explicit
    warning, because the honest state is "recognized, not usable here".
    """
    if isinstance(content, bytes):
        payload = content
    else:
        payload = content.encode("utf-8")
    if len(payload) > profile.max_bytes:
        raise RuleSetError("ruleset.too_large", f"{len(payload)} > {profile.max_bytes}")

    fmt = profile.format
    if fmt == "srs":
        info = _check_srs(payload)
        return RuleSetInfo(name=profile.name, format=info.format, sha256=info.sha256,
                           size=info.size, records=info.records, activatable=False,
                           warnings=info.warnings)

    # Everything else is textual; a binary payload is a format mismatch.
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuleSetError("ruleset.format_mismatch", "payload is not UTF-8 text") from exc

    if fmt == "text-domain":
        records = _count_domains(text)
    elif fmt == "text-cidr":
        records = _count_cidrs(text)
    elif fmt == "json":
        records = _count_json_rules(text)
    elif fmt == "geosite":
        records = _count_domains(text)
    elif fmt == "geoip":
        records = _count_cidrs(text)
    else:  # pragma: no cover - closed Literal, guarded by the schema
        raise RuleSetError("ruleset.format_unknown", fmt)

    if records > profile.max_records:
        raise RuleSetError("ruleset.too_many_records", f"{records} > {profile.max_records}")

    warnings: tuple[str, ...] = ()
    if fmt in ("geosite", "geoip"):
        warnings = ("ruleset.requires_materialization",)
    return RuleSetInfo(name=profile.name, format=fmt,
                       sha256=hashlib.sha256(payload).hexdigest(), size=len(payload),
                       records=records, activatable=True, warnings=warnings)


def staleness(*, now: float, last_success: float | None,
              stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS) -> Staleness:
    """Age of the last successful update of a set and whether it is stale."""
    if last_success is None:
        return Staleness(stale=True, age_seconds=None)
    age = now - last_success
    return Staleness(stale=age > stale_after_seconds, age_seconds=age)
