"""Preset source catalog: data + adapter, not router logic.

Scope
-----
Required by ``docs/sing-box-tproxy-plan.md`` §«Источники списков и обновления»:
the awg-manager catalog is ported as **data**, the *name → format/url/licence*
mapping, **not** its Keenetic NDMS behaviour. Each entry names its format, url,
allowed hosts, licence and a provenance warning, so a source never arrives
without its origin and terms attached.

The catalog is the *allowlist* the downloader expects: :func:`catalog_sources`
adapts entries into :class:`~vs_router.agent.downloader.BuiltinSource` objects
(URL + host set + kind/format). Wiring it into the running agent is a deliberate
opt-in — ``downloader.BUILTIN_SOURCES`` stays empty by default — so that merely
importing this module changes no fetch behaviour.

Licence honesty
---------------
``license_verified`` means "independently checked as sufficient for *redistribution
inside the product*", which has **not** been done for any third-party set here.
Catalog services carry ``license_verified=False`` and the
``preset.license_unverified`` provenance warning: their URLs point to
repo.hoaxisr.ru / SagerNet GitHub and redistribution review is pending.
``123jjck/cdn-ip-ranges`` additionally has no licence at all
(its GitHub tree carries no licence file). This is data a reviewer must confirm
before the catalog is shipped, not a guarantee.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from urllib.parse import urlsplit
import re
from typing import Iterable, Literal

from .downloader import BuiltinSource
from vs_router.schema import RuleSetSource

WARNING_LICENSE_UNVERIFIED = "preset.license_unverified"
WARNING_LICENSE_MISSING = "preset.license_missing"


@dataclass(frozen=True)
class CatalogRuleSet:
    tag: str
    url: str


@dataclass(frozen=True)
class CatalogPreset:
    """Upstream service data; redistribution rights have not been verified.

    ``license_verified`` remains false and ``provenance`` carries the warning
    until the third-party catalog's licensing has been reviewed.
    """

    id: str
    name: str
    icon_slug: str
    category: str
    origin: str
    notice: str | None
    covers: tuple[str, ...]
    dns_domains: tuple[str, ...]
    rule_sets: tuple[CatalogRuleSet, ...]
    action: str | None
    license_verified: bool = False
    provenance: str = WARNING_LICENSE_UNVERIFIED


def load_catalog() -> tuple[CatalogPreset, ...]:
    """Load the bundled upstream JSON as immutable service records."""
    raw = json.loads(Path(__file__).with_name("presets_catalog.json").read_text(encoding="utf-8"))
    return tuple(
        CatalogPreset(
            id=entry["id"], name=entry["name"],
            icon_slug=entry["iconSlug"], category=entry["category"],
            origin=entry["origin"], notice=entry.get("notice"),
            covers=tuple(entry.get("covers", ())),
            dns_domains=tuple(entry["engines"].get("dns", {}).get("domains", ())),
            rule_sets=tuple(CatalogRuleSet(tag=item["tag"], url=item["url"])
                            for item in entry["engines"].get("singbox", {}).get("ruleSets", ())),
            action=entry["engines"].get("singbox", {}).get("action"),
        ) for entry in raw
    )


def service_rule_set_format(url: str) -> Literal["srs", "json"]:
    """Infer only formats proven by a known filename suffix; never guess text."""
    path = urlsplit(url).path.lower()
    if path.endswith(".srs"):
        return "srs"
    if path.endswith(".json"):
        return "json"
    raise ValueError(f"preset.invalid_rule_set_format: {url}")


def _selected(ids: Iterable[str]) -> tuple[CatalogPreset, ...]:
    catalog = {entry.id: entry for entry in load_catalog()}
    selected = []
    seen = set()
    for id_ in ids:
        if id_ not in catalog:
            raise ValueError(f"preset.unknown_service: {id_}")
        if id_ not in seen:
            selected.append(catalog[id_])
            seen.add(id_)
    return tuple(selected)


def selection_to_rule_sets(ids: Iterable[str]) -> tuple[RuleSetSource, ...]:
    """Resolve selected service rules, retaining first occurrence order.

    Catalog tags are used verbatim as names. RuleSetSource permits only an
    initial ASCII letter followed by up to 30 letters, digits or underscores;
    upstream hyphenated tags therefore fail explicitly rather than being renamed.
    """
    result = []
    seen = set()
    for preset in _selected(ids):
        for source in preset.rule_sets:
            if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,30}", source.tag):
                raise ValueError(f"preset.invalid_rule_set_tag: {source.tag}; RuleSetSource.name allows letters, digits, hyphen and underscore only")
            if source.tag in seen:
                continue
            result.append(RuleSetSource(name=source.tag, format=service_rule_set_format(source.url), url=source.url))
            seen.add(source.tag)
    return tuple(result)


def selection_to_domains(ids: Iterable[str]) -> tuple[str, ...]:
    """Return unique DNS domains in selected-service and source order."""
    return tuple(dict.fromkeys(domain for preset in _selected(ids)
                               for domain in preset.dns_domains))


@dataclass(frozen=True)
class PresetSource:
    """One catalog entry: identity, format, url/hosts, licence and provenance."""

    key: str
    name: str
    format: str
    url: str
    hosts: tuple[str, ...]
    kind: str = "rule_set"
    license: str | None = None
    license_verified: bool = False
    provenance: str = ""
    notes: str | None = None

    def warning(self) -> str:
        return WARNING_LICENSE_MISSING if self.license is None else WARNING_LICENSE_UNVERIFIED


#: Minimal built-in example set. Deliberately small: it demonstrates the adapter
#: shape and the provenance/licence discipline without pretending a full,
#: redistribution-cleared catalog has been assembled.
CATALOG: dict[str, PresetSource] = {
    "v2fly_domains": PresetSource(
        key="v2fly_domains",
        name="v2fly domain-list-community (домены)",
        format="geosite",
        url="https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-ads-all",
        hosts=("raw.githubusercontent.com",),
        kind="rule_set",
        license="GPL-3.0 (заявлена upstream; не подтверждена для переупаковки)",
        license_verified=False,
        provenance="v2fly/domain-list-community, ветка master",
        notes="Доменный список; требует материализации в sing-box rule-set.",
    ),
    "sing_geosite": PresetSource(
        key="sing_geosite",
        name="SagerNet sing-geosite (домены)",
        format="json",
        url="https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.json",
        hosts=("raw.githubusercontent.com",),
        kind="rule_set",
        license="GPL-3.0 (заявлена upstream; не подтверждена для переупаковки)",
        license_verified=False,
        provenance="SagerNet/sing-geosite, ветка rule-set",
        notes="Готовый sing-box rule-set (json) для доменов.",
    ),
    "rockblack_ip": PresetSource(
        key="rockblack_ip",
        name="RockBlack-VPN ip-address (CIDR)",
        format="text-cidr",
        url="https://raw.githubusercontent.com/RockBlack-VPN/ip-address/main/ip.txt",
        hosts=("raw.githubusercontent.com",),
        kind="rule_set",
        license=None,
        license_verified=False,
        provenance="RockBlack-VPN/ip-address, ветка main",
        notes="Адресный список; лицензия не подтверждена.",
    ),
    "cjk_cdn_ip": PresetSource(
        key="cjk_cdn_ip",
        name="123jjck/cdn-ip-ranges (CDN IP)",
        format="text-cidr",
        url="https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cdn-ip-ranges.txt",
        hosts=("raw.githubusercontent.com",),
        kind="rule_set",
        license=None,
        license_verified=False,
        provenance="123jjck/cdn-ip-ranges (файл лицензии в репозитории не найден)",
        notes="Права на переупаковку НЕ подтверждены; не включать в дистрибутив без проверки.",
    ),
}


def catalog_sources() -> dict[str, BuiltinSource]:
    """Adapt the catalog to the downloader's allowlist mapping.

    ``format`` is left as the downloader's ``auto``: the strict per-set format is
    enforced separately by :mod:`vs_router.agent.rulesets`, while the downloader
    only needs url/hosts/kind for its SSRF allowlist.
    """
    return {
        key: BuiltinSource(url=preset.url, hosts=frozenset(preset.hosts),
                           kind=preset.kind, format="auto")
        for key, preset in CATALOG.items()
    }


def selected_catalog_sources(keys: str) -> dict[str, BuiltinSource]:
    """Select explicit catalog keys for the agent allowlist; empty means off."""
    names = [key.strip() for key in keys.split(',') if key.strip()]
    unknown = set(names) - CATALOG.keys()
    if unknown:
        raise ValueError('preset.unknown_key: ' + ', '.join(sorted(unknown)))
    catalog = catalog_sources()
    return {key: catalog[key] for key in names}


def catalog_view() -> list[dict]:
    """Serializable, read-only view of the catalog for the panel/API layer."""
    return [
        {
            "key": preset.key,
            "name": preset.name,
            "format": preset.format,
            "url": preset.url,
            "hosts": list(preset.hosts),
            "kind": preset.kind,
            "license": preset.license,
            "license_verified": preset.license_verified,
            "provenance": preset.provenance,
            "notes": preset.notes,
            "warning": preset.warning(),
        }
        for preset in sorted(CATALOG.values(), key=lambda p: p.key)
    ]


def sources_view(declared: list[dict], history: list[dict], *, now: float,
                 stale_after_seconds: int | None = None) -> list[dict]:
    """Read-only, secret-free status view of rule-set sources.

    ``declared`` is the contract's :class:`~vs_router.schema.RuleSetSource`
    list (name/format/url); ``history`` is the downloader's append-only update
    history. The two are joined by ``name`` and each row is reduced to
    ``name/format/url/kind/status/stale/last_attempt/last_success/sha256`` —
    never a secret, and never a fabricated value.

    Status is ``never`` for a declared source with no run, otherwise the last
    recorded status (``ok``/``failed``/``not_modified``). ``stale`` is computed
    from the last successful contact against ``stale_after_seconds``; a source
    that never succeeded (or a 304 that never followed a 200) is stale with an
    unknown age. Rows are sorted by name for a stable table.
    """
    from .rulesets import DEFAULT_STALE_AFTER_SECONDS, staleness
    threshold = DEFAULT_STALE_AFTER_SECONDS if stale_after_seconds is None else stale_after_seconds
    rows: dict[str, dict] = {}
    for entry in declared:
        name = entry.get("name")
        if not name:
            continue
        rows[name] = {
            "name": name, "format": entry.get("format"), "url": entry.get("url"),
            "kind": entry.get("kind", "rule_set"), "status": "never", "stale": True,
            "last_attempt": None, "last_success": None, "sha256": None,
            "declared": True,
        }
    for entry in history:
        name = entry.get("name")
        if not name:
            continue
        row = rows.get(name)
        if row is None:
            row = {"name": name, "format": None, "url": entry.get("url"),
                   "kind": entry.get("kind", "rule_set"), "status": "never",
                   "stale": True, "last_attempt": None, "last_success": None,
                   "sha256": None, "declared": False}
        if row.get("url") is None:
            row["url"] = entry.get("url")
        if not row.get("format") and entry.get("format"):
            row["format"] = entry["format"]
        if not row.get("kind") and entry.get("kind"):
            row["kind"] = entry["kind"]
        if entry.get("status"):
            row["status"] = entry["status"]
        row["last_attempt"] = entry.get("at")
        if entry.get("status") in ("ok", "not_modified"):
            row["last_success"] = entry.get("at")
            if entry.get("sha256"):
                row["sha256"] = entry["sha256"]
        rows[name] = row
    for row in rows.values():
        row["stale"] = staleness(now=now, last_success=row["last_success"],
                                 stale_after_seconds=threshold).stale
    return sorted(rows.values(), key=lambda r: r["name"])
