"""Read-only rule-set source contract for the panel, plus a manual update.

The agent downloader owns fetching, SSRF policy, format validation and status.
The web process never fetches: ``GET /api/rulesets`` joins the *declared* sources
from the draft contract with the agent's own ``source_status`` history, and
``POST /api/rulesets/update`` forwards a typed, whitelisted ``update_source``
RPC. No secrets exist in a rule-set source, so nothing needs redaction here.

``GET`` is available to any authenticated user (so an operator can view the
list); the privileged ``update`` is admin-only.
"""
from fastapi import APIRouter, Body, Depends, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agent.presets import sources_view, load_catalog, service_rule_set_format
from ..agent.rpc import UpdateSourceParams
from ..db import ConfigurationRow
from .auth import admin, current_user, get_db
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


def _declared(db: Session) -> list[dict]:
    """Declared rule-set sources from the single draft, if one exists."""
    row = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == "draft"))
    if row is None:
        return []
    return [source.model_dump(mode="json")
            for source in row.snapshot().configuration.rule_sets]


def _history() -> list[dict]:
    """Agent-owned update history. A down agent is an honest 503, not a lie."""
    try:
        return agent_call("source_status", {}) or []
    except APIError:
        raise
    except Exception:
        raise APIError(503, "ruleset.status_unavailable") from None


@router.get("/rulesets")
def list_rulesets(response: Response, db: Session = Depends(get_db)) -> list[dict]:
    """Read-only: declared sources joined with the agent's status/staleness."""
    import time
    response.headers["Cache-Control"] = "no-store"
    return sources_view(_declared(db), _history(), now=time.time())


@router.get("/presets/catalog")
def list_preset_catalog(response: Response, db: Session = Depends(get_db)) -> dict:
    """Read-only catalog; category counts exclude the six composite entries.

    Composite services remain in ``services`` with their ``covers`` intact.
    Only the draft configuration is considered declared, as in /api/rulesets.
    """
    response.headers["Cache-Control"] = "no-store"
    declared = {entry["name"] for entry in _declared(db)}
    titles = {
        "social": "Соцсети", "media": "Медиа", "developer": "Разработка",
        "cloud": "Облако", "gaming": "Игры", "ai": "AI", "block": "Блок",
    }
    counts = {key: 0 for key in titles}
    services = []
    for preset in load_catalog():
        if not preset.covers:
            counts[preset.category] += 1
        services.append({
            "id": preset.id, "name": preset.name, "category": preset.category,
            "icon_slug": preset.icon_slug, "notice": preset.notice,
            "covers": list(preset.covers), "dns_domains": list(preset.dns_domains),
            "rule_sets": [
                {"tag": source.tag, "url": source.url,
                 "format": service_rule_set_format(source.url)}
                for source in preset.rule_sets
            ],
            "action": preset.action,
            "declared": all(source.tag in declared for source in preset.rule_sets),
        })
    return {"categories": [
        {"key": key, "title": title, "count": counts[key]}
        for key, title in titles.items()
    ], "services": services}


@router.post("/rulesets/update", dependencies=[Depends(admin)])
def update_ruleset(body: UpdateSourceParams = Body()) -> dict:
    """Run one manual update through the typed agent RPC (never a shell)."""
    return agent_call("update_source", body)
