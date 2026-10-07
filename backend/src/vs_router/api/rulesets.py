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

from ..agent.presets import sources_view
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


@router.post("/rulesets/update", dependencies=[Depends(admin)])
def update_ruleset(body: UpdateSourceParams = Body()) -> dict:
    """Run one manual update through the typed agent RPC (never a shell)."""
    return agent_call("update_source", body)
