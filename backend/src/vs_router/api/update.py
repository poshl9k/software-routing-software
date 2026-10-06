"""Online release update: read-only status and a privileged apply (ADR-0010).

`GET /api/update` compares the installed release with the host-configured
manifest (read-only). `POST /api/update` starts a pinned, verified update through
the privileged agent; it is admin-only and never accepts a branch or `latest`.
"""
from fastapi import APIRouter, Body, Depends, Response

from ..agent.rpc import ApplyUpdateParams
from .auth import admin
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(admin)])


@router.get('/update')
def update_status(response: Response) -> dict:
    """Read-only: the installed release versus the published one."""
    response.headers['Cache-Control'] = 'no-store'
    try:
        return agent_call('update_status', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'update.status_unavailable') from None


@router.post('/update')
def apply_update(body: ApplyUpdateParams = Body()) -> dict:
    """Start a pinned, verified update (privileged, detached, admin-only)."""
    try:
        return agent_call('apply_update', body)
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'update.apply_unavailable') from None
