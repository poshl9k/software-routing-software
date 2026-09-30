"""Read-only host interface inventory via the agent."""
from fastapi import APIRouter, Depends

from .auth import current_user
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


@router.get('/host/interfaces')
def interfaces() -> list[dict[str, str | None]]:
    try:
        return agent_call('list_interfaces', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'host.interfaces_unavailable') from None
