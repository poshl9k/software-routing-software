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


@router.get('/host/addresses')
def addresses() -> dict[str, list[str]]:
    """Live IPv4 addresses per interface (desired state is in the draft)."""
    try:
        return agent_call('list_addresses', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'host.interfaces_unavailable') from None
