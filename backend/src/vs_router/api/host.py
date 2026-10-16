"""Host inventory reads and the panel-publication write (ADR-0025)."""
from fastapi import APIRouter, Depends

from ..agent.rpc import PanelDomainParams
from .auth import admin, current_user
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


@router.get('/host/management')
def management() -> dict | None:
    """The management record so the wizard knows if this is a one-NIC host."""
    try:
        return agent_call('management', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'host.interfaces_unavailable') from None


@router.put('/host/panel-domain', dependencies=[Depends(admin)])
def panel_domain(body: PanelDomainParams) -> dict:
    """Publish the panel under a public name, or clear it (ADR-0025).

    Admin-only: it moves where the administrator reaches the panel. The agent
    keeps the change only once an ACME certificate answers over HTTPS.
    """
    try:
        return agent_call('set_panel_domain', body)
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
