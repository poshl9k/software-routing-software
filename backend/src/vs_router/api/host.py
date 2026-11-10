"""Host inventory reads and host-owned publication writes."""
from ipaddress import ip_address

from fastapi import APIRouter, Depends, Response
from pydantic import Field, SecretStr, StrictStr, field_validator
from sqlalchemy.orm import Session

from ..agent.rpc import MasterBridgePublicationParams, PanelDomainParams
from ..db import MasterBridgeSetting
from ..management import HOSTNAME_PATTERN
from ..master_bridge_bootstrap import store_token
from ..schema import Model
from .auth import admin, current_user, get_db
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


class MasterBridgeSetup(Model):
    """One-time bridge token handoff through the node's authenticated admin UI."""
    token: SecretStr
    hostname: StrictStr = Field(pattern=HOSTNAME_PATTERN)
    source_ip: StrictStr = Field(min_length=3, max_length=45)

    @field_validator('token')
    @classmethod
    def valid_token(cls, value):
        token = value.get_secret_value()
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
        if len(token) != 43 or any(char not in alphabet for char in token):
            raise ValueError('master_bridge.token_invalid')
        return value

    @field_validator('source_ip')
    @classmethod
    def valid_source_ip(cls, value):
        try:
            return str(ip_address(value))
        except ValueError:
            raise ValueError('master_bridge.source_ip_invalid') from None


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


@router.get('/host/profile')
def profile() -> dict:
    """Read the host-owned product marker and live DHCP capability."""
    try:
        return agent_call('profile', {})
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


def _master_bridge_credential_state(db: Session) -> tuple[bool, str]:
    row = db.get(MasterBridgeSetting, 'master_bridge_token')
    if row is None:
        return False, 'not_installed'
    if not isinstance(row.value, dict):
        return True, 'unknown'
    return True, ('pending_verification' if row.value.get('setup_pending') is True
                  else 'verified')


@router.get('/host/master-bridge', dependencies=[Depends(admin)])
def master_bridge_status(response: Response, db: Session = Depends(get_db)) -> dict[str, str | bool]:
    response.headers['Cache-Control'] = 'no-store'
    credential_installed, credential_state = _master_bridge_credential_state(db)
    try:
        result = agent_call('master_bridge_publication_status', {})
        state = result.get('publication_state')
        if state not in {'absent', 'configured_on_disk', 'drift', 'invalid_marker',
                         'incompatible', 'unavailable'}:
            state = 'unavailable'
    except Exception:
        state = 'unavailable'
    return {'credential_installed': credential_installed,
            'credential_state': credential_state, 'publication_state': state}


@router.post('/host/master-bridge', dependencies=[Depends(admin)])
def setup_master_bridge(body: MasterBridgeSetup, response: Response,
                        db: Session = Depends(get_db)) -> dict[str, str | bool]:
    """Store the master-issued credential, then publish the restricted Caddy route.

    Replaying the same token is safe: it lets the administrator retry publication
    after a lost response or an unavailable host agent. A different token can
    never replace an installed credential through this endpoint.
    """
    response.headers['Cache-Control'] = 'no-store'
    try:
        store_token(db, body.token.get_secret_value(), allow_same=True)
    except ValueError as exc:
        if str(exc) == 'master bridge token already installed':
            raise APIError(409, 'master_bridge.already_configured') from None
        raise APIError(422, 'master_bridge.token_invalid') from None
    try:
        publication = agent_call('set_master_bridge_publication',
                                 MasterBridgePublicationParams(
                                     hostname=body.hostname, source_ip=body.source_ip))
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'agent.unavailable') from None
    if not isinstance(publication, dict) or publication.get('published') is not True:
        raise APIError(503, 'master_bridge.publication_unavailable')
    _, credential_state = _master_bridge_credential_state(db)
    return {'credential_installed': True, 'credential_state': credential_state,
            'publication_state': 'configured_on_disk'}


@router.get('/host/addresses')
def addresses() -> dict[str, list[str]]:
    """Live IPv4 addresses per interface (desired state is in the draft)."""
    try:
        return agent_call('list_addresses', {})
    except APIError:
        raise
    except Exception:
        raise APIError(503, 'host.interfaces_unavailable') from None
