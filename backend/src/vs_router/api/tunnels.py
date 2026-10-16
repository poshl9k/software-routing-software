"""QR and file export of tunnel peer configs, plus peer activity telemetry."""
from io import BytesIO
from ipaddress import ip_address, ip_interface

import qrcode
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ConfigurationRow
from ..generators.amnezia import amnezia_uri
from ..generators.wireguard import generate_wg_bundle
from .auth import current_user, get_db
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])

# The app resolves the inner config's DNS placeholders from these. The panel
# does not serve DNS on the tunnel yet (its resolver is a local stub), so a
# public pair is advertised — pointing a client at an address nobody answers on
# leaves it with no name resolution at all. ADR-0020 replaces this with the
# subscriber resolver.
DEFAULT_PRIMARY_DNS = '1.0.0.1'
DEFAULT_SECONDARY_DNS = '1.1.1.1'


def _public_endpoint() -> str | None:
    """The address clients should dial: the panel's published name, else its IP.

    Read from the agent's management record. Without it an export is only a
    fill-in template (the tunnel's own endpoint is often unset on a DHCP uplink),
    so it is worth one RPC. A host without a port gets the listen port appended
    by the generator.
    """
    try:
        state = agent_call('management', {})
    except Exception:
        return None
    if not isinstance(state, dict):
        return None
    hostname = state.get('hostname')
    if isinstance(hostname, str) and hostname.strip():
        return hostname
    address = state.get('address')
    if isinstance(address, str) and address:
        try:
            return str(ip_interface(address).ip)
        except ValueError:
            return None
    return None


def _peer_conf(db: Session, name: str, peer_name: str) -> str:
    """The peer's client config, generated exactly as the QR encodes it."""
    row = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if not row:
        raise APIError(404, 'tunnel.not_found')
    try:
        snapshot = row.snapshot()
        endpoint = _public_endpoint()
        # An endpoint the operator set is intentional and wins; the panel's own
        # published address only fills the gap where none was configured.
        metadata = ({t.name: {'endpoint': endpoint}
                     for t in snapshot.configuration.tunnels if endpoint and not t.endpoint}
                    if endpoint else {})
        content = generate_wg_bundle(snapshot, metadata).get(f'{name}.peer-{peer_name}.conf')
    except (ValueError, KeyError):
        content = None
    if content is None:
        raise APIError(404, 'peer.not_found')
    return content


@router.get('/tunnels/{name}/peer/{peer_name}/qr')
def qr(name: str, peer_name: str, db: Session = Depends(get_db)):
    image = qrcode.make(_peer_conf(db, name, peer_name))
    out = BytesIO()
    image.save(out, format='PNG')
    return Response(out.getvalue(), media_type='image/png')


@router.get('/tunnels/{name}/peer/{peer_name}/conf')
def peer_conf(name: str, peer_name: str, db: Session = Depends(get_db)):
    """Download the same client config the QR encodes, as a .conf file."""
    return Response(
        _peer_conf(db, name, peer_name),
        media_type='text/plain; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{name}-{peer_name}.conf"'},
    )


@router.get('/tunnels/activity')
def activity(db: Session = Depends(get_db)) -> dict[str, dict[str, int | None]]:
    """Latest handshake time per peer, keyed by tunnel then peer name.

    Read-only telemetry. A peer the panel has configured but that never
    handshaked reports 0, not a missing entry, so the panel can say "no
    activity" instead of showing nothing.
    """
    row = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if not row:
        return {}
    try:
        snapshot = row.snapshot()
    except (ValueError, KeyError):
        return {}
    try:
        live = agent_call('tunnel_activity', {})
    except Exception:
        # Telemetry only: an unreachable agent must not fail the screen.
        live = {}
    if not isinstance(live, dict):
        live = {}
    result: dict[str, dict[str, int | None]] = {}
    for tunnel in snapshot.configuration.tunnels:
        handshakes = {peer.get('public_key'): peer.get('latest_handshake')
                      for peer in live.get(tunnel.interface, []) or []
                      if isinstance(peer, dict)}
        result[tunnel.name] = {peer.name: handshakes.get(peer.public_key)
                               for peer in tunnel.peers}
    return result


def _amnezia_uri(db: Session, name: str, peer_name: str,
                 dns1: str | None, dns2: str | None) -> str:
    """The Amnezia `vpn://` document for one peer, or an APIError explaining why not."""
    row = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if not row:
        raise APIError(404, 'tunnel.not_found')
    try:
        snapshot = row.snapshot()
    except (ValueError, KeyError):
        raise APIError(404, 'tunnel.not_found') from None
    tunnel = next((t for t in snapshot.configuration.tunnels if t.name == name), None)
    peer = next((p for p in tunnel.peers if p.name == peer_name), None) if tunnel else None
    if peer is None or tunnel is None:
        raise APIError(404, 'peer.not_found')
    primary = dns1 or DEFAULT_PRIMARY_DNS
    for value in (primary, dns2 or DEFAULT_SECONDARY_DNS):
        try:
            ip_address(value)
        except ValueError:
            raise APIError(400, 'amnezia.invalid_dns') from None
    try:
        # A configured endpoint wins; otherwise the panel's published address
        # fills the gap (a DHCP uplink leaves the tunnel's own endpoint unset).
        return amnezia_uri(tunnel, peer, snapshot.configuration,
                           endpoint=None if tunnel.endpoint else _public_endpoint(),
                           dns1=primary, dns2=dns2 or DEFAULT_SECONDARY_DNS)
    except ValueError as error:
        raise APIError(400, str(error)) from error


@router.get('/tunnels/{name}/peer/{peer_name}/amnezia')
def peer_amnezia(name: str, peer_name: str, dns1: str | None = None, dns2: str | None = None,
                 db: Session = Depends(get_db)):
    """The peer as an Amnezia `vpn://` document the app imports natively."""
    return Response(
        _amnezia_uri(db, name, peer_name, dns1, dns2),
        media_type='text/plain; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{name}-{peer_name}.vpn"'},
    )


@router.get('/tunnels/{name}/peer/{peer_name}/amnezia/qr')
def peer_amnezia_qr(name: str, peer_name: str, dns1: str | None = None, dns2: str | None = None,
                    db: Session = Depends(get_db)):
    image = qrcode.make(_amnezia_uri(db, name, peer_name, dns1, dns2))
    out = BytesIO()
    image.save(out, format='PNG')
    return Response(out.getvalue(), media_type='image/png')
