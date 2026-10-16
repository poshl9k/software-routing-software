"""QR and file export of tunnel peer configs, plus peer activity telemetry."""
from io import BytesIO

import qrcode
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import ConfigurationRow
from ..generators.wireguard import generate_wg_bundle
from .auth import current_user, get_db
from .errors import APIError
from .versions import agent_call

router = APIRouter(dependencies=[Depends(current_user)])


def _peer_conf(db: Session, name: str, peer_name: str) -> str:
    """The peer's client config, generated exactly as the QR encodes it."""
    row = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if not row:
        raise APIError(404, 'tunnel.not_found')
    try:
        content = generate_wg_bundle(row.snapshot(), {}).get(f'{name}.peer-{peer_name}.conf')
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
