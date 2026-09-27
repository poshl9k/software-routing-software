"""QR export of tunnel peer configs (PNG)."""
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

router = APIRouter(dependencies=[Depends(current_user)])


@router.get('/tunnels/{name}/peer/{peer_name}/qr')
def qr(name: str, peer_name: str, db: Session = Depends(get_db)):
    row = db.scalars(select(ConfigurationRow).order_by(ConfigurationRow.id.desc())).first()
    if not row:
        raise APIError(404, 'tunnel.not_found')
    try:
        content = generate_wg_bundle(row.snapshot(), {}).get(f'{name}.peer-{peer_name}.conf')
    except (ValueError, KeyError):
        content = None
    if content is None:
        raise APIError(404, 'peer.not_found')
    image = qrcode.make(content)
    out = BytesIO()
    image.save(out, format='PNG')
    return Response(out.getvalue(), media_type='image/png')
