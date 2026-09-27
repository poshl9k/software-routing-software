"""Generate WireGuard and preshared keys for authenticated users."""
import base64
import secrets
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from .auth import current_user

router = APIRouter(dependencies=[Depends(current_user)])


class TunnelKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["wg", "awg"]


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


@router.post("/keygen/tunnel")
def generate_tunnel_keys(body: TunnelKeyRequest):
    private = X25519PrivateKey.generate()
    result = {
        "private_key": _b64(private.private_bytes_raw()),
        "public_key": _b64(private.public_key().public_bytes_raw()),
    }
    if body.protocol == "awg":
        jmin, jmax = sorted(secrets.SystemRandom().sample(range(30, 121), 2))
        result["obfuscation"] = {
            "Jc": secrets.randbelow(8) + 3,
            "Jmin": jmin,
            "Jmax": jmax,
            "S1": secrets.randbelow(21) + 10,
            "S2": secrets.randbelow(41) + 80,
            **dict(zip(("H1", "H2", "H3", "H4"), secrets.SystemRandom().sample(range(5, 2_147_483_648), 4))),
        }
    return result


@router.post("/keygen/peer")
def generate_peer_key():
    return {"preshared_key": _b64(secrets.token_bytes(32))}


@router.post("/keygen/peer-keypair")
def generate_peer_keypair():
    """Full peer pair for panel-generated client configs: the private key is
    returned once and stored encrypted with the draft; the public key lands
    in the tunnel's peer list."""
    private = X25519PrivateKey.generate()
    return {"private_key": _b64(private.private_bytes_raw()),
            "public_key": _b64(private.public_key().public_bytes_raw())}
