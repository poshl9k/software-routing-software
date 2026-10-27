"""Generate WireGuard and preshared keys for authenticated users."""
import base64
import secrets
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from .auth import current_user

router = APIRouter(dependencies=[Depends(current_user)])

# A server tunnel on the default AWG ports is a fingerprint of its own; the
# Amnezia app flags 51820/51821 and tells the operator to move the server.
DEFAULT_AWG_PORT = 51820
RESERVED_PORTS = (DEFAULT_AWG_PORT, 51821)
PORT_RANGE = (20000, 60000)


class TunnelKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["wg", "awg"]


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _span(rng, low: int, high: int, width: tuple[int, int]) -> str:
    """A `min-max` range: AWG 3+ accepts a range wherever it accepted one value,
    which is what the protocol's own obfuscation profiles use."""
    start = rng.randint(low, high)
    return f"{start}-{start + rng.randint(*width)}"


def suggest_port(rng=None) -> int:
    """A UDP port for a server tunnel, avoiding the well-known AWG defaults."""
    rng = rng or secrets.SystemRandom()
    low, high = PORT_RANGE
    while True:
        port = rng.randint(low, high)
        if port not in RESERVED_PORTS:
            return port


def awg_profile(rng=None) -> dict:
    """The full AmneziaWG 3+ obfuscation set, randomised per tunnel.

    Every parameter the protocol offers, not only the classic Jc/S1/S2/H1-H4
    core: S3/S4, signature packets, header protection, content padding, the
    timing ranges and the trailer/cookie toggles. Header protection requires
    S1-S4 >= 12 (amneziawg-go), so nothing is generated below that. Randomising
    each install keeps two servers from sharing a fingerprint, which is the
    point of the protocol.
    """
    rng = rng or secrets.SystemRandom()
    jmin = rng.randint(8, 64)
    # Amnezia recommendation for AWG 3.1: with RandomTrailers on, S1-S4 must be
    # equal and >= 12 (header-protection floor). They are also capped at 32:
    # S4 pads every data packet, and a larger value fragments a full-size
    # packet at any MTU below ~1500, which collapses throughput (measured on
    # lab hosts: ~0.4 Mbit/s at the default 1420 with S4 > 20).
    s_value = rng.randint(12, 32)
    profile = {
        "Jc": rng.randint(4, 12),
        "Jmin": jmin,
        "Jmax": jmin + rng.randint(16, 64),
        "S1": s_value,
        "S2": s_value,
        "S3": s_value,
        "S4": s_value,
        "I1": f"<b 0x{rng.randbytes(6).hex()}><r {rng.randint(2, 6)}>",
        "I2": f"<rd {rng.randint(4, 10)}><b 0x{rng.randbytes(4).hex()}>",
        "I3": f"<r {rng.randint(3, 9)}><t>",
        "I4": f"<b 0x{rng.randbytes(8).hex()}>",
        "I5": f"<rc {rng.randint(4, 12)}><rd {rng.randint(2, 6)}>",
        # ContentPaddingAddition is deliberately absent: together with
        # RandomTrailers it is the worst combination — it defeats trailer
        # obfuscation on the send path while keeping the receiver's loose
        # matching, and its randomised per-packet length defeats UDP GRO
        # batching (~22% of download, measured upstream).
        "RekeyAfterTime": _span(rng, 90, 150, (10, 40)),
        "RekeyTimeout": _span(rng, 2, 5, (2, 5)),
        "RejectAfterTime": _span(rng, 130, 200, (20, 60)),
        "KeepaliveTimeout": _span(rng, 5, 15, (5, 15)),
        "MaxHandshakeAttempts": _span(rng, 10, 20, (3, 10)),
    }
    for key, value in zip(("H1", "H2", "H3", "H4"), rng.sample(range(5, 2_147_483_648), 4)):
        profile[key] = value
    profile["HeaderProtectionKey"] = _b64(rng.randbytes(32))
    return profile


@router.post("/keygen/tunnel")
def generate_tunnel_keys(body: TunnelKeyRequest):
    rng = secrets.SystemRandom()
    private = X25519PrivateKey.generate()
    result: dict = {
        "private_key": _b64(private.private_bytes_raw()),
        "public_key": _b64(private.public_key().public_bytes_raw()),
    }
    if body.protocol == "awg":
        result["obfuscation"] = awg_profile()
        result["header_protection_key"] = result["obfuscation"].pop("HeaderProtectionKey")
        result["random_trailers"] = True
        result["disable_cookies"] = True
        result["listen_port"] = suggest_port()
        # AWG 3+ obfuscation consumes tunnel-MTU headroom before the outer UDP
        # packet is built; 1200 leaves room for paddings at any common WAN MTU.
        result["mtu"] = 1200
    # A creation-time random subnet instead of the name-derived pool slot: two
    # independently managed panels must not correlate on the same 10.66.x.0/24
    # (cross-host tunnel overlap is a silent blackhole). The picked subnet is
    # stored as the tunnel device's explicit address on save, and explicit
    # values always win afterwards.
    result["subnet"] = f"10.66.{rng.randint(0, 255)}.0/24"
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
