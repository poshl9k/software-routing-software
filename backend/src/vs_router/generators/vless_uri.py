"""Share link for a subscriber inbound (ADR-0034); deterministic, I/O-free.

The URI is the contract between this host and an App Store client, so it is
built from the same fields the generator puts into the engine config — one
source of truth, no hand-assembled strings in the panel.
"""
import re
import uuid as uuid_module
from ipaddress import ip_address
from urllib.parse import quote

from vs_router.schema import Inbound

#: XTLS-Vision is the flow the inbound renders; clients must be told explicitly
#: or Reality falls back to plain TLS-in-TLS and the connection is refused.
VLESS_FLOW = "xtls-rprx-vision"


HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _valid_host(host: str) -> str:
    """Accept an address or a plain hostname; a URI fragment is never a host."""
    bare = host.strip("[]")
    try:
        ip_address(bare)
    except ValueError:
        if not HOSTNAME.fullmatch(bare):
            raise ValueError("inbound.entry_host") from None
    return bare


def _hostport(host: str, port: int) -> str:
    bare = host.strip("[]")
    return f"[{bare}]:{port}" if ":" in bare else f"{bare}:{port}"


def vless_uri(inbound: Inbound, uuid: str, host: str, name: str | None = None) -> str:
    """Build ``vless://`` for one subscriber device on ``inbound``.

    ``host`` is the address the client dials (public entry), never a loopback
    one: the server half of ``handshake_dest`` belongs to the host, not to the
    client. ``pyal``/``sni``/``sid``/``pbk`` mirror the Reality parameters; a
    missing short id is a contract error rather than a silently weaker link.
    """
    if not inbound.short_ids:
        raise ValueError("inbound.short_ids_required")
    host = _valid_host(host)
    query = {
        "encryption": "none",
        "security": "reality",
        "sni": inbound.server_name,
        "fp": "chrome",
        "pbk": inbound.public_key,
        "sid": inbound.short_ids[0],
        "type": "tcp",
        "headerType": "none",
        "flow": inbound.flow or VLESS_FLOW,
    }
    label = quote(name or inbound.tag, safe="")
    # Base64url padding of the Reality key must reach the client verbatim:
    # percent-escaping ``=`` makes several clients reject the link.
    pairs = "&".join(f"{key}={quote(str(value), safe='-_=')}" for key, value in query.items())
    return (f"vless://{quote(uuid, safe='')}@{_hostport(host, inbound.listen_port)}"
            f"?{pairs}#{label}")


#: Fixed namespace for device credentials. Deriving the UUID from the device's
#: public key means the node and the master agree without either of them
#: transferring or storing an extra secret, and deleting the device (and its
#: peer) removes the credential at the same moment. Rotating it is a new keypair.
DEVICE_NAMESPACE = uuid_module.UUID('6d1b8b1a-4f7e-5e0d-9f2a-3b6c1d7e8a90')


def device_uuid(public_key: str) -> str:
    """Deterministic VLESS UUID for a subscriber device's public key."""
    value = (public_key or "").strip()
    if not value:
        raise ValueError("inbound.device_key_required")
    return str(uuid_module.uuid5(DEVICE_NAMESPACE, value))
