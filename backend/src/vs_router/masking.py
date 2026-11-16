"""AmneziaWG 3+ signature packets (I1-I5): strict validation and ready masks.

Before every handshake a client sends up to five UDP packets (I1..I5) that the
server discards. A packet is built from tags:

    <b 0xHEX>  fixed bytes          <r N>   N random bytes
    <rc N>     N random letters     <rd N>  N random digits
    <t>        time, 4 bytes (big-endian)

Only these five tags are understood by both amneziawg-go and the kernel
module: <c> exists only in the kernel module, <d>/<ds>/<dz> only in
amneziawg-go, so a packet carrying a foreign tag keeps the other side from
starting. Validation therefore accepts only the portable set and rejects
anything else before it reaches a tunnel.

The masks below mimic the beginnings of real protocols (a DNS response,
STUN, QUIC Initial, SIP INVITE); the variable fields (IDs, names, keys) are
random tags, so no two handshakes carry the same bytes - which is the point:
a DPI probe sees a plausible protocol, not a repeated fingerprint. The
masks are pure functions of their arguments (the randomness lives in the
tags, resolved per packet by the tunnel device), so generation stays
deterministic and free of I/O like every other generator.
"""
from __future__ import annotations

import re
from ipaddress import IPv4Address, ip_address

#: The five signature packets, in the order the config emits them.
KEYS = ("I1", "I2", "I3", "I4", "I5")

#: Tags both amneziawg-go and the kernel module understand.
PORTABLE = frozenset({"b", "r", "rc", "rd", "t"})
#: Tags only one implementation understands; a packet with them is not portable.
ENGINE_ONLY = frozenset({"c", "d", "ds", "dz"})

#: A packet longer than this fragments at almost any path (MTU 1500 minus
#: headers); 1200 is the QUIC Initial floor and also the friendly warning mark.
MAX_PACKET = 1400
WARN_PACKET = 1200
MAX_TAG = 1400

TOKEN_RE = re.compile(r"<[^<>]*>|[^<>\s]+|[<>]")
HEX_RE = re.compile(r"^0x((?:[0-9a-fA-F]{2})+)$")
# A DNS name: ASCII labels a-z0-9- (1-63 bytes), dot-separated, at most 255
# bytes of wire form. Punycode names must be supplied in ASCII form already.
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def packet_size(value: str, key: str = "I1") -> int:
    """The packet's byte length; ``ValueError`` with a stable code if it cannot
    be emitted to a client (a non-tag token, an unknown tag, an oversized one)."""
    total = 0
    for token in TOKEN_RE.findall(value or ""):
        if not (token.startswith("<") and token.endswith(">") and len(token) > 2):
            raise ValueError("tunnel.awg_signature_text")
        name, _, arg = token[1:-1].strip().partition(" ")
        name, arg = name.lower(), arg.strip()
        if name in ENGINE_ONLY:
            raise ValueError("tunnel.awg_signature_unsupported")
        if name not in PORTABLE:
            raise ValueError("tunnel.awg_signature_tag")
        if name == "b":
            match = HEX_RE.match(arg)
            if not match:
                raise ValueError("tunnel.awg_signature_hex")
            total += len(match.group(1)) // 2
        elif name == "t":
            if arg:
                raise ValueError("tunnel.awg_signature_number")
            total += 4
        else:
            if not arg.isdigit() or not 1 <= int(arg) <= MAX_TAG:
                raise ValueError("tunnel.awg_signature_number")
            total += int(arg)
    if total > MAX_PACKET:
        raise ValueError("tunnel.awg_signature_size")
    return total


def normalize(value) -> str:
    """Whitespace-collapsed packet text; empty means the packet is absent."""
    return " ".join(str(value or "").split())


def validate(value, key: str = "I1") -> str:
    """One signature packet, normalized and size-checked."""
    packet = normalize(value)
    if packet:
        packet_size(packet, key)
    return packet


def validate_set(values: dict) -> dict[str, str]:
    """{I1..I5: value} -> normalized values, every packet checked."""
    return {key: validate(values.get(key), key) for key in KEYS}


# ------------------------------------------------------------------ masks
def _b(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode()
    return f"<b 0x{raw.hex()}>"


def _labels(host: str) -> tuple[bytes, bytes]:
    """A dotted name as (first length byte, remaining labels + root).

    The caller emits the first length byte before the first (possibly random)
    label, exactly like the wire form of a DNS question. A one-label name gets
    an empty remainder: the root byte travels with the tail.
    """
    labels = host.rstrip(".").split(".")
    raw = b"".join(bytes([len(label)]) + label.encode() for label in labels)
    return raw[:1], raw[1:] + b"\x00"


def _dns_name(host: str | None) -> tuple[bytes, str, bytes]:
    """The question's name as (first length byte, random-label tag, remaining
    labels). A custom name is fixed on the wire; without one the first label is
    12 random letters under .com, so the tag keeps the handshake variable."""
    if host is None:
        return b"\x0c", "<rc 12>", b"\x03com\x00"
    first, rest = _labels(host)
    return first, "", rest


def _dns_query(name: tuple[bytes, str, bytes]) -> str:
    """RFC 1035 query for an A record + EDNS0 (RFC 6891, UDP 1232) padded with
    the padding option (RFC 7830) up to 128 bytes, as modern resolvers do
    (RFC 8467). Only the transaction ID is random: <r 2>."""
    head = bytes.fromhex("0100" "0001" "0000" "0000" "0001")
    first, random_label, rest = name
    # 2 (ID) + 10 (header) + 1 (first length byte) + the random label
    # + 4 (qtype+qclass) + 11 (opt up to rdlength) + 4 (option code + length).
    fixed = (2 + len(head) + len(first) + (12 if random_label else 0)
             + len(rest) + 4 + 11 + 4)
    pad = 128 - fixed
    if pad > 0:
        opt = (b"\x00" + bytes.fromhex("0029" "04d0" "00" "00" "0000")
               + (4 + pad).to_bytes(2, "big") + bytes.fromhex("000c")
               + pad.to_bytes(2, "big") + bytes(pad))
    else:
        opt = b"\x00" + bytes.fromhex("0029" "04d0" "00" "00" "0000" "0000")
    return ("<r 2>" + _b(head + first) + random_label
            + _b(rest + bytes.fromhex("00010001") + opt))


def _sip() -> str:
    """RFC 3261 INVITE without a body; numbers, domains, branch, tag and
    Call-ID are random."""
    crlf = "\r\n"
    return ("".join([
        _b("INVITE sip:"), "<rd 10>", _b("@"), "<rc 8>", _b(".com SIP/2.0" + crlf),
        _b("Via: SIP/2.0/UDP 192.168.1."), "<rd 2>", _b(":5060;branch=z9hG4bK"), "<rc 16>",
        _b(crlf + "Max-Forwards: 70" + crlf + "From: <sip:"), "<rd 10>", _b("@"), "<rc 8>",
        _b(".com>;tag="), "<rc 10>", _b(crlf + "To: <sip:"), "<rd 10>", _b("@"), "<rc 8>",
        _b(".com>" + crlf + "Call-ID: "), "<rc 24>",
        _b(crlf + "CSeq: 1 INVITE" + crlf + "Contact: <sip:"), "<rd 10>", _b("@192.168.1."), "<rd 2>",
        _b(":5060>" + crlf + "Content-Length: 0" + crlf + crlf)]))


def _stun() -> str:
    """RFC 8489/8445: the ICE Binding Request a WebRTC call opens with
    (browsers, messengers). Attributes: USERNAME "ufrag:ufrag" (9 bytes plus
    3 alignment bytes), ICE-CONTROLLING, PRIORITY, MESSAGE-INTEGRITY,
    FINGERPRINT; the transaction ID and the values are random."""
    attrs_len = (4 + 12) + (4 + 8) + (4 + 4) + (4 + 20) + (4 + 4)
    return (_b(bytes.fromhex("0001") + attrs_len.to_bytes(2, "big") + bytes.fromhex("2112a442")) + "<r 12>"
            + _b(bytes.fromhex("00060009")) + "<rc 4>" + _b(":") + "<rc 4>" + _b(bytes(3))
            + _b(bytes.fromhex("802a0008")) + "<r 8>"
            + _b(bytes.fromhex("00240004")) + "<r 4>"
            + _b(bytes.fromhex("00080014")) + "<r 20>"
            + _b(bytes.fromhex("80280004")) + "<r 4>")


def _quic() -> str:
    """RFC 9000 Initial: 0b11000011 (long header, Initial, 4-byte packet
    number), version 1, 8-byte DCID, empty SCID (as Chrome sends), empty token,
    length of the rest (2-byte varint). The packet number and the encrypted
    payload are random bytes on the wire. The first client QUIC packet is at
    least 1200 bytes by standard; a shorter one betrays the disguise."""
    rest = 1200 - 18
    return (_b(bytes.fromhex("c300000001") + b"\x08") + "<r 8>"
            + _b(b"\x00\x00" + (0x4000 | rest).to_bytes(2, "big")) + f"<r {rest}>")


def dns_response(host: str = "icloud.com", ip: str = "17.253.144.10") -> str:
    """RFC 1035 response of a recursive resolver (QR, RD, RA) to an A query for
    ``host`` with EDNS0 (RFC 6891, UDP 1232, like the question in the "dns
    query" mask). The address is the real address of ``host``; the ID and the
    remaining TTL (up to 65535 s) are random.

    The default mimics the packet the AmneziaVPN app puts in its own configs -
    except that the app's copy answers icloud.com with a Yandex address
    (77.88.55.55), which is the same on every server and an easy DPI mark.
    """
    try:
        addr = ip_address(ip)
    except ValueError:
        raise ValueError("tunnel.awg_masking_ip") from None
    if addr.version != 4:
        raise ValueError("tunnel.awg_masking_ip")
    name = _labels(host)
    return ("<r 2>" + _b(bytes.fromhex("8180" "0001" "0001" "0000" "0001")
                         + name[0] + name[1] + bytes.fromhex("00010001")
                         + bytes.fromhex("c00c" "0001" "0001" "0000"))
            + "<r 2>" + _b(bytes.fromhex("0004") + IPv4Address(addr).packed
                           + b"\x00" + bytes.fromhex("0029" "04d0" "00" "00" "0000" "0000")))


#: The I1 AmneziaVPN itself puts in: the same on every server (only the 2 ID
#: bytes vary), and it answers icloud.com with the Yandex address. Kept for
#: diagnostics - a tunnel whose I1 equals this is leaking a shared fingerprint.
AMNEZIA_I1 = ("<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c0001000100"
              "00105a00044d583737>")


def is_amnezia(value: str) -> bool:
    """The I1 packet every AmneziaVPN server shares."""
    return normalize(value) == AMNEZIA_I1


PRESETS = ("icloud", "stun", "quic", "dns", "sip", "none")


def check_host(host: str) -> str:
    """A custom mask host: lowercase ASCII DNS name (labels 1-63 bytes, name
    up to 255 bytes on the wire)."""
    name = str(host or "").strip().lower().rstrip(".")
    if not name or len(name) > 253:
        raise ValueError("tunnel.awg_masking_host")
    labels = name.split(".")
    if any(not LABEL_RE.match(label) for label in labels):
        raise ValueError("tunnel.awg_masking_host")
    return name


def preset(name: str, host: str | None = None, ip: str | None = None) -> dict[str, str]:
    """One ready mask as {I1..I5: value} (empty value - no packet).

    ``host``/``ip`` customize the DNS masks: the question asks for ``host``,
    the response answers ``host`` with ``ip``. The defaults mimic the
    AmneziaVPN packet with the real Apple address.
    """
    host = check_host(host) if host is not None else None
    if name == "icloud":
        value = dns_response(host or "icloud.com", ip or "17.253.144.10")
    elif name == "dns":
        value = _dns_query(_dns_name(host))
    elif name == "stun":
        value = _stun()
    elif name == "quic":
        value = _quic()
    elif name == "sip":
        value = _sip()
    elif name == "none":
        value = ""
    else:
        raise ValueError("tunnel.awg_masking_preset")
    packet = validate(value, "I1")
    return {key: packet if key == "I1" else "" for key in KEYS}


def catalog() -> list[dict]:
    """The masks for the browser: values and packet sizes."""
    out = []
    for name in PRESETS:
        values = preset(name)
        sizes = {key: packet_size(value, key) for key, value in values.items() if value}
        out.append({"id": name, "values": values, "sizes": sizes})
    return out
