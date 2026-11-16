"""Signature packets I1-I5 (AWG 3+ masks): validation, presets and the tunnel contract.

The presets are byte-for-byte the masks of the AWG-Router panel (r-slashslash/AWG-Router,
app/cps.py): both panels then produce the same wire packets, and neither shares
AmneziaVPN's default fingerprint. The masks mimic the openings of real protocols
(a DNS response, STUN, QUIC Initial, SIP INVITE); the variable fields are random
tags resolved by the tunnel device per packet, so no two handshakes look alike.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from vs_router import masking
from vs_router.api import keygen
from vs_router.api.auth import current_user
from vs_router.api.errors import install_errors
from vs_router.schema import EncryptedSecret, Tunnel


@pytest.fixture
def client():
    # The keygen router alone: the full app import chain needs the Unix-only
    # agent daemon, which a Windows development host does not have. TestClient
    # keeps the test synchronous without an asyncio pytest plugin.
    app = FastAPI()
    install_errors(app)
    app.include_router(keygen.router)
    app.dependency_overrides[current_user] = lambda: None
    with TestClient(app) as c:
        yield c


def test_keygen_awg_masking_endpoint(client):
    # Ready I1-I5 masks: the same wire packets the AWG-Router panel emits, so a
    # client configured by either panel produces the same handshake bytes.
    mask = client.post("/keygen/awg-masking", json={"preset": "quic"}).json()
    assert mask["obfuscation"]["I1"] == REF_QUIC
    assert mask["sizes"] == {"I1": 1200}
    assert set(mask["obfuscation"]) == {"I1", "I2", "I3", "I4", "I5"}
    # A custom DNS answer: the question name and the real address travel in the packet.
    mask = client.post("/keygen/awg-masking",
                       json={"preset": "icloud", "host": "example.com",
                             "ip": "93.184.216.34"}).json()
    assert "5db8d822" in mask["obfuscation"]["I1"]
    # Unknown preset, bad host and bad ip are 422 with a stable code.
    for body in ({"preset": "smtp"}, {"preset": "icloud", "host": "X!"},
                 {"preset": "icloud", "ip": "::1"}, {"preset": "quic", "x": 1}):
        response = client.post("/keygen/awg-masking", json=body)
        assert response.status_code == 422
        assert set(response.json()) == {"code", "message", "details"}


# Golden masks, transcribed from the reference panel's builders.
REF_ICLOUD = ("<r 2><b 0x818000010001000000010669636c6f756403636f6d0000010001c00c000100010000><r 2><b 0"
              "x000411fd900a00002904d0000000000000>")
REF_STUN = ("<b 0x000100442112a442><r 12><b 0x00060009><rc 4><b 0x3a><rc 4><b 0x000000><b 0x802a0008>"
              "<r 8><b 0x00240004><r 4><b 0x00080014><r 20><b 0x80280004><r 4>")
REF_QUIC = ("<b 0xc30000000108><r 8><b 0x0000449e><r 1182>")
REF_DNS = ("<r 2><b 0x010000010000000000010c><rc 12><b 0x03636f6d000001000100002904d0000000000053000"
              "c004f00000000000000000000000000000000000000000000000000000000000000000000000000000000000"
              "000000000000000000000000000000000000000000000000000000000000000000000000000>")
REF_SIP = ("<b 0x494e56495445207369703a><rd 10><b 0x40><rc 8><b 0x2e636f6d205349502f322e300d0a><b 0x"
              "5669613a205349502f322e302f554450203139322e3136382e312e><rd 2><b 0x3a353036303b6272616e63"
              "683d7a39684734624b><rc 16><b 0x0d0a4d61782d466f7277617264733a2037300d0a46726f6d3a203c736"
              "9703a><rd 10><b 0x40><rc 8><b 0x2e636f6d3e3b7461673d><rc 10><b 0x0d0a546f3a203c7369703a>"
              "<rd 10><b 0x40><rc 8><b 0x2e636f6d3e0d0a43616c6c2d49443a20><rc 24><b 0x0d0a435365713a203"
              "120494e564954450d0a436f6e746163743a203c7369703a><rd 10><b 0x403139322e3136382e312e><rd 2"
              "><b 0x3a353036303e0d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>")

def test_validator_accepts_portable_tags():
    assert masking.packet_size("<r 2><b 0x8580>") == 4
    assert masking.packet_size("<t>") == 4
    assert masking.packet_size("<rc 12><rd 10>") == 22
    # Whitespace is noise on the wire: the size is the same either way.
    assert masking.packet_size(" <r 2>  <b 0x8580> ") == 4
    assert masking.validate(" <r 2> <b 0x8580> ", "I1") == "<r 2> <b 0x8580>"


def test_validator_rejects_foreign_and_broken():
    # A non-tag token is not a packet the device can emit.
    with pytest.raises(ValueError, match="tunnel.awg_signature_text"):
        masking.packet_size("hello world")
    # Only the portable tag set: <c> exists only in the kernel module,
    # <d>/<ds>/<dz> only in amneziawg-go - a packet with a foreign tag keeps
    # the other tunnel side from starting.
    with pytest.raises(ValueError, match="tunnel.awg_signature_unsupported"):
        masking.packet_size("<c 5>")
    with pytest.raises(ValueError, match="tunnel.awg_signature_unsupported"):
        masking.packet_size("<dz 5>")
    with pytest.raises(ValueError, match="tunnel.awg_signature_tag"):
        masking.packet_size("<x 5>")
    # <b> needs an even hex string; counts must be 1..MAX_TAG.
    with pytest.raises(ValueError, match="tunnel.awg_signature_hex"):
        masking.packet_size("<b 0x2>")
    with pytest.raises(ValueError, match="tunnel.awg_signature_number"):
        masking.packet_size("<r 0>")
    with pytest.raises(ValueError, match="tunnel.awg_signature_number"):
        masking.packet_size("<r 2000>")
    with pytest.raises(ValueError, match="tunnel.awg_signature_number"):
        masking.packet_size("<t 5>")
    # A packet past 1400 bytes fragments at almost any path.
    with pytest.raises(ValueError, match="tunnel.awg_signature_size"):
        masking.packet_size("<b 0x" + "ab" * 1400 + "><r 2>")
    # Exactly 1400 is fine.
    assert masking.packet_size("<b 0x" + "ab" * 1400 + ">") == 1400


def test_masks_match_the_reference_panel():
    for name, expected in (("icloud", REF_ICLOUD), ("stun", REF_STUN), ("quic", REF_QUIC),
                           ("dns", REF_DNS), ("sip", REF_SIP)):
        values = masking.preset(name)
        assert values["I1"] == expected, name
        assert all(values[key] == "" for key in ("I2", "I3", "I4", "I5"))


def test_icloud_answers_with_the_real_address():
    # The packet AmneziaVPN puts in every server config answers icloud.com with
    # a Yandex address (4d583737 = 77.88.55.55); the mask keeps the shape but
    # carries the real Apple address.
    values = masking.preset("icloud")
    assert "69636c6f756403636f6d" in values["I1"]  # "icloud.com"
    assert "11fd900a" in values["I1"]  # 17.253.144.10, Apple's net
    assert "4d583737" not in values["I1"]
    assert masking.is_amnezia(masking.AMNEZIA_I1)
    assert not masking.is_amnezia(values["I1"])


def test_custom_host_and_ip():
    values = masking.preset("icloud", host="example.com", ip="93.184.216.34")
    assert "076578616d706c6503636f6d" in values["I1"]
    assert "5db8d822" in values["I1"]
    question = masking.preset("dns", host="example.com")
    # The first length byte ends the first fixed-bytes tag; the name follows.
    assert "076578616d706c6503636f6d" in question["I1"].replace("><b 0x", "")
    # The 128-byte padding option scales with the name: the packet stays small.
    assert masking.packet_size(question["I1"]) < 200
    # Punycode names must be supplied in ASCII form already; IPv6 and garbage
    # hosts are rejected before anything reaches a tunnel.
    with pytest.raises(ValueError, match="tunnel.awg_masking_host"):
        masking.preset("icloud", host="пример")
    with pytest.raises(ValueError, match="tunnel.awg_masking_host"):
        masking.preset("dns", host="x" * 64)
    with pytest.raises(ValueError, match="tunnel.awg_masking_ip"):
        masking.dns_response(ip="::1")
    with pytest.raises(ValueError, match="tunnel.awg_masking_ip"):
        masking.dns_response(ip="999.1.1.1")


def test_preset_unknown():
    with pytest.raises(ValueError, match="tunnel.awg_masking_preset"):
        masking.preset("smtp")


def test_catalog_shapes():
    catalog = {item["id"]: item for item in masking.catalog()}
    assert set(catalog) == {"icloud", "stun", "quic", "dns", "sip", "none"}
    assert catalog["quic"]["values"]["I1"] == REF_QUIC
    assert catalog["quic"]["sizes"] == {"I1": 1200}
    assert catalog["none"]["values"] == {key: "" for key in masking.KEYS}
    assert catalog["none"]["sizes"] == {}


def make_tunnel(**over):
    obfuscation = {"Jc": 4, "S1": 16, "S2": 16, "H1": 1, "H2": 2, "H3": 3, "H4": 4,
                   "I1": "<r 2><b 0x8580>"}
    obfuscation.update(over.pop("obfuscation", {}))
    return Tunnel(name="t", interface="awg0", role="server", protocol="awg",
                  private_key=EncryptedSecret(ciphertext="gAAAAABm" + "x" * 20),
                  listen_port=51821, obfuscation=obfuscation, **over)


def test_tunnel_accepts_a_valid_packet():
    assert make_tunnel().obfuscation["I1"] == "<r 2><b 0x8580>"


def test_tunnel_stores_the_normalized_packet():
    tunnel = make_tunnel(obfuscation={"I1": " <r 2> <b 0x8580> "})
    assert tunnel.obfuscation["I1"] == "<r 2> <b 0x8580>"


def test_tunnel_rejects_a_foreign_or_oversized_packet():
    with pytest.raises(ValidationError):
        make_tunnel(obfuscation={"I1": "<d 5>"})
    with pytest.raises(ValidationError):
        make_tunnel(obfuscation={"I1": "<b 0x" + "ab" * 1400 + "><r 2>"})
