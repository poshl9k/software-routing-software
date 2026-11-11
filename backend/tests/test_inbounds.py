"""ADR-0034 slice 1: VLESS + Reality subscriber inbounds (contract + render)."""
import base64
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from vs_router.generators.singbox import PLACEHOLDER_REALITY_KEY, PLACEHOLDER_UUID, generate_singbox
from vs_router.schema import (
    Configuration, ConfigurationVersion, EncryptedSecret, Inbound, InboundUser, TProxy, Tunnel,
)

SECRET = EncryptedSecret(ciphertext="gAAAAABm" + "x" * 20)
PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()


def user(name="alice_phone", uuid="11111111-2222-3333-4444-555555555555"):
    return InboundUser(name=name, uuid=SECRET), uuid


def inbound(**overrides):
    data = dict(
        tag="vless_in",
        listen_port=443,
        server_name="www.microsoft.com",
        handshake_dest="127.0.0.1:8444",
        private_key=SECRET,
        public_key=PUBLIC_KEY,
        short_ids=("0123abcd",),
    )
    data.update(overrides)
    return Inbound(**data)


def version(inbound_obj, profile="panel"):
    return ConfigurationVersion(profile=profile,
                                configuration=Configuration(inbounds=(inbound_obj,)))


def test_panel_inbound_renders_vless_reality_with_fronting():
    inbound_obj = inbound(users=(user()[0],))
    document = generate_singbox(version(inbound_obj))
    listeners = {item["tag"]: item for item in document["inbounds"]}
    rendered = listeners["vless_in"]
    assert rendered["type"] == "vless"
    assert rendered["listen_port"] == 443
    assert rendered["users"] == [{"name": "alice_phone", "uuid": PLACEHOLDER_UUID,
                                  "flow": "xtls-rprx-vision"}]
    reality = rendered["tls"]["reality"]
    assert reality["handshake"] == {"server": "127.0.0.1", "server_port": 8444}
    assert reality["short_id"] == ["0123abcd"]
    assert reality["private_key"] == PLACEHOLDER_REALITY_KEY
    # The pre-existing loopback listeners stay, so interception is unchanged.
    assert {"tproxy-tcp", "tproxy-udp"} <= set(listeners)


def test_apply_provider_replaces_placeholder_credentials():
    inbound_obj = inbound(users=(user()[0],))
    seen = []

    def reveal(user_obj):
        seen.append(user_obj.name)
        return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    document = generate_singbox(version(inbound_obj), inbound_user_secret=reveal)
    rendered = next(item for item in document["inbounds"] if item["tag"] == "vless_in")
    assert rendered["users"][0]["uuid"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert seen == ["alice_phone"]
    # A preview never leaks a real key even when a provider exists.
    assert rendered["tls"]["reality"]["private_key"] == PLACEHOLDER_REALITY_KEY


def test_apply_provider_replaces_the_reality_private_key():
    """A declared inbound needs its own key revealed on apply, not just UUIDs.

    Regression: the render used to hardcode the placeholder, so every apply
    with an inbound failed ``sing-box check`` on the placeholder key while the
    unit tests (user provider only) stayed green.
    """
    inbound_obj = inbound(users=(user()[0],))
    seen = []

    def reveal_key(inbound_value):
        seen.append(inbound_value.tag)
        return "q" * 43 + "="

    document = generate_singbox(version(inbound_obj), inbound_secret=reveal_key)
    rendered = next(item for item in document["inbounds"] if item["tag"] == "vless_in")
    assert rendered["tls"]["reality"]["private_key"] == "q" * 43 + "="
    assert seen == ["vless_in"]
    # Preview stays a placeholder without the provider.
    preview = generate_singbox(version(inbound_obj))
    preview_rendered = next(i for i in preview["inbounds"] if i["tag"] == "vless_in")
    assert preview_rendered["tls"]["reality"]["private_key"] == PLACEHOLDER_REALITY_KEY


def test_build_artifacts_decrypts_the_inbound_private_key(monkeypatch):
    """The apply artifacts carry the real key, so the pinned engine can check them."""
    import base64 as b64
    import json

    from vs_router.agent.tproxy_apply import build_artifacts
    from vs_router.secrets import encrypt_secret

    key = b64.urlsafe_b64encode(b"7" * 32)
    monkeypatch.setenv("VS_ROUTER_SECRET_KEY", key.decode())
    secret = encrypt_secret("k" * 43 + "=", key)
    uuid = encrypt_secret("11111111-2222-3333-4444-555555555555", key)
    inbound_obj = inbound(private_key=secret,
                          users=(InboundUser(name="alice_phone", uuid=uuid),))
    artifacts = build_artifacts(version(inbound_obj), key)
    document = json.loads(artifacts["singbox"])
    rendered = next(item for item in document["inbounds"] if item["tag"] == "vless_in")
    assert rendered["tls"]["reality"]["private_key"] == "k" * 43 + "="
    assert rendered["users"][0]["uuid"] == "11111111-2222-3333-4444-555555555555"
    # Preview (no key) still never leaks key material.
    assert PLACEHOLDER_REALITY_KEY not in artifacts["singbox"]


def test_inbounds_without_capture_stage_only_the_engine():
    """A panel inbound alone must not stage or verify the TProxy capture tract.

    Regression: ``required()`` treated inbounds as a full TProxy branch, so a
    host with ``tproxy.enabled == False`` staged destroy-only guard text and
    then failed confirmation with ``agent.tproxy_tables_missing``.
    """
    from vs_router.agent import tproxy_apply

    inbound_obj = inbound(users=(user()[0],))
    engine_only = version(inbound_obj)
    assert tproxy_apply.required(engine_only)
    assert not tproxy_apply.capture_required(engine_only)
    assert set(tproxy_apply.artifacts(engine_only)) == {"subscriber_peers", "singbox"}
    rendered = tproxy_apply.build_artifacts(engine_only)
    assert set(rendered) == {"subscriber_peers", "singbox"}
    assert "tproxy_guards" not in rendered and "tproxy_interception" not in rendered


def test_capture_configuration_still_stages_the_full_tract():
    from vs_router.agent import tproxy_apply

    inbound_obj = inbound(users=(user()[0],))
    # Assignment (not validation): an enabled TProxy contract needs a full DNS
    # contour, which is irrelevant to the file map under test.
    configuration = Configuration(inbounds=(inbound_obj,)).model_copy(
        update={"tproxy": TProxy(enabled=True)})
    # ``artifacts``/``capture_required`` only read ``configuration``, so a
    # version shell without the (unrelated) capture-contract validation is
    # enough here; a full enabled TProxy contract is covered by test_tproxy*.
    capture = SimpleNamespace(configuration=configuration)
    assert tproxy_apply.capture_required(capture)
    assert set(tproxy_apply.artifacts(capture)) == set(tproxy_apply.TPROXY_FILES)
    assert set(tproxy_apply.artifact_validators(capture)) == set(tproxy_apply.TPROXY_FILES)


def test_router_profile_rejects_inbounds():
    with pytest.raises(ValueError, match="inbound.panel_only"):
        generate_singbox(version(inbound(), profile="router"))


def test_inbound_tag_and_port_must_be_unique():
    with pytest.raises(ValueError, match="inbound.duplicate_tag"):
        Configuration(inbounds=(inbound(), inbound(short_ids=("beef",))))
    with pytest.raises(ValueError, match="inbound.port_conflict"):
        Configuration(inbounds=(inbound(), inbound(tag="vless_alt")))


def test_fronting_on_the_panel_port_needs_a_loopback_target():
    with pytest.raises(ValueError, match="inbound.handshake_loopback"):
        inbound(handshake_dest="www.microsoft.com:443")
    # A dedicated high port may front anything the operator names.
    assert inbound(listen_port=8443, handshake_dest="www.microsoft.com:443").listen_port == 8443
    # A port the panel already owns cannot be fronted from a non-loopback target.
    with pytest.raises(ValueError, match="inbound.panel_port_conflict"):
        Configuration(panel_port=8443,
                      inbounds=(inbound(listen_port=8443,
                                        handshake_dest="www.microsoft.com:443"),))


def test_reality_material_is_validated():
    with pytest.raises(ValueError, match="inbound.reality_public_key"):
        inbound(public_key="not-a-key")
    with pytest.raises(ValueError, match="inbound.short_id"):
        inbound(short_ids=("zz11",))
    with pytest.raises(ValueError, match="inbound.short_id_count"):
        inbound(short_ids=tuple(f"{index:02x}" for index in range(9)))
    with pytest.raises(ValueError, match="inbound.handshake_dest"):
        inbound(handshake_dest="127.0.0.1")


def test_user_names_must_tie_to_a_device():
    with pytest.raises(ValueError, match="inbound.user_duplicate"):
        inbound(users=(user()[0], user()[0]))
    with pytest.raises(ValueError, match="inbound.user_name"):
        InboundUser(name="phone", uuid=SECRET)


def test_rendered_document_passes_the_pinned_engine_check():
    binary = shutil.which("sing-box")
    if binary is None:
        pytest.skip("sing-box binary is not installed on this host")
    inbound_obj = inbound(users=(user()[0],))
    document = generate_singbox(version(inbound_obj))
    # The always-rendered loopback stubs need their rule-set declared; keep the
    # check honest by removing only the unrelated subscriber capacity guard.
    payload = {"inbounds": document["inbounds"], "outbounds": document["outbounds"],
               "route": {"rules": [], "final": "direct"}}
    path = "inbounds-check.json"
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(payload, stream)
    try:
        result = subprocess.run([binary, "check", "-c", path], capture_output=True, text=True)
    finally:
        import os
        os.unlink(path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_inbound_opens_its_port_on_the_wan_zone():
    from vs_router.generators.nftables import generate_nftables
    from vs_router.schema import Interface

    configuration = Configuration(
        interfaces=(Interface(name="wan0", type="physical", zone="wan",
                              addresses=("203.0.113.2/24",)),),
        inbounds=(inbound(),),
    )
    rules = generate_nftables(ConfigurationVersion(profile="panel", configuration=configuration))
    assert 'tcp dport 443 counter accept comment "inbound_vless_in"' in rules
    # Default deny stays: the rule is an explicit accept, not a policy change.
    assert "policy drop;" in rules


def test_inbounds_alone_require_the_engine():
    from vs_router.agent.tproxy_apply import required

    assert required(version(inbound())) is True
    assert required(ConfigurationVersion(profile="panel", configuration=Configuration())) is False


def test_apply_injects_real_user_uuids(monkeypatch):
    import base64

    from vs_router.agent import tproxy_apply
    from vs_router.secrets import encrypt_secret

    key = base64.urlsafe_b64encode(b"0" * 32)
    monkeypatch.setenv("VS_ROUTER_SECRET_KEY", key.decode())
    uuid = "11111111-2222-3333-4444-555555555555"
    secret = encrypt_secret(uuid, key)
    # The inbound's own Reality key is revealed by the same apply path, so it
    # must be real ciphertext rather than the fixture placeholder.
    reality = encrypt_secret("k" * 43 + "=", key)
    inbound_obj = inbound(private_key=reality,
                          users=(InboundUser(name="alice_phone", uuid=secret),))
    artifacts = tproxy_apply.build_artifacts(version(inbound_obj), key)
    document = json.loads(artifacts["singbox"])
    rendered = next(item for item in document["inbounds"] if item["tag"] == "vless_in")
    assert rendered["users"][0]["uuid"] == uuid
    assert "\"" + uuid + "\"" in artifacts["singbox"]


def _management(address="203.0.113.2/24"):
    from vs_router.management import Management
    return Management(interface="wan0", mac="02:00:00:00:00:01",
                      address=address, mode="single-uplink",
                      hostname="203.0.113.2.nip.io")


def _fronting_configuration():
    from vs_router.schema import Interface
    return Configuration(
        interfaces=(Interface(name="wan0", type="physical", zone="wan",
                              addresses=("203.0.113.2/24",)),),
        inbounds=(inbound(),),
    )


def test_panel_moves_behind_the_inbound_when_it_owns_the_port():
    from vs_router.generators.caddy import generate_caddy_json
    document = generate_caddy_json(ConfigurationVersion(profile="panel",
                                                        configuration=_fronting_configuration()),
                                   _management())
    server = document["apps"]["http"]["servers"]["management"]
    # Reality terminates 443 and hands everything else to the panel on loopback.
    assert server["listen"] == ["127.0.0.1:8444"]
    # The public panel names keep their routes, so the UI is not lost.
    assert any("host" in matcher for route in server["routes"] for matcher in route.get("match", []))


def test_panel_keeps_the_management_address_without_inbounds():
    from vs_router.generators.caddy import generate_caddy_json
    from vs_router.schema import Interface
    configuration = Configuration(
        interfaces=(Interface(name="wan0", type="physical", zone="wan",
                              addresses=("203.0.113.2/24",)),),
    )
    document = generate_caddy_json(ConfigurationVersion(profile="panel",
                                                        configuration=configuration),
                                   _management())
    server = document["apps"]["http"]["servers"]["management"]
    assert server["listen"] == ["203.0.113.2:443"]


def test_vless_share_link_carries_reality_parameters():
    from vs_router.generators.vless_uri import vless_uri

    link = vless_uri(inbound(), "11111111-2222-3333-4444-555555555555",
                     "203.0.113.2", "phone")
    assert link.startswith("vless://11111111-2222-3333-4444-555555555555@203.0.113.2:443?")
    for fragment in ("security=reality", "sni=www.microsoft.com", "pbk=",
                     "sid=0123abcd", "flow=xtls-rprx-vision", "fp=chrome",
                     "type=tcp", "encryption=none"):
        assert fragment in link, fragment
    assert link.endswith("#phone")


def test_vless_share_link_rejects_an_unusable_entry():
    from vs_router.generators.vless_uri import vless_uri

    with pytest.raises(ValueError, match="inbound.entry_host"):
        vless_uri(inbound(), "uuid", "203.0.113.2/path")
    with pytest.raises(ValueError, match="inbound.entry_host"):
        vless_uri(inbound(), "uuid", "a:b")
    # An IPv6 entry is bracketed, not ambiguous with the port separator.
    assert "@[2001:db8::1]:443?" in vless_uri(inbound(), "uuid", "[2001:db8::1]")


def test_keygen_returns_an_inbound_the_contract_accepts():
    from vs_router.api.keygen import InboundRequest, generate_inbound

    payload = generate_inbound(InboundRequest())
    built = Inbound.model_validate({**payload,
                                    "private_key": {"encrypted": True,
                                                    "ciphertext": "gAAAAABm"}})
    assert built.listen_port == 443
    assert built.handshake_dest == "127.0.0.1:8444"
    assert len(built.short_ids) == 1 and len(built.short_ids[0]) == 16
    # The public half is a real 32-byte key, so a client link is usable at once.
    # base64url without padding: 43 characters for a 32-byte key.
    assert len(base64.urlsafe_b64decode(built.public_key + "=")) == 32


def test_keygen_rejects_conflicting_or_invalid_ports():
    from vs_router.api.keygen import InboundRequest, generate_inbound
    from vs_router.api.errors import APIError

    with pytest.raises(APIError) as error:
        generate_inbound(InboundRequest(listen_port=8444, handshake_port=8444))
    assert error.value.code == "inbound.port_conflict"
    with pytest.raises(APIError) as names:
        generate_inbound(InboundRequest(server_name="not a host"))
    assert names.value.code == "inbound.server_name"


def test_saving_an_inbound_encrypts_the_key_and_user_uuids(monkeypatch):
    import base64 as b64

    from vs_router.api.configuration import parse_configuration

    monkeypatch.setenv("VS_ROUTER_SECRET_KEY",
                       b64.urlsafe_b64encode(b"1" * 32).decode())
    document = {
        "inbounds": [{
            "tag": "vless_in", "listen_port": 443, "server_name": "www.microsoft.com",
            "handshake_dest": "127.0.0.1:8444",
            "private_key": {"plaintext": "PRIVATE-KEY-MATERIAL"},
            "public_key": base64.urlsafe_b64encode(bytes(range(32))).decode(),
            "short_ids": ["0123abcd"],
            "users": [{"name": "alice_phone", "uuid": {"plaintext":
                       "11111111-2222-3333-4444-555555555555"}}],
        }],
    }
    configuration = parse_configuration(document)
    inbound = configuration.inbounds[0]
    assert inbound.private_key.ciphertext.startswith("gAAAA")
    assert inbound.users[0].uuid.ciphertext.startswith("gAAAA")
    assert "PRIVATE-KEY-MATERIAL" not in configuration.model_dump_json()
