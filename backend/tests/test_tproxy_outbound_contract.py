"""Disabled-by-default proxy/subscription/group contract (plan stage 1).

Offline schema + validators only: no subscription fetch, no UI, no apply.
These tests pin the plan's stage-3 semantics (https-only subscriptions, unique
tags, no recursive/self-addressed outbound, no open administrative inbound,
encrypted+redacted secrets) and prove legacy snapshots still load disabled.
"""
import pytest
from typing import Any, cast
from cryptography.fernet import Fernet
from pydantic import ValidationError

from vs_router.api.configuration import parse_configuration, redact
from vs_router.schema import Configuration
from vs_router.secrets import decrypt_secret


def outbound(tag="proxy1", **overrides):
    row = {"tag": tag, "type": "vless", "server": "198.51.100.10", "port": 443}
    row.update(overrides)
    return row


def test_proxy_contract_disabled_and_empty_by_default():
    payload = Configuration.model_validate({}).model_dump(mode="json")
    assert payload["proxies"] == {
        "enabled": False, "outbounds": [], "subscriptions": [], "groups": [],
    }


def test_legacy_snapshot_without_proxies_loads_disabled_and_roundtrips():
    configuration = Configuration.model_validate({"interfaces": [{"name": "lan0", "zone": "lan"}]})
    payload = configuration.model_dump(mode="json")
    assert payload["proxies"]["enabled"] is False
    assert Configuration.model_validate(payload).model_dump(mode="json") == payload


def test_valid_outbound_subscription_and_group_accepted():
    config = Configuration.model_validate({"proxies": {
        "outbounds": [outbound("proxy1"), outbound("proxy2", type="trojan")],
        "subscriptions": [{"name": "sub1", "url": "https://example.org/sub"}],
        "groups": [{"tag": "select", "type": "selector", "outbounds": ["proxy1", "proxy2"]},
                   {"tag": "auto", "type": "urltest", "outbounds": ["proxy1"]}],
    }})
    assert [o.tag for o in config.proxies.outbounds] == ["proxy1", "proxy2"]
    assert config.proxies.groups[0].type == "selector"


@pytest.mark.parametrize("url", ["http://example.org/sub", "ftp://example.org/sub", "example.org/sub"])
def test_subscription_requires_https(url):
    with pytest.raises(ValidationError, match="proxy.subscription_https_required"):
        Configuration.model_validate({"proxies": {"subscriptions": [{"name": "sub", "url": url}]}})


def test_duplicate_tag_rejected():
    with pytest.raises(ValidationError, match="proxy.duplicate_tag"):
        Configuration.model_validate({"proxies": {"outbounds": [outbound("same"), outbound("same")]}})


def test_group_tag_collides_with_outbound_tag():
    with pytest.raises(ValidationError, match="proxy.tag_collision"):
        Configuration.model_validate({"proxies": {
            "outbounds": [outbound("dup")],
            "groups": [{"tag": "dup", "type": "selector", "outbounds": ["dup"]}],
        }})


def test_recursive_group_rejected():
    with pytest.raises(ValidationError, match="proxy.group_recursive"):
        Configuration.model_validate({"proxies": {"groups": [
            {"tag": "alpha", "type": "selector", "outbounds": ["beta"]},
            {"tag": "beta", "type": "selector", "outbounds": ["alpha"]},
        ]}})


def test_group_self_reference_rejected():
    with pytest.raises(ValidationError, match="proxy.group_recursive"):
        Configuration.model_validate({"proxies": {"groups": [
            {"tag": "alpha", "type": "urltest", "outbounds": ["alpha"]},
        ]}})


def test_group_must_reference_known_tag():
    with pytest.raises(ValidationError, match="proxy.group_reference"):
        Configuration.model_validate({"proxies": {"groups": [
            {"tag": "alpha", "type": "selector", "outbounds": ["missing"]},
        ]}})


def test_group_must_not_be_empty():
    with pytest.raises(ValidationError, match="proxy.group_empty"):
        Configuration.model_validate({"proxies": {"groups": [
            {"tag": "alpha", "type": "selector"},
        ]}})


@pytest.mark.parametrize("server", ["127.0.0.1", "::1", "localhost", "0.0.0.0"])
def test_self_addressed_outbound_rejected(server):
    with pytest.raises(ValidationError, match="proxy.outbound_self_reference"):
        Configuration.model_validate({"proxies": {"outbounds": [outbound(server=server)]}})


def test_outbound_cannot_target_router_own_address():
    with pytest.raises(ValidationError, match="proxy.outbound_self_reference"):
        Configuration.model_validate({
            "interfaces": [{"name": "lan0", "zone": "lan", "addresses": ["192.0.2.1/24"]}],
            "proxies": {"outbounds": [outbound(server="192.0.2.1")]},
        })


def test_open_administrative_inbound_rejected_loopback_allowed():
    with pytest.raises(ValidationError, match="proxy.admin_inbound_open"):
        Configuration.model_validate({"proxies": {"outbounds": [outbound(admin_listen="0.0.0.0")]}})
    Configuration.model_validate({"proxies": {"outbounds": [outbound(admin_listen="127.0.0.1")]}})


def test_local_outbound_forbids_remote_fields():
    for change in ({"server": "198.51.100.10", "port": 443}, {"admin_listen": "127.0.0.1"}):
        with pytest.raises(ValidationError, match="proxy.outbound_local_fields"):
            Configuration.model_validate({"proxies": {"outbounds": [
                {"tag": "direct", "type": "direct", **change}]}})


def test_remote_outbound_requires_server_and_port():
    with pytest.raises(ValidationError, match="proxy.outbound_server_required"):
        Configuration.model_validate({"proxies": {"outbounds": [{"tag": "p", "type": "trojan"}]}})
    with pytest.raises(ValidationError, match="proxy.outbound_server_required"):
        Configuration.model_validate({"proxies": {"outbounds": [
            {"tag": "p", "type": "trojan", "server": "198.51.100.10"}]}})


def test_plaintext_secret_rejected():
    with pytest.raises(ValidationError):
        Configuration.model_validate({"proxies": {"outbounds": [
            outbound(secret="my-password")]}})


def test_proxy_secret_encrypted_and_redacted(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("VS_ROUTER_SECRET_KEY", key.decode())
    payload = {"proxies": {"outbounds": [outbound(secret={"plaintext": "hunter2"})]}}
    config = parse_configuration(payload)
    assert decrypt_secret(config.proxies.outbounds[0].secret, key) == "hunter2"
    saved = config.model_dump(mode="json")
    assert "hunter2" not in str(saved)
    assert "plaintext" not in str(saved)
    redacted = cast(dict[str, Any], redact(saved))
    saved_outbounds = redacted["proxies"]["outbounds"]
    assert saved_outbounds[0]["secret"] == {"redacted": True}
    assert parse_configuration(redacted, saved) == config


def test_tproxy_still_cannot_be_enabled():
    with pytest.raises(ValidationError, match="tproxy.not_available"):
        Configuration.model_validate({"tproxy": {"enabled": True}})