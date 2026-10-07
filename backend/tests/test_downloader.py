"""SSRF-guarded subscription/rule-set downloader (agent module).

Every network interaction is a mocked transport; nothing here opens a socket.
The tests pin the plan's security requirements: address policy (loopback,
private, link-local/metadata, multicast, unspecified, IPv6 ULA/link-local),
redirect and DNS-rebinding refusal, https-only, size/time limits, format
validation and atomic activation with rollback and history.
"""
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, "tests")

import pytest
from pydantic import ValidationError

from test_agent_apply import FakeFS
from vs_router.agent import daemon
from vs_router.agent.downloader import (BuiltinSource, DownloadError, FetchResponse,
                                        SourceStore, SourceUpdater, fetch, ip_is_forbidden,
                                        validate_content)
from vs_router.agent.rpc import build_request

PUBLIC = "93.184.216.34"          # documentation-grade public unicast
INTERNAL = "10.0.0.5"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def response(status=200, body=b"", headers=None):
    return FetchResponse(status=status, headers=dict(headers or {}), body=body)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def fetch(self, *, url, connect_ip, timeout, max_bytes,
              etag=None, last_modified=None):
        self.calls.append({"url": url, "connect_ip": connect_ip,
                           "timeout": timeout, "max_bytes": max_bytes,
                           "etag": etag, "last_modified": last_modified})
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def fixed_resolver(mapping):
    def _resolve(host):
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, host)
        return mapping[host]
    return _resolve


def make_updater(tmp_path, *, responses, mapping=None, builtin=None, **kw):
    store = SourceStore(base=tmp_path / "sources", filesystem=FakeFS(), clock=lambda: 100.0)
    transport = FakeTransport(responses)
    updater = SourceUpdater(store=store, transport=transport,
                            resolver=fixed_resolver(mapping or {}),
                            builtin_sources={} if builtin is None else builtin, **kw)
    return updater, store, transport


def user_spec(updater, url="https://public.example/x", **overrides):
    return updater.build_spec(name="sub1", url=url, authorized=True, **overrides)


# ---------------------------------------------------------------------------
# Address policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address,forbidden", [
    ("127.0.0.1", True), ("10.0.0.5", True), ("169.254.169.254", True),
    ("100.64.0.1", True), ("172.16.0.1", True), ("192.168.1.1", True),
    ("192.0.2.1", True), ("224.0.0.1", True), ("0.0.0.0", True),
    ("::1", True), ("fe80::1", True), ("fc00::1", True), ("::ffff:127.0.0.1", True),
    (PUBLIC, False), ("2606:2800:220:1:248:1893:25c8:1946", False),
])
def test_ip_policy(address, forbidden):
    import ipaddress
    assert ip_is_forbidden(ipaddress.ip_address(address)) is forbidden


@pytest.mark.parametrize("hostname,address", [
    ("loop.example", "127.0.0.1"), ("rfc1918.example", "10.0.0.5"),
    ("metadata.example", "169.254.169.254"), ("cgnat.example", "100.64.0.1"),
    ("multicast.example", "224.0.0.1"), ("unspec.example", "0.0.0.0"),
    ("v6loop.example", "::1"), ("v6link.example", "fe80::1"), ("v6ula.example", "fc00::1"),
])
def test_single_forbidden_resolved_address_is_rejected(tmp_path, hostname, address):
    spec = user_spec(_updater_only(tmp_path), url=f"https://{hostname}/x")
    transport = FakeTransport([response(200, b"ok")])
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=transport, resolver=fixed_resolver({hostname: [address]}))
    assert exc.value.code == "download.forbidden_address"
    assert transport.calls == []  # rejected before any connection


def test_ip_literal_host_is_checked(tmp_path):
    spec = user_spec(_updater_only(tmp_path), url="https://127.0.0.1/x")
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=FakeTransport([response(200, b"ok")]), resolver=fixed_resolver({}))
    assert exc.value.code == "download.forbidden_address"


def test_mixed_answer_with_one_internal_record_is_rejected(tmp_path):
    # Split-horizon: a public record must not let an internal one through.
    spec = user_spec(_updater_only(tmp_path), url="https://mixed.example/x")
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=FakeTransport([response(200, b"ok")]),
              resolver=fixed_resolver({"mixed.example": [PUBLIC, INTERNAL]}))
    assert exc.value.code == "download.forbidden_address"


def _updater_only(tmp_path):
    store = SourceStore(base=tmp_path / "sources", filesystem=FakeFS())
    return SourceUpdater(store=store, transport=FakeTransport([]),
                         resolver=fixed_resolver({}), builtin_sources={})


# ---------------------------------------------------------------------------
# Scheme, authorization and allowlist
# ---------------------------------------------------------------------------

def test_plaintext_http_is_refused(tmp_path):
    spec = user_spec(_updater_only(tmp_path), url="http://public.example/x")
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=FakeTransport([response(200, b"ok")]),
              resolver=fixed_resolver({"public.example": [PUBLIC]}))
    assert exc.value.code == "download.https_required"


def test_user_source_requires_explicit_authorization(tmp_path):
    updater = _updater_only(tmp_path)
    with pytest.raises(DownloadError) as exc:
        updater.build_spec(name="sub1", url="https://public.example/x", authorized=False)
    assert exc.value.code == "download.user_authorization_required"


def test_builtin_url_must_match_registry(tmp_path):
    builtin = {"geo": BuiltinSource(url="https://public.example/rules.json",
                                    hosts=frozenset({"public.example"}))}
    updater, _, _ = make_updater(tmp_path, responses=[], builtin=builtin)
    with pytest.raises(DownloadError) as exc:
        updater.build_spec(name="geo", url="https://evil.example/rules.json")
    assert exc.value.code == "download.builtin_url_mismatch"


def test_connect_ip_is_pinned_to_the_validated_address(tmp_path):
    # DNS-rebinding defence: the checked address is the dialled address.
    updater, _, transport = make_updater(
        tmp_path, responses=[response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert transport.calls[0]["connect_ip"] == PUBLIC


def test_rebinding_private_answer_is_refused(tmp_path):
    # Second stage of a rebind (resolver now returns an internal address) is
    # rejected before any connection is made.
    updater, _, transport = make_updater(
        tmp_path, responses=[response(200, b"ok")],
        mapping={"public.example": ["127.0.0.1"]})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert exc.value.code == "download.forbidden_address"
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------

def test_redirect_to_unlisted_host_is_refused(tmp_path):
    spec = user_spec(_updater_only(tmp_path), url="https://public.example/x")
    transport = FakeTransport([response(302, headers={"Location": "https://other.example/x"})])
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=transport, resolver=fixed_resolver({"public.example": [PUBLIC]}))
    assert exc.value.code == "download.host_not_authorized"
    assert len(transport.calls) == 1


def test_redirect_to_forbidden_address_is_refused(tmp_path):
    builtin = {"geo": BuiltinSource(url="https://public.example/rules.json",
                                    hosts=frozenset({"public.example", "internal.example"}))}
    updater, _, _ = make_updater(tmp_path, responses=[
        response(302, headers={"Location": "https://internal.example/rules.json"})],
        mapping={"public.example": [PUBLIC], "internal.example": ["127.0.0.1"]},
        builtin=builtin)
    with pytest.raises(DownloadError) as exc:
        updater.update(name="geo", url="https://public.example/rules.json")
    assert exc.value.code == "download.forbidden_address"


def test_builtin_redirect_off_allowlist_is_refused(tmp_path):
    builtin = {"geo": BuiltinSource(url="https://public.example/rules.json",
                                    hosts=frozenset({"public.example"}))}
    updater, _, _ = make_updater(tmp_path, responses=[
        response(302, headers={"Location": "https://cdn.example/rules.json"})],
        mapping={"public.example": [PUBLIC]},
        builtin=builtin)
    with pytest.raises(DownloadError) as exc:
        updater.update(name="geo", url="https://public.example/rules.json")
    assert exc.value.code == "download.host_not_allowed"


def test_redirect_chain_within_allowlist_is_followed(tmp_path):
    builtin = {"geo": BuiltinSource(url="https://public.example/rules.json",
                                    hosts=frozenset({"public.example", "cdn.example"}))}
    updater, _, transport = make_updater(tmp_path, responses=[
        response(302, headers={"Location": "https://cdn.example/rules.json"}),
        response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC], "cdn.example": [PUBLIC]},
        builtin=builtin)
    record = updater.update(name="geo", url="https://public.example/rules.json")
    assert record["status"] == "ok"
    assert [call["url"] for call in transport.calls] == [
        "https://public.example/rules.json", "https://cdn.example/rules.json"]


def test_too_many_redirects_is_refused(tmp_path):
    spec = user_spec(_updater_only(tmp_path), url="https://public.example/x")
    responses = [response(302, headers={"Location": "https://public.example/x"})
                 for _ in range(10)]
    with pytest.raises(DownloadError) as exc:
        fetch(spec, transport=FakeTransport(responses),
              resolver=fixed_resolver({"public.example": [PUBLIC]}))
    assert exc.value.code == "download.too_many_redirects"


# ---------------------------------------------------------------------------
# Size and timeout limits
# ---------------------------------------------------------------------------

def test_size_limit_is_enforced(tmp_path):
    updater, _, transport = make_updater(
        tmp_path, responses=[response(200, b"a" * 2000)],
        mapping={"public.example": [PUBLIC]})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True,
                       max_bytes=1024)
    assert exc.value.code == "download.size_exceeded"
    assert transport.calls[0]["max_bytes"] == 1024


def test_timeout_is_mapped(tmp_path):
    updater, _, transport = make_updater(
        tmp_path, responses=[socket.timeout("slow")],
        mapping={"public.example": [PUBLIC]})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True,
                       timeout=5)
    assert exc.value.code == "download.timeout"
    assert transport.calls[0]["timeout"] == 5


def test_transport_error_is_mapped(tmp_path):
    updater, _, _ = make_updater(tmp_path, responses=[OSError("refused")],
                                 mapping={"public.example": [PUBLIC]})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert exc.value.code == "download.transport_failed"


# ---------------------------------------------------------------------------
# Format validation
# ---------------------------------------------------------------------------

def test_format_detection():
    assert validate_content('{"outbounds": [{"type": "direct", "tag": "direct"}]}', "auto") == "sing-box"
    assert validate_content("# comment\nexample.com\n10.0.0.0/8\n", "text") == "text"
    assert validate_content('{"version": 1, "rules": []}', "auto") == "rule-set"


@pytest.mark.parametrize("declared,content,code", [
    ("sing-box", "not json at all", "download.invalid_format"),
    ("json", "][", "download.invalid_format"),
    ("text", "!! not a domain or cidr !!", "download.invalid_format"),
    ("srs", "SRS", "download.format_unsupported"),
    ("auto", "just some random words\n", "download.invalid_format"),
])
def test_invalid_format_is_refused(declared, content, code):
    with pytest.raises(DownloadError) as exc:
        validate_content(content, declared)
    assert exc.value.code == code


def test_update_rejects_malformed_payload_without_activating(tmp_path):
    updater, store, _ = make_updater(
        tmp_path, responses=[response(200, b"<html>not a subscription</html>")],
        mapping={"public.example": [PUBLIC]})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert exc.value.code == "download.invalid_format"
    assert store.read_active("sub1", "rule_set") is None
    assert updater.status()[-1]["status"] == "failed"


# ---------------------------------------------------------------------------
# Atomic activation, rollback and history
# ---------------------------------------------------------------------------

def test_successful_update_activates_and_records_history(tmp_path):
    updater, store, _ = make_updater(
        tmp_path, responses=[response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC]})
    record = updater.update(name="sub1", url="https://public.example/x",
                            kind="subscription", authorized=True)
    assert record["status"] == "ok"
    assert record["format"] == "sing-box"
    assert record["sha256"]
    active = store.active_path("sub1", "subscription")
    assert store.fs.read(active) == '{"outbounds": []}'
    # The versioned copy and the staging move both happened.
    assert store.version_path("sub1", record["sha256"]) in store.fs.files  # type: ignore[attr-defined]
    assert store.staging_path("sub1") not in store.fs.files  # type: ignore[attr-defined]
    assert [entry["status"] for entry in updater.status()] == ["ok"]


class _FailingMoveFS(FakeFS):
    def atomic_move(self, source, destination):
        raise OSError("disk full")


def test_activation_failure_restores_previous_active_file(tmp_path):
    store = SourceStore(base=tmp_path / "sources", filesystem=FakeFS(), clock=lambda: 100.0)
    store.fs.write(store.active_path("sub1", "rule_set"), "OLD-CONTENT")
    failing = _FailingMoveFS()
    failing.write(store.active_path("sub1", "rule_set"), "OLD-CONTENT")
    updater = SourceUpdater(store=SourceStore(base=tmp_path / "sources", filesystem=failing,
                                              clock=lambda: 100.0),
                            transport=FakeTransport([response(200, b'{"outbounds": []}')]),
                            resolver=fixed_resolver({"public.example": [PUBLIC]}),
                            builtin_sources={})
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert exc.value.code == "download.activation_failed"
    # Rolled back to the previously working set, never a half-written file.
    assert updater.store.fs.read(updater.store.active_path("sub1", "rule_set")) == "OLD-CONTENT"


def test_config_check_failure_keeps_previous_file(tmp_path):
    store = SourceStore(base=tmp_path / "sources", filesystem=FakeFS(), clock=lambda: 100.0)
    store.fs.write(store.active_path("sub1", "rule_set"), "OLD-CONTENT")

    def reject(_candidate):
        raise ValueError("sing-box check failed")

    updater = SourceUpdater(store=store,
                            transport=FakeTransport([response(200, b'{"outbounds": []}')]),
                            resolver=fixed_resolver({"public.example": [PUBLIC]}),
                            builtin_sources={}, config_validator=reject)
    with pytest.raises(DownloadError) as exc:
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert exc.value.code == "download.config_invalid"
    assert store.read_active("sub1", "rule_set") == "OLD-CONTENT"
    assert updater.status()[-1] == {
        "name": "sub1", "kind": "rule_set", "status": "failed",
        "url": "https://public.example/x", "format": None, "sha256": None,
        "size": None, "at": 100.0, "error": "download.config_invalid",
    }


def test_history_accumulates_and_is_capped(tmp_path):
    updater, store, _ = make_updater(
        tmp_path, responses=[response(200, b'{"outbounds": []}')] * 3,
        mapping={"public.example": [PUBLIC]})
    for _ in range(3):
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert [entry["status"] for entry in updater.status()] == ["ok", "ok", "ok"]


# ---------------------------------------------------------------------------
# RPC whitelist and daemon wiring
# ---------------------------------------------------------------------------

def test_update_source_is_a_typed_whitelisted_method():
    request = build_request("update_source", {
        "name": "sub1", "url": "https://public.example/x",
        "kind": "subscription", "format": "auto", "authorized": True,
        "max_bytes": 4096, "timeout": 10,
    }, request_id=1)
    assert request.method == "update_source"
    assert request.params["name"] == "sub1"


@pytest.mark.parametrize("params", [
    {},                                                   # name/url required
    {"name": "1bad", "url": "https://x.example/"},
    {"name": "ok", "url": 123},
    {"name": "ok", "url": "https://x.example/", "max_bytes": 10},
    {"name": "ok", "url": "https://x.example/", "timeout": 9999},
    {"name": "ok", "url": "https://x.example/", "extra": 1},
    {"name": "ok", "url": "https://x.example/", "format": "exotic"},
])
def test_update_source_rejects_malformed_params(params):
    with pytest.raises(ValidationError):
        build_request("update_source", params)


def test_source_status_takes_no_params():
    assert build_request("source_status", {}, request_id=1).params == {}


def test_scheduled_update_is_rejected_while_apply_pending(tmp_path):
    updater, _, transport = make_updater(tmp_path, responses=[], mapping={"public.example": [PUBLIC]})

    class PendingEngine:
        def status(self):
            return {"status": "pending"}

    handlers = daemon.make_handlers(PendingEngine(), None, updater=updater)
    response = daemon.dispatch(build_request("update_source", {
        "name": "sub1", "url": "https://public.example/x",
        "authorized": True, "scheduled": True,
    }).model_dump_json(), handlers)
    assert response.error.message == "agent.apply_pending"
    assert transport.calls == []


def test_daemon_wires_update_source_and_maps_errors(tmp_path):
    updater, store, _ = make_updater(
        tmp_path, responses=[response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC]})
    handlers = daemon.make_handlers(None, None, updater=updater)

    result = daemon.dispatch(build_request("update_source", {
        "name": "sub1", "url": "https://public.example/x",
        "kind": "subscription", "authorized": True,
    }).model_dump_json(), handlers)
    assert result.error is None
    assert result.result["status"] == "ok"
    assert handlers["source_status"]()[-1]["status"] == "ok"

    # A user source without authorization is refused with a typed code.
    denied = daemon.dispatch(build_request("update_source", {
        "name": "sub2", "url": "https://public.example/y",
    }).model_dump_json(), handlers)
    assert denied.error is not None
    assert denied.error.message == "download.user_authorization_required"


# ---------------------------------------------------------------------------
# Conditional HTTP: ETag / Last-Modified / 304
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("", None), ("   ", None), (None, None), (123, None),
    ('"abc"', '"abc"'), ("Wed, 01 Oct 2025 00:00:00 GMT", "Wed, 01 Oct 2025 00:00:00 GMT"),
    ("abc\r\nX-Evil: 1", None), ("line\nbreak", None), ("x" * 5000, None),
])
def test_conditional_validators_are_sanitized(value, expected):
    from vs_router.agent.downloader import _header_value
    assert _header_value(value) == expected


def test_conditional_fetch_sends_etag_and_handles_304(tmp_path):
    updater, store, transport = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"ETag": '"v1"'}),
                   response(304, headers={"ETag": '"v1"'})],
        mapping={"public.example": [PUBLIC]})
    first = updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert first["status"] == "ok"
    assert transport.calls[0]["etag"] is None  # no prior validator yet
    active_before = store.fs.read(store.active_path("sub1", "rule_set"))

    second = updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert second["status"] == "not_modified"
    # The stored validator was re-sent as If-None-Match.
    assert transport.calls[1]["etag"] == '"v1"'
    # The active set is untouched, and only the attempt bookkeeping moved.
    assert store.fs.read(store.active_path("sub1", "rule_set")) == active_before
    assert [entry["status"] for entry in updater.status()] == ["ok", "not_modified"]


def test_last_modified_is_sent_as_if_modified_since(tmp_path):
    stamp = "Wed, 01 Oct 2025 00:00:00 GMT"
    updater, _, transport = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"Last-Modified": stamp}),
                   response(304, headers={"Last-Modified": stamp})],
        mapping={"public.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    record = updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert record["status"] == "not_modified"
    assert transport.calls[1]["last_modified"] == stamp


def test_304_keeps_active_set_and_skips_format_validation(tmp_path):
    # A 304 has no body to validate; a bogus body must not fail the run.
    updater, store, _ = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"ETag": '"v1"'}),
                   response(304, b"<html>not a set</html>", headers={"ETag": '"v1"'})],
        mapping={"public.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    before = store.fs.read(store.active_path("sub1", "rule_set"))
    record = updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert record["status"] == "not_modified"
    assert store.fs.read(store.active_path("sub1", "rule_set")) == before


def test_validators_are_dropped_when_the_url_changes(tmp_path):
    updater, store, transport = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"ETag": '"v1"'}),
                   response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC], "other.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert store.latest_validators("sub1", "https://public.example/x") == ('"v1"', None)
    assert store.latest_validators("sub1", "https://other.example/x") == (None, None)
    updater.update(name="sub1", url="https://other.example/x", authorized=True)
    assert transport.calls[1]["etag"] is None


def test_control_characters_in_a_response_validator_are_ignored(tmp_path):
    updater, store, transport = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"ETag": "a\r\nX-Evil: 1"}),
                   response(200, b'{"outbounds": []}')],
        mapping={"public.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    # The crafted value never reaches the store, so it is never re-sent.
    assert store.latest_validators("sub1", "https://public.example/x") == (None, None)
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert transport.calls[1]["etag"] is None


def test_failed_attempt_does_not_clear_stored_validators(tmp_path):
    updater, store, transport = make_updater(
        tmp_path,
        responses=[response(200, b'{"outbounds": []}', headers={"ETag": '"v1"'}),
                   response(500),
                   response(304, headers={"ETag": '"v1"'})],
        mapping={"public.example": [PUBLIC]})
    updater.update(name="sub1", url="https://public.example/x", authorized=True)
    with pytest.raises(DownloadError):
        updater.update(name="sub1", url="https://public.example/x", authorized=True)
    # A transient failure keeps the validator so the next attempt is conditional.
    assert store.latest_validators("sub1", "https://public.example/x") == ('"v1"', None)
    record = updater.update(name="sub1", url="https://public.example/x", authorized=True)
    assert record["status"] == "not_modified"
    assert transport.calls[2]["etag"] == '"v1"'


def test_validators_are_keyed_to_the_configured_url_across_redirect(tmp_path):
    # The configured URL is what the next request dials, so the (final-hop)
    # validator must be stored against it, not the redirect target.
    builtin = {"geo": BuiltinSource(url="https://public.example/rules.json",
                                    hosts=frozenset({"public.example", "cdn.example"}))}
    updater, store, transport = make_updater(
        tmp_path, responses=[
            response(302, headers={"Location": "https://cdn.example/rules.json"}),
            response(200, b'{"outbounds": []}', headers={"ETag": '"cdn-v1"'}),
            response(302, headers={"Location": "https://cdn.example/rules.json"}),
            response(304, headers={"ETag": '"cdn-v1"'})],
        mapping={"public.example": [PUBLIC], "cdn.example": [PUBLIC]}, builtin=builtin)
    updater.update(name="geo", url="https://public.example/rules.json")
    assert store.latest_validators("geo", "https://public.example/rules.json") == ('"cdn-v1"', None)
    # A second run re-sends the validator on the first hop of the chain.
    record = updater.update(name="geo", url="https://public.example/rules.json")
    assert record["status"] == "not_modified"
    assert transport.calls[2]["etag"] == '"cdn-v1"'
