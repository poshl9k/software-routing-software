"""Read-only rule-set web contract: schema, view builder, redaction, endpoints.

Everything is offline: the agent RPC is monkeypatched; no fetch ever happens.
"""
import time

import pytest
from pydantic import ValidationError

from vs_router.agent.presets import sources_view
from vs_router.api import rulesets as rulesets_module
from vs_router.api.configuration import redact
from vs_router.schema import Configuration, RuleSetSource
from test_api import api, sign_in

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


DECLARED = {"name": "geo", "format": "geosite",
            "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/x"}


# ---------------------------------------------------------------------------
# Schema validation (strict, off by default, no secrets)
# ---------------------------------------------------------------------------

def test_rule_sets_default_empty_and_off():
    assert Configuration().rule_sets == ()
    assert RuleSetSource(**DECLARED).name == "geo"


@pytest.mark.parametrize("overrides,code", [
    ({"format": "exotic"}, "format"),
    ({"url": "http://plain.example/x"}, "https"),          # https mandatory
    ({"url": "FTP://x.example/y"}, "https"),
    ({"name": "1bad"}, "name"),                            # name pattern
    ({"name": "x" * 40}, "name"),
    ({"max_records": 0}, "max_records"),                   # caps
    ({"max_bytes": 10}, "max_bytes"),
    ({"secret": {"encrypted": True, "ciphertext": "gAAAAx"}}, "secret"),  # extra forbidden
])
def test_rule_set_source_rejects_malformed(overrides, code):
    with pytest.raises(ValidationError):
        RuleSetSource(**{**DECLARED, **overrides})


def test_duplicate_rule_set_names_are_rejected():
    with pytest.raises(ValidationError):
        Configuration(rule_sets=[DECLARED, dict(DECLARED)])


def test_rule_sets_carry_no_secret_field():
    # There is simply no secret field to leak; a raw string cannot be stored.
    assert "secret" not in RuleSetSource.model_fields
    dumped = RuleSetSource(**DECLARED).model_dump(mode="json")
    assert not any("ciphertext" in str(v) for v in dumped.values())


# ---------------------------------------------------------------------------
# Redaction: rule-set sources survive untouched, real secrets still redacted
# ---------------------------------------------------------------------------

def test_redaction_keeps_rule_sets_and_still_redacts_secrets():
    config = Configuration.model_validate({
        "rule_sets": [DECLARED],
        "proxies": {"outbounds": [{
            "tag": "ss1", "type": "shadowsocks", "server": "exit.example.com",
            "port": 8388, "secret": {"encrypted": True,
                                     "ciphertext": "gAAAAABfake-ciphertext"},
        }]},
    })
    view = redact(config.model_dump(mode="json"))
    # The declared rule-set source is fully visible (no secret in it).
    assert view["rule_sets"][0] == {
        "name": "geo", "format": "geosite", "url": DECLARED["url"],
        "max_records": 200_000, "max_bytes": 5_000_000,
    }
    # The outbound secret is still masked.
    assert view["proxies"]["outbounds"][0]["secret"] == {"redacted": True}


# ---------------------------------------------------------------------------
# sources_view: join declared + history, compute status/stale
# ---------------------------------------------------------------------------

def test_sources_view_joins_declared_and_history():
    now = 1_000_000.0
    history = [
        {"name": "geo", "kind": "rule_set", "status": "ok", "url": DECLARED["url"],
         "format": "geosite", "sha256": "abc", "at": now - 60},
        {"name": "other", "kind": "rule_set", "status": "failed", "url": "https://o.example/x",
         "format": None, "at": now - 10},
    ]
    rows = sources_view([DECLARED], history, now=now)
    assert [r["name"] for r in rows] == ["geo", "other"]
    geo = rows[0]
    assert geo["status"] == "ok" and geo["stale"] is False
    assert geo["sha256"] == "abc" and geo["declared"] is True
    other = rows[1]
    assert other["declared"] is False and other["status"] == "failed"
    assert other["stale"] is True  # never succeeded


def test_sources_view_declared_without_history_is_never_and_stale():
    rows = sources_view([DECLARED], [], now=1_000_000.0)
    assert rows == [{
        "name": "geo", "format": "geosite", "url": DECLARED["url"], "kind": "rule_set",
        "status": "never", "stale": True, "last_attempt": None, "last_success": None,
        "sha256": None, "declared": True,
    }]


def test_sources_view_marks_old_last_success_stale():
    now = 1_000_000.0
    fresh = sources_view([DECLARED], [
        {"name": "geo", "status": "ok", "at": now - 60,
         "url": DECLARED["url"], "format": "geosite"}], now=now)[0]
    old = sources_view([DECLARED], [
        {"name": "geo", "status": "ok", "at": now - 30 * 24 * 3600,
         "url": DECLARED["url"], "format": "geosite"}], now=now)[0]
    assert fresh["stale"] is False and old["stale"] is True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

def _patch_agent(monkeypatch, *, history=None, error=None, capture=None):
    def fake_call(method, body):
        if capture is not None:
            capture.append((method, body))
        if error is not None:
            raise error
        return history if method == "source_status" else {"status": "ok", "name": "geo"}
    monkeypatch.setattr(rulesets_module, "agent_call", fake_call)


async def test_rulesets_requires_auth(api):
    client, _, _ = api
    assert (await client.get("/api/rulesets")).status_code == 401


async def test_rulesets_list_returns_declared_with_status_and_stale(api, monkeypatch):
    client, _, _ = api
    await sign_in(client)
    assert (await client.post("/api/draft", json={"rule_sets": [DECLARED]})).status_code == 201
    now = time.time()
    _patch_agent(monkeypatch, history=[
        {"name": "geo", "kind": "rule_set", "status": "ok", "url": DECLARED["url"],
         "format": "geosite", "sha256": "abc", "at": now - 5},
        {"name": "extra", "kind": "rule_set", "status": "failed",
         "url": "https://e.example/x", "format": None, "at": now - 5},
    ])
    response = await client.get("/api/rulesets")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    rows = response.json()
    assert [r["name"] for r in rows] == ["extra", "geo"]
    geo = next(r for r in rows if r["name"] == "geo")
    assert geo["format"] == "geosite" and geo["status"] == "ok" and geo["stale"] is False
    assert geo["sha256"] == "abc"
    extra = next(r for r in rows if r["name"] == "extra")
    assert extra["status"] == "failed" and extra["stale"] is True
    # No secret marker ever appears in a rule-set source response.
    assert "ciphertext" not in response.text and "redacted" not in response.text


async def test_rulesets_list_reports_agent_unavailable(api, monkeypatch):
    from vs_router.api.errors import APIError
    client, _, _ = api
    await sign_in(client)
    _patch_agent(monkeypatch, error=APIError(503, "agent.unavailable"))
    assert (await client.get("/api/rulesets")).status_code == 503


async def test_ruleset_update_forwards_typed_rpc(api, monkeypatch):
    client, _, _ = api
    await sign_in(client)
    calls = []
    _patch_agent(monkeypatch, history=[], capture=calls)
    response = await client.post("/api/rulesets/update", json={
        "name": "geo", "url": DECLARED["url"], "kind": "rule_set",
        "format": "auto", "authorized": True,
    })
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert len(calls) == 1 and calls[0][0] == "update_source"
    assert calls[0][1].name == "geo" and calls[0][1].authorized is True


async def test_ruleset_update_rejects_malformed_params(api):
    client, _, _ = api
    await sign_in(client)
    response = await client.post("/api/rulesets/update", json={"name": "1bad", "url": "https://x/"})
    assert response.status_code == 422


async def test_ruleset_update_is_admin_only(api, monkeypatch):
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from vs_router.db import UserRow
    client, engine, _ = api
    await sign_in(client)
    _patch_agent(monkeypatch, history=[])
    with Session(engine) as db:
        db.scalar(select(UserRow)).role = "operator"
        db.commit()
    # Read-only view is allowed for an operator...
    assert (await client.get("/api/rulesets")).status_code == 200
    # ...but the privileged update is not.
    response = await client.post("/api/rulesets/update", json={
        "name": "geo", "url": DECLARED["url"], "authorized": True})
    assert response.status_code == 403
