"""Rule-set profiles: strict format↔content mismatch, limits, staleness, ``.srs``.

Offline only: ``validate_ruleset`` never touches the network.
"""
import hashlib

import pytest
from pydantic import ValidationError

from vs_router.agent.rulesets import (RuleSetError, SourceProfile, validate_ruleset,
                                      staleness)


def profile(fmt="text-domain", **overrides):
    fields = dict(name="set1", format=fmt, url="https://example.org/rules")
    fields.update(overrides)
    return SourceProfile(**fields)  # type: ignore[arg-type]


def code_of(exc_info):
    return exc_info.value.code


# ---------------------------------------------------------------------------
# profile model
# ---------------------------------------------------------------------------

def test_profile_requires_https_and_closed_format():
    with pytest.raises(ValidationError, match="ruleset.https_required"):
        SourceProfile(name="s", format="json", url="http://example.org/x")
    with pytest.raises(ValidationError):
        SourceProfile(name="s", format="weird", url="https://example.org/x")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# strict format <-> content
# ---------------------------------------------------------------------------

def test_text_domain_accepts_domains_and_rejects_cidr():
    info = validate_ruleset("example.com\nsub.example.org\n# comment\n", profile("text-domain"))
    assert info.records == 2 and info.activatable is True
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("10.0.0.0/8\n", profile("text-domain"))
    assert code_of(exc) == "ruleset.format_mismatch"


def test_text_cidr_accepts_cidr_and_rejects_domains():
    info = validate_ruleset("10.0.0.0/8\n2001:db8::/32\n", profile("text-cidr"))
    assert info.records == 2
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("example.com\n", profile("text-cidr"))
    assert code_of(exc) == "ruleset.format_mismatch"
    # A domain-prefixed line in an address set is still a mismatch.
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("domain:example.com\n", profile("text-cidr"))
    assert code_of(exc) == "ruleset.format_mismatch"


def test_json_ruleset_shape():
    info = validate_ruleset('{"version": 1, "rules": [{"domain_suffix": ["x.com"]}]}',
                            profile("json"))
    assert info.records == 1
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("[]", profile("json"))
    assert code_of(exc) == "ruleset.format_mismatch"
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("{not json", profile("json"))
    assert code_of(exc) == "ruleset.invalid_record"


def test_geosite_and_geoip_are_flagged_for_materialization():
    geo = validate_ruleset("example.com\n", profile("geosite"))
    assert geo.activatable is True and "ruleset.requires_materialization" in geo.warnings
    ip = validate_ruleset("192.0.2.0/24\n", profile("geoip"))
    assert ip.activatable is True and "ruleset.requires_materialization" in ip.warnings


def test_srs_is_recognized_but_not_activatable():
    result = validate_ruleset(b"SRS\x01binary-rule-set-bytes", profile("srs"))
    assert result.format == "srs"
    assert result.activatable is False
    assert "ruleset.srs_requires_pinned_tool" in result.warnings
    assert "ruleset.srs_magic_missing" not in result.warnings
    # A payload without the magic is still reported honestly, not accepted.
    bogus = validate_ruleset(b"not-srs", profile("srs"))
    assert bogus.activatable is False
    assert "ruleset.srs_magic_missing" in bogus.warnings


def test_empty_domain_set_is_refused():
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("# only a comment\n\n", profile("text-domain"))
    assert code_of(exc) == "ruleset.empty"


# ---------------------------------------------------------------------------
# limits and metadata
# ---------------------------------------------------------------------------

def test_record_limit_is_enforced():
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("a.com\nb.com\nc.com\n", profile("text-domain", max_records=2))
    assert code_of(exc) == "ruleset.too_many_records"


def test_byte_limit_is_enforced():
    with pytest.raises(RuleSetError) as exc:
        validate_ruleset("a" * 2000, profile("text-domain", max_bytes=1024))
    assert code_of(exc) == "ruleset.too_large"


def test_hash_and_size_are_reported():
    content = "example.com\n"
    info = validate_ruleset(content, profile("text-domain"))
    assert info.sha256 == hashlib.sha256(content.encode()).hexdigest()
    assert info.size == len(content.encode())
    assert info.format == "text-domain" and info.name == "set1"


def test_staleness():
    assert staleness(now=1000.0, last_success=None).stale is True
    assert staleness(now=1000.0, last_success=900.0).stale is False
    assert staleness(now=1000.0, last_success=1000.0 - 8 * 24 * 3600).stale is True
