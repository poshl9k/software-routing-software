"""Catalog port, offline helpers, and authenticated read-only API."""
import hashlib
import json
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from vs_router.agent.presets import (
    CatalogPreset, CatalogRuleSet, load_catalog, selection_to_domains,
    selection_to_rule_sets, service_rule_set_format, WARNING_LICENSE_UNVERIFIED,
)
from vs_router.agent import presets as presets_module
from vs_router.db import UserRow
from test_api import api, sign_in

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


#: SHA-256 of the committed catalog = verbatim copy of awg-manager
#: ``internal/presets/defaults.json`` at port time (no local edits). Pinned so the
#: test is self-contained and does not depend on a transient reference checkout.
CATALOG_SHA256 = '48a555798291933b001c3385ec5247aaa424da5afe4f9d22e31cfd897843d19b'


def test_catalog_is_verbatim_and_typed():
    copied = Path(__file__).parents[1] / 'src/vs_router/agent/presets_catalog.json'
    assert hashlib.sha256(copied.read_bytes()).hexdigest() == CATALOG_SHA256
    raw = json.loads(copied.read_text())
    entries = load_catalog()
    assert len(raw) == len(entries) == 88
    assert [e.id for e in entries] == [e['id'] for e in raw]
    assert all(e.license_verified is False and WARNING_LICENSE_UNVERIFIED in e.provenance for e in entries)
    anthropic = next(e for e in entries if e.id == 'anthropic')
    assert anthropic.name == 'Anthropic / Claude'
    assert anthropic.dns_domains == ('anthropic.com', 'claude.ai', 'claude.com')
    assert anthropic.rule_sets[0].tag == 'geosite-anthropic'
    meta = {e.id: e.covers for e in entries if e.covers}
    assert set(meta) == {'category-ai', 'dev-tools', 'category-games', 'category-media', 'google', 'meta'}
    assert 'anthropic' in meta['category-ai']


def test_helpers_are_stable_and_accept_hyphen_tags(monkeypatch):
    ids = ('anthropic', 'anthropic')
    assert selection_to_domains(ids) == ('anthropic.com', 'claude.ai', 'claude.com')
    assert selection_to_domains(ids) == selection_to_domains(ids)
    # Engine tags may contain hyphens (sing-box convention, e.g. geosite-anthropic).
    rules = selection_to_rule_sets(ids)
    assert len(rules) == 1
    assert rules[0].name == 'geosite-anthropic' and rules[0].format == 'srs'
    with pytest.raises(ValueError, match='preset.unknown_service'):
        selection_to_domains(('does-not-exist',))
    assert selection_to_rule_sets(()) == ()

    bad = CatalogPreset(
        id='bad', name='Bad', icon_slug='bad', category='ai', origin='', notice=None,
        covers=(), dns_domains=('example.org',),
        rule_sets=(CatalogRuleSet(tag='bad tag', url='https://example.org/x.srs'),),
        action='tunnel',
    )
    monkeypatch.setattr(presets_module, 'load_catalog', lambda: (bad,))
    with pytest.raises(ValueError, match='preset.invalid_rule_set_tag'):
        selection_to_rule_sets(('bad',))


def test_helper_success_for_schema_compatible_tags(monkeypatch):
    """Helper generates valid models when schema accepts upstream tags."""
    service = CatalogPreset(
        id='fixture', name='Fixture', icon_slug='fixture', category='ai',
        origin='', notice=None, covers=(), dns_domains=('example.org',),
        rule_sets=(CatalogRuleSet(tag='geosite_fixture', url='https://example.org/fixture.srs'),),
        action='tunnel',
    )
    monkeypatch.setattr(presets_module, 'load_catalog', lambda: (service,))
    rules = selection_to_rule_sets(('fixture', 'fixture'))
    assert len(rules) == 1
    assert (rules[0].name, rules[0].format, rules[0].url) == (
        'geosite_fixture', 'srs', 'https://example.org/fixture.srs')
    assert selection_to_domains(('fixture', 'fixture')) == ('example.org',)
    assert service_rule_set_format('https://example.org/set.json?rev=1') == 'json'
    with pytest.raises(ValueError, match='preset.invalid_rule_set_format'):
        service_rule_set_format('https://example.org/unknown.txt')


async def test_catalog_api_auth_shape_counts_and_declared(api):
    client, engine, _ = api
    assert (await client.get('/api/presets/catalog')).status_code == 401
    await sign_in(client)
    response = await client.get('/api/presets/catalog')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    data = response.json()
    assert set(data) == {'categories', 'services'}
    assert [(c['key'], c['title'], c['count']) for c in data['categories']] == [
        ('social', 'Соцсети', 16), ('media', 'Медиа', 16),
        ('developer', 'Разработка', 15), ('cloud', 'Облако', 12),
        ('gaming', 'Игры', 11), ('ai', 'AI', 6), ('block', 'Блок', 6),
    ]
    assert len(data['services']) == 88
    anthropic = next(e for e in data['services'] if e['id'] == 'anthropic')
    assert set(anthropic) == {'id', 'name', 'category', 'icon_slug', 'notice',
                              'covers', 'dns_domains', 'rule_sets', 'action', 'declared'}
    assert anthropic['rule_sets'] == [{
        'tag': 'geosite-anthropic', 'url': 'https://repo.hoaxisr.ru/rulesets/srs/claude.srs',
        'format': 'srs',
    }]
    assert anthropic['action'] == 'tunnel' and anthropic['declared'] is False
    assert next(e for e in data['services'] if e['id'] == 'category-ai')['covers']
    # An in-memory draft with the exact tag tests name matching. The schema rejects
    # hyphens on writes; this read-only test documents the existing incompatibility.
    from vs_router.api import rulesets
    original = rulesets._declared
    try:
        rulesets._declared = lambda db: [{'name': 'geosite-anthropic'}]
        declared = await client.get('/api/presets/catalog')
        assert next(e for e in declared.json()['services'] if e['id'] == 'anthropic')['declared'] is True
    finally:
        rulesets._declared = original
    with Session(engine) as db:
        db.scalar(select(UserRow)).role = 'operator'
        db.commit()
    assert (await client.get('/api/presets/catalog')).status_code == 200
