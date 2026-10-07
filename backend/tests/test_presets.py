"""Preset source catalog: data/adapter shape, allowlist and licence honesty.

No network: the allowlist is exercised through ``SourceUpdater.build_spec``,
which never resolves or connects.
"""
import sys

sys.path.insert(0, "tests")

import pytest

from test_downloader import FakeTransport, fixed_resolver
from vs_router.agent.downloader import BuiltinSource, DownloadError, SourceStore, SourceUpdater
from vs_router.agent.presets import (CATALOG, WARNING_LICENSE_MISSING,
                                     WARNING_LICENSE_UNVERIFIED, catalog_sources,
                                     catalog_view, selected_catalog_sources)


def test_catalog_selection_is_off_by_default_and_validates_keys():
    assert selected_catalog_sources('') == {}
    chosen = selected_catalog_sources('sing_geosite, rockblack_ip')
    assert set(chosen) == {'sing_geosite', 'rockblack_ip'}
    assert chosen['sing_geosite'] == catalog_sources()['sing_geosite']
    with pytest.raises(ValueError, match='preset.unknown_key'):
        selected_catalog_sources('sing_geosite,missing')


def test_catalog_is_a_small_nonempty_example_set():
    assert CATALOG, "the built-in example catalog must not be empty"
    for key, preset in CATALOG.items():
        assert key == preset.key
        assert preset.hosts, f"{key} must declare at least one allowed host"
        assert preset.url.lower().startswith("https://")
        assert preset.format in ("text-domain", "text-cidr", "json", "geosite", "geoip", "srs")


def test_every_entry_is_explicitly_unverified_for_redistribution():
    # Honesty invariant: nothing in the shipped catalog claims verified licence.
    assert all(preset.license_verified is False for preset in CATALOG.values())


def test_cdn_ip_ranges_has_no_licence_and_is_flagged():
    preset = CATALOG["cjk_cdn_ip"]
    assert preset.license is None
    assert preset.warning() == WARNING_LICENSE_MISSING


def test_entries_with_declared_licence_are_flagged_unverified():
    preset = CATALOG["sing_geosite"]
    assert preset.license is not None
    assert preset.warning() == WARNING_LICENSE_UNVERIFIED


def test_catalog_view_is_sorted_and_carries_provenance():
    view = catalog_view()
    assert [row["key"] for row in view] == sorted(row["key"] for row in view)
    for row in view:
        assert row["provenance"]
        assert row["warning"] in (WARNING_LICENSE_MISSING, WARNING_LICENSE_UNVERIFIED)
        assert row["license_verified"] is False


def test_adapter_yields_downloader_allowlist_entries():
    sources = catalog_sources()
    assert set(sources) == set(CATALOG)
    for key, builtin in sources.items():
        assert isinstance(builtin, BuiltinSource)
        assert builtin.url == CATALOG[key].url
        assert builtin.hosts == frozenset(CATALOG[key].hosts)
        # The url's own host must be in the allowlist, or the downloader would
        # refuse its own built-in.
        assert builtin.url.split("/")[2] in builtin.hosts


def test_catalog_allowlist_is_accepted_and_mismatch_refused(tmp_path):
    sources = catalog_sources()
    updater = SourceUpdater(store=SourceStore(base=tmp_path / "sources"),
                            transport=FakeTransport([]), resolver=fixed_resolver({}),
                            builtin_sources=sources)
    preset = CATALOG["sing_geosite"]
    spec = updater.build_spec(name="sing_geosite", url=preset.url)
    assert spec.builtin is True and spec.allowed_hosts == frozenset(preset.hosts)
    with pytest.raises(DownloadError) as exc:
        updater.build_spec(name="sing_geosite", url="https://evil.example/x")
    assert exc.value.code == "download.builtin_url_mismatch"
