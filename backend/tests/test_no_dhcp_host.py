"""A host whose profile has no DHCP server (the panel installs no Kea, ADR-0021).

Such a host has no ``kea`` phase at all: it must not run, must not be required by
a configuration that serves nothing, and must fail loudly when one does.
"""
import json
from pathlib import Path

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from vs_router.agent import boot_restore
from vs_router.agent.apply import (APPLIED_DIR, FILES, PHASE_TOOLS, ApplyEngine,
                                   ApplyError, host_files)


def without_kea():
    return {name: filename for name, filename in FILES.items() if name not in PHASE_TOOLS}


def engine_without_kea(fs, executor):
    return ApplyEngine(filesystem=fs, executor=executor, files=without_kea())


def dhcp_snapshot(i=1):
    """A configuration that DOES serve addresses."""
    return {'id': i, 'status': 'draft', 'configuration': {
        'interfaces': [{'name': 'lan0', 'type': 'physical', 'zone': 'lan',
                        'addressing': 'static', 'addresses': ['10.0.0.1/24']}],
        'dhcp_subnets': [{'id': 1, 'interface': 'lan0', 'subnet': '10.0.0.0/24',
                          'pools': [{'start': '10.0.0.100', 'end': '10.0.0.200'}]}]}}


def test_host_files_drops_a_phase_whose_engine_binary_is_absent():
    present = host_files(which=lambda name: f'/usr/sbin/{name}')
    missing = host_files(which=lambda name: None)
    assert set(present) == set(FILES)
    assert set(missing) == set(FILES) - set(PHASE_TOOLS)
    assert 'kea' not in missing
    # The real probe only ever removes phases; it never invents one.
    assert set(host_files()) <= set(FILES)


def test_a_host_without_kea_applies_without_a_kea_phase():
    fs, executor = FakeFS(), FakeExecutor()
    result = engine_without_kea(fs, executor).apply_version(snapshot())
    assert result.status == 'confirmed'
    assert set(result.phases) == set(without_kea())
    assert APPLIED_DIR / 'kea.json' not in fs.files
    assert APPLIED_DIR / 'nftables.conf' in fs.files


def test_refuses_to_apply_addresses_it_cannot_serve():
    """A subnet nobody serves must never be installed silently."""
    fs, executor = FakeFS(), FakeExecutor()
    with pytest.raises(ApplyError) as failure:
        engine_without_kea(fs, executor).apply_version(dhcp_snapshot())
    assert failure.value.code == 'kea.unavailable'
    assert not any(APPLIED_DIR / name in fs.files for name in without_kea().values())


def test_rollback_on_a_host_without_kea_skips_the_kea_phase():
    fs, executor = FakeFS(), FakeExecutor()
    engine = engine_without_kea(fs, executor)
    engine.apply_version(snapshot())
    engine.apply_version(snapshot(2), True, 60)
    result = engine.rollback('timeout')
    assert result.status == 'rolled_back'
    assert 'kea' not in result.phases
    assert APPLIED_DIR / 'kea.json' not in fs.files


def test_boot_recovery_tolerates_a_snapshot_without_kea(monkeypatch):
    """A confirmed snapshot with no kea entry must not abort the boot restore."""
    from vs_router.agent import apply as apply_mod

    fs, executor = FakeFS(), FakeExecutor()
    engine = engine_without_kea(fs, executor)
    pending = {'version_id': 1, 'status': 'pending', 'deadline': 4242.0,
               'phases': {'nftables': 'applied'}}
    fs.files[apply_mod.JOURNAL_PATH] = json.dumps(pending)
    fs.files[apply_mod.MARKER_PATH] = json.dumps(pending)
    fs.files[apply_mod.CONFIRMED_DIR / 'snapshot.json'] = json.dumps(
        {'version_id': 1, 'files': {name: '' for name in without_kea()},
         'version_snapshot': {'id': 1, 'configuration': {}}})

    monkeypatch.setattr(apply_mod, 'ApplyEngine', lambda: engine)
    monkeypatch.setattr(boot_restore, 'APPLIED', '/run/does-not-matter')
    monkeypatch.setattr('vs_router.management.read_management', lambda: None)

    boot_restore.recover_interrupted_apply()

    assert engine.status()['status'] == 'rolled_back'
    assert Path('/run/does-not-matter/nftables.conf') in fs.files
