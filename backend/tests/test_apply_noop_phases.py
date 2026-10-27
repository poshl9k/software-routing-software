"""No-op apply still validates and proves live TProxy readiness (offline only)."""
from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from test_agent_apply import FakeFS, snapshot
from test_tproxy_apply_integration import enabled_version
from vs_router.agent import singbox_service, tproxy_apply
from vs_router.agent.apply import (APPLIED_DIR, FILES, JOURNAL_PATH,
                                   MARKER_PATH, PENDING_DIR, ApplyEngine)
from vs_router.schema import ConfigurationVersion


class RecordingFS(FakeFS):
    def __init__(self):
        super().__init__()
        self.moves = []

    def atomic_move(self, source, destination):
        self.moves.append((source, destination))
        super().atomic_move(source, destination)


class ActiveExecutor:
    def __init__(self):
        self.calls = []
        self.active = True
        self.tables = True

    def run(self, argv, timeout):
        self.calls.append(argv)
        if argv == ['systemctl', 'is-active', '--quiet', singbox_service.SINGBOX_UNIT]:
            return SimpleNamespace(returncode=0 if self.active else 3)
        if argv == ['/usr/sbin/nft', 'list', 'tables']:
            return SimpleNamespace(returncode=0, stdout=''.join(
                f'table {name}\n' for name in tproxy_apply.owned_tables()) if self.tables else '')
        return SimpleNamespace(returncode=0)


def rig():
    fs, executor = RecordingFS(), ActiveExecutor()
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: 100.0)
    events = []
    engine.reload_commands = {
        **{name: lambda path, name=name: events.append(name) for name in
           ('nftables', 'wireguard', 'tproxy_guards', 'tproxy_interception')},
        tproxy_apply.POLICY_ROUTE_STEP: lambda: events.append('policy'),
        tproxy_apply.SINGBOX_PROCESS_STEP: lambda: events.append('singbox_process'),
    }
    validated = []

    def validate(name, path):
        validated.append((name, path))
        return SimpleNamespace(returncode=0)

    validators = {name: validate for name in {*FILES, *tproxy_apply.TPROXY_FILES}}
    return engine, fs, executor, events, validated, validators


def apply(engine, validators, version):
    result = engine.apply_version(version, validators=validators)
    assert result.status == 'confirmed'
    return result


def next_version(version, **updates):
    return version.model_copy(update={"id": (version.id or 1) + 1,
                                      "configuration": version.configuration.model_copy(update=updates)})


def test_criterion_1_identical_singbox_active_skips_process_but_records_phase():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    events.clear()
    result = apply(engine, validators, next_version(first))
    assert 'singbox_process' not in events
    assert ['systemctl', 'is-active', '--quiet', singbox_service.SINGBOX_UNIT] in executor.calls
    assert result.phases['singbox_process'] == 'applied'
    marker = engine.status()
    assert marker is not None and marker['phases']['singbox_process'] == 'applied'
    assert ('singbox', PENDING_DIR / tproxy_apply.TPROXY_FILES['singbox']) in validated


def test_criterion_1_inactive_singbox_runs_injected_process_even_if_unchanged():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    executor.active = False
    events.clear()
    apply(engine, validators, next_version(first))
    assert events.count('singbox_process') == 1
    assert ['systemctl', 'is-active', '--quiet', singbox_service.SINGBOX_UNIT] in executor.calls


def test_criterion_2_changed_singbox_secret_bytes_run_process(monkeypatch):
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    original = tproxy_apply.build_artifacts
    secret = ['private-first']

    def with_secret(version, key=None):
        artifacts = original(version, key)
        data = json.loads(artifacts['singbox'])
        data['experimental'] = {'credential': secret[0]}
        artifacts['singbox'] = json.dumps(data, indent=2) + '\n'
        return artifacts

    monkeypatch.setattr(tproxy_apply, 'build_artifacts', with_secret)
    apply(engine, validators, first)
    before = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['singbox'])
    secret[0] = 'private-second'
    events.clear()
    apply(engine, validators, next_version(first))
    assert events.count('singbox_process') == 1
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['singbox']) != before


@pytest.mark.parametrize('name', ['nftables', 'wireguard', 'tproxy_guards', 'tproxy_interception'])
def test_criterion_3_unchanged_artifact_validated_without_reload_or_move(name):
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    events.clear()
    fs.moves.clear()
    validated.clear()
    result = apply(engine, validators, next_version(first))
    filename = (FILES | tproxy_apply.TPROXY_FILES)[name]
    assert (name, PENDING_DIR / filename) in validated
    assert name not in events
    assert (PENDING_DIR / filename, APPLIED_DIR / filename) not in fs.moves
    assert PENDING_DIR / filename not in fs.files
    assert result.phases[name] == 'applied'
    if name == 'tproxy_guards':
        assert executor.calls.count(['/usr/sbin/nft', 'list', 'tables']) >= 4
    assert 'ssh' in result.phases and 'networkd' in result.phases


@pytest.mark.parametrize('name', ['nftables', 'wireguard', 'tproxy_guards', 'tproxy_interception'])
def test_criterion_3_changed_artifact_reloads(name, monkeypatch):
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    original = fs.read(APPLIED_DIR / (FILES | tproxy_apply.TPROXY_FILES)[name])
    if name in tproxy_apply.TPROXY_FILES:
        build = tproxy_apply.build_artifacts
        def changed(version, key=None):
            artifacts = build(version, key)
            artifacts[name] += '\n'
            return artifacts
        monkeypatch.setattr(tproxy_apply, 'build_artifacts', changed)
    else:
        import vs_router.agent.apply as apply_module
        generator = {'nftables': 'generate_nftables', 'wireguard': 'serialize_wireguard'}[name]
        build = getattr(apply_module, generator)
        monkeypatch.setattr(apply_module, generator, lambda *args, **kwargs: build(*args, **kwargs) + '\n')
    events.clear()
    fs.moves.clear()
    apply(engine, validators, next_version(first))
    filename = (FILES | tproxy_apply.TPROXY_FILES)[name]
    assert fs.read(APPLIED_DIR / filename) != original
    assert events.count(name) == 1
    assert (PENDING_DIR / filename, APPLIED_DIR / filename) in fs.moves


def test_criterion_3_untrusted_failed_marker_does_not_skip_reload():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    marker = engine.status()
    assert marker is not None
    marker['status'] = 'failed'
    engine.marker(marker)
    events.clear()
    apply(engine, validators, next_version(first))
    for name in ('nftables', 'wireguard', 'tproxy_guards', 'tproxy_interception',
                 'singbox_process'):
        assert events.count(name) == 1


def test_criterion_4_non_tproxy_version_change_keeps_generated_singbox_bytes():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    second = next_version(first, panel_port=8443)
    assert first.configuration != second.configuration
    assert tproxy_apply.build_artifacts(first, b'')['singbox'] == tproxy_apply.build_artifacts(second, b'')['singbox']
    apply(engine, validators, first)
    events.clear()
    apply(engine, validators, second)
    assert events.count('singbox_process') == 0


def test_confirmed_snapshot_without_marker_skips_unchanged_singbox():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    # confirm_version removes both markers after a guarded/safe apply.
    fs.remove(JOURNAL_PATH)
    fs.remove(MARKER_PATH)
    events.clear()
    apply(engine, validators, next_version(first))
    assert 'singbox_process' not in events


def test_stale_applied_snapshot_without_marker_does_not_skip_restart():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    fs.remove(JOURNAL_PATH)
    fs.remove(MARKER_PATH)
    fs.write(APPLIED_DIR / 'snapshot.json', json.dumps({'id': -1}))
    events.clear()
    apply(engine, validators, next_version(first))
    assert events.count('singbox_process') == 1


def test_peer_membership_only_updates_local_set_without_engine_restart(monkeypatch):
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    before_config = fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['singbox'])
    original = tproxy_apply.build_artifacts

    def peer_added(version, key=None):
        artifacts = original(version, key)
        peers = json.loads(artifacts['subscriber_peers'])
        peers['rules'] = [{'source_ip_cidr': ['10.66.66.3/32']}]
        artifacts['subscriber_peers'] = json.dumps(peers, indent=2) + '\n'
        return artifacts

    monkeypatch.setattr(tproxy_apply, 'build_artifacts', peer_added)
    events.clear()
    fs.moves.clear()
    result = apply(engine, validators, next_version(first))
    filename = tproxy_apply.TPROXY_FILES['subscriber_peers']
    assert (PENDING_DIR / filename, APPLIED_DIR / filename) in fs.moves
    assert fs.read(APPLIED_DIR / filename) == peer_added(first)['subscriber_peers']
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['singbox']) == before_config
    assert 'singbox_process' not in events
    assert result.phases['subscriber_peers'] == 'applied'


def test_pending_peer_set_rollback_restores_confirmed_membership(monkeypatch):
    engine, fs, executor, events, validated, validators = rig()
    data = enabled_version().model_dump(mode='json')
    data['id'] = 1
    data['configuration']['routing_rules'] = [
        {'name': 'direct', 'ip_cidr': ['203.0.113.0/24']}]
    first = ConfigurationVersion.model_validate(data)
    apply(engine, validators, first)
    path = APPLIED_DIR / tproxy_apply.TPROXY_FILES['subscriber_peers']
    original_set = fs.read(path)
    original = tproxy_apply.build_artifacts

    def peer_added(version, key=None):
        artifacts = original(version, key)
        artifacts['subscriber_peers'] = json.dumps({
            'version': 3, 'rules': [{'source_ip_cidr': ['10.66.66.3/32']}]
        }, indent=2) + '\n'
        return artifacts

    monkeypatch.setattr(tproxy_apply, 'build_artifacts', peer_added)
    pending = engine.apply_version(next_version(first), safe_mode=True, validators=validators)
    assert pending.status == 'pending'
    assert fs.read(path) != original_set
    rolled_back = engine.rollback('test')
    assert rolled_back.status == 'rolled_back'
    assert fs.read(path) == original_set


def test_staged_singbox_validation_uses_staged_peer_set():
    engine, fs, executor, events, validated, validators = rig()
    files = dict(tproxy_apply.TPROXY_FILES)
    contents = tproxy_apply.build_artifacts(enabled_version())
    marker = {'phases': {}, 'version_id': 1}
    runtime_validators = {**validators,
                          'subscriber_peers': tproxy_apply.TPROXY_VALIDATORS['subscriber_peers'],
                          'singbox': tproxy_apply.TPROXY_VALIDATORS['singbox']}
    engine._install(contents, marker, runtime_validators, files=files)
    compile_call = next(call for call in executor.calls if 'rule-set' in call)
    assert compile_call[-1] == str(PENDING_DIR / files['subscriber_peers'])
    check_call = next(call for call in executor.calls if 'check' in call)
    assert check_call[-1] == str(PENDING_DIR / 'singbox-check.json')
    assert PENDING_DIR / 'singbox-check.json' not in fs.files
    assert PENDING_DIR / 'subscriber-peers-check.srs' not in fs.files


def test_criterion_3_missing_live_guards_are_reloaded_before_readiness():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    executor.tables = False
    original = engine.reload_commands['tproxy_guards']

    def restore_guards(path):
        original(path)
        executor.tables = True

    engine.reload_commands['tproxy_guards'] = restore_guards
    events.clear()
    result = engine.apply_version(next_version(first), validators=validators)
    assert result.status == 'confirmed'
    assert events.count('tproxy_guards') == 1
    assert result.phases['tproxy_guards'] == 'applied'


def test_criterion_3_missing_live_guards_fail_verification_even_without_reloading():
    engine, fs, executor, events, validated, validators = rig()
    first = enabled_version().model_copy(update={'id': 1})
    apply(engine, validators, first)
    executor.tables = False
    result = engine.apply_version(next_version(first), validators=validators)
    assert result.status != 'confirmed'
    assert 'tproxy_interception' not in events[-1:]
