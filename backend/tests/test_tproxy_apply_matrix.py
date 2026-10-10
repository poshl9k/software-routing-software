"""Engine failure-injection matrix for the gated sing-box TProxy apply path.

Offline only (``FakeFS``/``FakeExecutor``, no host, no shell). The public gate
``tproxy.not_available`` stays closed, so the enabled branch is reachable solely
through the offline ``model_copy`` snapshot
(:func:`test_tproxy_apply_integration.enabled_version`).

The matrix injects a failure at *each* TProxy phase and pins the atomicity and
safety invariants the plan (``docs/sing-box-tproxy-plan.md`` §«1. Контракт и
контролируемый процесс») requires:

* successful activation: staged -> validated -> applied -> commit, guards before
  the capture table;
* compensation/rollback when guards, readiness (engine file *and* both typed
  steps) or interception fails, returning to the confirmed baseline and leaving
  the host boot-safe;
* safe-mode timer: an unconfirmed pending version rolls back on deadline;
* first apply without a confirmed baseline: every owned artifact is torn down;
* rollback against an old snapshot that carries no sing-box file;
* boot_restore: guards are raised before the product tract, and a pending version
  is never promoted by a reboot.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_agent_apply import FakeFS, FakeExecutor, snapshot
from test_tproxy_apply_integration import enabled_version
from vs_router.agent import boot_restore, singbox_service, tproxy_apply
from vs_router.agent.apply import (APPLIED_DIR, CONFIRMED_DIR, FILES, ApplyEngine,
                                   ApplyError)
from vs_router.agent.rollback_check import check_deadline


def _engine(fs, executor, now):
    original = executor.run
    def with_loaded_tables(argv, timeout):
        if argv == ['/usr/sbin/nft', 'list', 'tables']:
            return SimpleNamespace(returncode=0, stdout=''.join(
                f'table {name}\n' for name in tproxy_apply.owned_tables()))
        return original(argv, timeout)
    executor.run = with_loaded_tables
    return ApplyEngine(filesystem=fs, executor=executor, clock=lambda: now[0])


def _recording_validators(order):
    def validator(name, path):
        order.append(name)
        return SimpleNamespace(returncode=0)
    return {name: validator for name in {*FILES, *tproxy_apply.TPROXY_FILES}}


def _confirmed_baseline(engine, fs):
    """Apply the ordinary (enabled=False) snapshot; return its live file set."""
    assert engine.apply_version(snapshot()).status == 'confirmed'
    return {name: fs.read(APPLIED_DIR / filename) for name, filename in FILES.items()}


def _fail_on(executor, argv_prefix):
    original = executor.run

    def run(argv, timeout):
        if argv[:1] == [argv_prefix]:
            return SimpleNamespace(returncode=1)
        return original(argv, timeout)
    executor.run = run


def _live_applied(fs):
    return {Path(p).name for p in fs.files if str(APPLIED_DIR) in str(p)}


# --------------------------------------------------------------------------
# Success: staged -> validated -> applied -> commit, guards before capture
# --------------------------------------------------------------------------

def test_successful_activation_commits_every_phase():
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    seen = {}

    def policy():
        # Snapshot of what is already live in APPLIED at the readiness step.
        seen['during'] = _live_applied(fs)

    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: policy,
                              tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None}
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))

    assert result.status == 'confirmed'
    marker = engine.status()
    assert marker['status'] == 'confirmed'
    assert marker['deadline'] is None
    # Every scaffold artifact reached the terminal 'applied' phase.
    for name in tproxy_apply.TPROXY_FILES:
        assert marker['phases'][name] == 'applied'
    # Guards (and the engine config) are live before interception is authorized;
    # the capture table is not yet present during readiness.
    assert tproxy_apply.TPROXY_FILES['tproxy_guards'] in seen['during']
    assert tproxy_apply.TPROXY_FILES['singbox'] in seen['during']
    assert tproxy_apply.TPROXY_FILES['tproxy_interception'] not in seen['during']
    # Commit: the confirmed snapshot carries the whole (TProxy) file map.
    assert APPLIED_DIR / 'snapshot.json' in fs.files
    backup = json.loads(fs.read(CONFIRMED_DIR / 'snapshot.json'))
    assert set(tproxy_apply.TPROXY_FILES) <= set(backup['files'])
    assert set(tproxy_apply.TPROXY_FILES.values()) <= _live_applied(fs)


# --------------------------------------------------------------------------
# Failure at each phase: compensate, return to the confirmed baseline
# --------------------------------------------------------------------------

def _arm_failure(engine, executor, reload=None, step=None, stub_steps=False):
    commands = {}
    if stub_steps:
        # Isolate the interception-phase failure from the live readiness
        # adapters (they verify the pinned binary, which needs a real host).
        commands[tproxy_apply.POLICY_ROUTE_STEP] = lambda: None
        commands[tproxy_apply.SINGBOX_PROCESS_STEP] = lambda: None
    if reload is not None:
        name, argv = reload
        commands[name] = [argv]
        _fail_on(executor, argv)
    if step is not None:
        def boom():
            raise ApplyError('agent.reload_failed')
        commands[step] = boom
    engine.reload_commands = commands


FAILURE_CASES = {
    # phase "guards": reload of the protective tables fails
    'guards_reload': dict(reload=('tproxy_guards', 'fail-guard')),
    # phase "readiness": engine config reload fails
    'readiness_engine_reload': dict(reload=('singbox', 'fail-engine')),
    # phase "readiness": the typed policy-route step fails
    'readiness_policy_step': dict(step=tproxy_apply.POLICY_ROUTE_STEP),
    # phase "readiness": the typed engine-process step fails
    'readiness_process_step': dict(step=tproxy_apply.SINGBOX_PROCESS_STEP),
    # phase "interception": capture table reload fails (steps stubbed so the
    # failure lands on the capture table, not on the live engine adapter)
    'interception_reload': dict(reload=('tproxy_interception', 'fail-capture'),
                                stub_steps=True),
}


@pytest.mark.parametrize('case', list(FAILURE_CASES))
def test_failure_at_each_phase_rolls_back_and_restores_confirmed(case):
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    baseline = _confirmed_baseline(engine, fs)

    _arm_failure(engine, executor, **FAILURE_CASES[case])
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))

    # The apply failed and compensated against the confirmed (non-TProxy) target.
    assert result.status == 'rolled_back'
    assert result.reason == 'agent.reload_failed'
    status = engine.status()
    assert status['status'] == 'rolled_back'
    assert status['phases'].get('rollback') == 'rolled_back'
    # The confirmed baseline is byte-for-byte restored.
    assert fs.read(APPLIED_DIR / FILES['nftables']) == baseline['nftables']
    # No TProxy-owned artifact survives except the guard, which is now
    # destroy-only so a reboot can never re-raise the fail-closed tables.
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['tproxy_guards']) \
        == tproxy_apply.cleanup_content()
    for filename in tproxy_apply.teardown_files():
        assert APPLIED_DIR / filename not in fs.files
    # Compensation also ran the table teardown and stopped the engine / route.
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE) == tproxy_apply.cleanup_content()
    argv = [call for call, _ in executor.calls]
    assert ['systemctl', 'disable', '--now', singbox_service.SINGBOX_UNIT] in argv
    assert ['ip', 'rule', 'del', 'priority', '100', 'fwmark', '0x100',
            'lookup', '100'] in argv


@pytest.mark.parametrize('case', ['guards_reload', 'readiness_engine_reload',
                                  'interception_reload'])
def test_reload_failure_names_the_failing_service(case):
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    _confirmed_baseline(engine, fs)
    _arm_failure(engine, executor, **FAILURE_CASES[case])

    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))

    expected = FAILURE_CASES[case]['reload'][0]
    assert result.status == 'rolled_back'
    assert result.reason_service == expected
    assert engine.status()['reason_service'] == expected


def test_validation_failure_before_any_mutation_does_not_rollback():
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    baseline = _confirmed_baseline(engine, fs)

    def bad(name, path):
        return SimpleNamespace(returncode=1)

    validators = _recording_validators([])
    validators['tproxy_guards'] = bad
    result = engine.apply_version(enabled_version(), validators=validators)

    # Guards fail validation: nothing went live, so no live file was touched and
    # the confirmed baseline is intact.
    assert result.status == 'failed'
    assert result.error['code'] == 'agent.validation_failed'
    assert fs.read(APPLIED_DIR / FILES['nftables']) == baseline['nftables']
    assert tproxy_apply.TPROXY_FILES['tproxy_guards'] not in _live_applied(fs)


# --------------------------------------------------------------------------
# Safe mode: unconfirmed pending version rolls back on the deadline
# --------------------------------------------------------------------------

def test_safe_mode_deadline_rolls_back_pending_tproxy():
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    baseline = _confirmed_baseline(engine, fs)
    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: lambda: None,
                              tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None}

    result = engine.apply_version(enabled_version(), safe_mode=True,
                                  confirmation_timeout=60,
                                  validators=_recording_validators([]))
    assert result.status == 'pending'
    marker = engine.status()
    assert marker['status'] == 'pending'
    assert marker['deadline'] == 160

    # The deadline expires with no confirmation: the timer rolls the pending
    # version back to the confirmed baseline.
    now[0] = 160
    assert check_deadline(engine.status(), engine.rollback, lambda: now[0])
    status = engine.status()
    assert status['status'] == 'rolled_back'
    assert status['reason'] == 'timeout'
    assert fs.read(APPLIED_DIR / FILES['nftables']) == baseline['nftables']
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['tproxy_guards']) \
        == tproxy_apply.cleanup_content()


def test_confirmed_tproxy_version_backs_up_the_whole_file_map():
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    _confirmed_baseline(engine, fs)
    engine.reload_commands = {tproxy_apply.POLICY_ROUTE_STEP: lambda: None,
                              tproxy_apply.SINGBOX_PROCESS_STEP: lambda: None}
    assert engine.apply_version(enabled_version(), safe_mode=True,
                                validators=_recording_validators([])).status == 'pending'

    assert engine.confirm_version(1)['status'] == 'confirmed'
    backup = json.loads(fs.read(CONFIRMED_DIR / 'snapshot.json'))
    # Confirmation keeps the additive TProxy artifacts, not a FILES-only backup.
    assert set(tproxy_apply.TPROXY_FILES) <= set(backup['files'])
    assert engine.status() is None


# --------------------------------------------------------------------------
# First apply with no confirmed baseline
# --------------------------------------------------------------------------

def test_first_apply_without_baseline_tears_everything_down():
    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    engine.reload_commands = {tproxy_apply.SINGBOX_PROCESS_STEP:
                              (lambda: (_ for _ in ()).throw(ApplyError('agent.reload_failed')))}

    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))

    # There is no rollback target; the scaffold still forces a teardown.
    assert result.status == 'failed'
    assert CONFIRMED_DIR / 'snapshot.json' not in fs.files
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_FILES['tproxy_guards']) \
        == tproxy_apply.cleanup_content()
    for filename in tproxy_apply.teardown_files():
        assert APPLIED_DIR / filename not in fs.files
    assert engine.status()['status'] == 'rolled_back'


# --------------------------------------------------------------------------
# Old snapshot without sing-box files
# --------------------------------------------------------------------------

def test_old_snapshot_has_no_singbox_file_and_rolls_back_cleanly():
    from vs_router.agent.apply import _tproxy_branch_from_snapshot

    fs, executor, now = FakeFS(), FakeExecutor(), [100.0]
    engine = _engine(fs, executor, now)
    baseline = _confirmed_baseline(engine, fs)
    backup = json.loads(fs.read(CONFIRMED_DIR / 'snapshot.json'))
    assert 'singbox' not in backup['files']
    # An old snapshot (and an un-revalidatable enabled one) yields the empty
    # branch rather than raising during compensation.
    assert _tproxy_branch_from_snapshot(backup['version_snapshot']) == ({}, {})
    assert _tproxy_branch_from_snapshot(enabled_version().model_dump(mode='json')) == ({}, {})

    engine.reload_commands = {'tproxy_interception': ['fail-capture']}
    _fail_on(executor, 'fail-capture')
    result = engine.apply_version(enabled_version(), validators=_recording_validators([]))

    assert result.status == 'rolled_back'
    assert 'singbox.json' not in _live_applied(fs)
    assert fs.read(APPLIED_DIR / tproxy_apply.TPROXY_CLEANUP_FILE) == tproxy_apply.cleanup_content()
    assert fs.read(APPLIED_DIR / FILES['nftables']) == baseline['nftables']


# --------------------------------------------------------------------------
# Boot: guards before the tract; pending is never promoted
# --------------------------------------------------------------------------

def test_boot_recover_never_promotes_pending_and_tears_down_interrupted_tproxy(monkeypatch):
    from vs_router.agent import apply as apply_mod
    fs, executor = FakeFS(), FakeExecutor()
    engine = _engine(fs, executor, [100.0])
    pending = {'version_id': 1, 'status': 'pending', 'deadline': 4242.0,
               'phases': {'nftables': 'applied', 'tproxy_guards': 'applied'}}
    fs.files[apply_mod.JOURNAL_PATH] = json.dumps(pending)
    fs.files[apply_mod.MARKER_PATH] = json.dumps(pending)
    confirmed_by = {'version_id': 1, 'files': {name: '' for name in FILES},
                    'version_snapshot': {'id': 1, 'configuration': {}}}
    fs.files[apply_mod.CONFIRMED_DIR / 'snapshot.json'] = json.dumps(confirmed_by)

    monkeypatch.setattr(apply_mod, 'ApplyEngine', lambda: engine)
    monkeypatch.setattr(boot_restore, 'APPLIED', '/run/does-not-matter')
    monkeypatch.setattr('vs_router.management.read_management', lambda: None)

    boot_restore.recover_interrupted_apply()

    status = engine.status()
    assert status['status'] == 'rolled_back'
    assert status['reason'] == 'reboot'
    # The half-open guard is replaced by destroy-only teardown, never restored.
    guard = fs.read(Path('/run/does-not-matter') / tproxy_apply.TPROXY_FILES['tproxy_guards'])
    assert guard == tproxy_apply.cleanup_content()
    for filename in tproxy_apply.cleanup_files():
        assert Path('/run/does-not-matter') / filename not in fs.files


def test_boot_restores_guards_before_the_product_tract(monkeypatch, tmp_path):
    applied = tmp_path / 'applied'
    applied.mkdir()
    (applied / tproxy_apply.TPROXY_FILES['tproxy_guards']).write_text(
        tproxy_apply.cleanup_content())
    (applied / 'nftables.conf').write_text('table inet vs_router {}\n')

    monkeypatch.setattr(boot_restore, 'APPLIED', str(applied))
    monkeypatch.setattr('vs_router.agent.management_console.check', lambda: None)
    monkeypatch.setattr('vs_router.management.read_management', lambda: None)
    monkeypatch.setattr(boot_restore, 'recover_interrupted_apply', lambda: None)
    monkeypatch.setattr(boot_restore, 'restore_tunnel_proxy_files', lambda: 0)
    monkeypatch.setattr(boot_restore, 'restore_ssh', lambda: None)

    order = []
    monkeypatch.setattr(boot_restore, 'run', lambda argv: order.append(argv) or 0)

    assert boot_restore.main() == 0
    guard = ['/usr/sbin/nft', '-f', str(applied / tproxy_apply.TPROXY_FILES['tproxy_guards'])]
    nft = ['/usr/sbin/nft', '-f', str(applied / 'nftables.conf')]
    assert guard in order and nft in order
    # The fail-closed guard is raised before the product firewall loads.
    assert order.index(guard) < order.index(nft)
