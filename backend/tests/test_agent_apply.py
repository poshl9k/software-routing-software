import json
from types import SimpleNamespace
import pytest
from vs_router.agent.apply import ApplyEngine, ApplyError, MARKER_PATH, APPLIED_DIR, FILES
from vs_router.agent.rollback_check import check_deadline


class FakeFS:
    def __init__(self):
        self.files = {}
    def write(self, path, content):
        self.files[path] = content
    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]
    def remove(self, path):
        self.files.pop(path, None)
    def atomic_move(self, source, destination):
        self.write(destination, self.read(source))
        self.remove(source)


class FakeExecutor:
    def __init__(self):
        self.calls = []
        self.fail = False
    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        return SimpleNamespace(returncode=int(self.fail))


@pytest.fixture
def pipeline():
    fs, executor = FakeFS(), FakeExecutor()
    now = [100.0]
    engine = ApplyEngine(filesystem=fs, executor=executor, clock=lambda: now[0])
    return engine, fs, executor, now


def snapshot(i=1):
    return {'id': i, 'status': 'draft', 'configuration': {}}


def test_success_and_confirm(pipeline):
    engine, fs, executor, now = pipeline
    assert engine.apply_version(snapshot()).status == 'confirmed'
    assert len(executor.calls) == len(FILES)
    assert all(timeout == 15 for _, timeout in executor.calls)
    assert engine.apply_version(snapshot(2), True, 60).status == 'pending'
    assert json.loads(fs.read(MARKER_PATH))['deadline'] == 160
    with pytest.raises(ApplyError, match='apply_pending'):
        engine.apply_version(snapshot(3))
    with pytest.raises(ApplyError, match='version_mismatch'):
        engine.confirm_version(1)
    assert engine.confirm_version(2)['status'] == 'confirmed'
    assert engine.status() is None


def test_validator_failure_does_not_touch_live_files(pipeline):
    engine, fs, executor, _ = pipeline
    executor.fail = True
    result = engine.apply_version(snapshot())
    assert result.status == 'failed'
    assert result.error['code'] == 'agent.validation_failed'
    assert engine.status()['status'] == 'failed'
    assert not any(APPLIED_DIR / f in fs.files for f in FILES.values())


def test_rollback_restores_confirmed(pipeline):
    engine, fs, _, _ = pipeline
    engine.apply_version(snapshot())
    originals = {f: fs.read(APPLIED_DIR / f) for f in FILES.values()}
    engine.apply_version(dict(snapshot(2), configuration={'panel_port': 8443}), True)
    assert engine.rollback('timeout').status == 'rolled_back'
    assert engine.status()['phases']['rollback'] == 'rolled_back'
    assert engine.status()['reason'] == 'timeout'
    assert all(fs.read(APPLIED_DIR / f) == text for f, text in originals.items())


@pytest.mark.parametrize('now,expected', [(159, False), (160, True), (161, True)])
def test_deadline(pipeline, now, expected):
    engine, _, _, _ = pipeline
    engine.apply_version(snapshot())
    engine.apply_version(snapshot(2), True, 60)
    calls = []
    assert check_deadline(engine.status(), calls.append, lambda: now) == expected
    assert calls == (['timeout'] if expected else [])


def test_expired_confirmation_rolls_back(pipeline):
    engine, _, _, now = pipeline
    engine.apply_version(snapshot())
    engine.apply_version(snapshot(2), True, 60)
    now[0] = 160
    with pytest.raises(ApplyError, match='confirmation_expired'):
        engine.confirm_version(2)
    assert engine.status()['status'] == 'rolled_back'


def test_probe_failure(pipeline):
    engine, _, _, _ = pipeline
    engine.apply_version(snapshot())
    engine.panel_probe = lambda: False
    assert engine.apply_version(snapshot(2), True).status == 'rolled_back'


def test_safe_first_apply_requires_backup(pipeline):
    with pytest.raises(ApplyError, match='no_confirmed_version'):
        pipeline[0].apply_version(snapshot(), True)


def test_marker_survives_run_loss(pipeline):
    engine, fs, _, _ = pipeline
    engine.apply_version(snapshot())
    engine.apply_version(snapshot(2), True)
    fs.remove(MARKER_PATH)
    assert engine.status()['status'] == 'pending'


def test_reload_failure_rolls_back(pipeline):
    engine, _, executor, _ = pipeline
    engine.apply_version(snapshot())
    engine.reload_commands = {'nftables': ['reload-nft']}
    original_run = executor.run
    failures = [True]
    def run(argv, timeout):
        if argv == ['reload-nft'] and failures:
            failures.pop()
            return SimpleNamespace(returncode=1)
        return original_run(argv, timeout)
    executor.run = run
    assert engine.apply_version(snapshot(2), True).status == 'rolled_back'
    assert engine.status()['reason'] == 'agent.reload_failed'


def test_injected_validator_callbacks(pipeline):
    engine, _, _, _ = pipeline
    calls = []
    def validator(name, path):
        calls.append((name, path.name))
        return SimpleNamespace(returncode=0)
    assert engine.apply_version(snapshot(), validators={name: validator for name in FILES}).status == 'confirmed'
    assert dict(calls) == FILES


def test_local_filesystem_atomic_move(tmp_path):
    from vs_router.agent.apply import LocalFileSystem
    fs = LocalFileSystem()
    source, destination = tmp_path / 'pending' / 'config', tmp_path / 'applied' / 'config'
    fs.write(source, 'new')
    fs.write(destination, 'old')
    fs.atomic_move(source, destination)
    assert fs.read(destination) == 'new'
    assert not source.exists()
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.parametrize('marker', [None, {'status': 'confirmed', 'deadline': 1},
                                    {'status': 'rolled_back', 'deadline': 1},
                                    {'status': 'confirmed', 'deadline': None}])
def test_terminal_markers_do_not_rollback(marker):
    assert not check_deadline(marker, lambda reason: pytest.fail(reason), lambda: 200)


def test_failed_rollback_can_be_retried_by_timer(pipeline):
    engine, _, executor, now = pipeline
    engine.apply_version(snapshot())
    engine.apply_version(snapshot(2), True)
    executor.fail = True
    with pytest.raises(ApplyError, match='rollback_failed'):
        engine.rollback('timeout')
    assert engine.status()['status'] == 'rollback_failed'
    executor.fail = False
    assert check_deadline(engine.status(), engine.rollback, lambda: now[0])
    assert engine.status()['status'] == 'rolled_back'
