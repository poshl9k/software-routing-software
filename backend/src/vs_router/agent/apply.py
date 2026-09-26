"""Host-side application pipeline. All effects can be replaced in tests."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Callable, Protocol

from ..generators import generate_kea, generate_nftables, generate_unbound
from ..schema import ConfigurationVersion

PENDING_DIR = Path('/run/vs-router/pending')
APPLIED_DIR = Path('/etc/vs-router/applied')
CONFIRMED_DIR = Path('/etc/vs-router/confirmed')
MARKER_PATH = Path('/run/vs-router/marker.json')
# /run is volatile: retain the same journal across host reboots.
JOURNAL_PATH = Path('/etc/vs-router/marker.json')
FILES = {'nftables': 'nftables.conf', 'unbound': 'unbound.conf', 'kea': 'kea.json'}
VALIDATORS = {'nftables': ['nft', '-c', '-f'], 'unbound': ['unbound-checkconf'],
              'kea': ['kea-dhcp4', '-t']}


class Completed(Protocol):
    returncode: int


class Executor(Protocol):
    def run(self, argv: list[str], timeout: int) -> Completed: ...


class FileSystem(Protocol):
    def write(self, path: Path, content: str) -> None: ...
    def atomic_move(self, source: Path, destination: Path) -> None: ...
    def read(self, path: Path) -> str: ...
    def remove(self, path: Path) -> None: ...


class Clock(Protocol):
    def __call__(self) -> float: ...


class SubprocessExecutor:
    def run(self, argv, timeout):
        return subprocess.run(argv, timeout=timeout, capture_output=True, check=False)


class LocalFileSystem:
    def write(self, path, content):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def atomic_move(self, source, destination):
        # Stage on the destination mount before rename (/run -> /etc).
        self.write(destination, self.read(source))
        self.remove(source)

    def read(self, path):
        return Path(path).read_text()

    def remove(self, path):
        Path(path).unlink(missing_ok=True)


class ApplyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass
class ApplyResult:
    version_id: int
    status: str
    phases: dict
    error: dict | None = None

    def to_dict(self):
        return asdict(self)


class ApplyEngine:
    def __init__(self, *, executor=None, filesystem=None, clock: Clock = time.time,
                 validators=None, reload_commands=None, panel_probe: Callable | None = None):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.clock = clock
        self.validators = VALIDATORS if validators is None else validators
        self.reload_commands = reload_commands or {}
        self.panel_probe = panel_probe

    def status(self):
        for path in (JOURNAL_PATH, MARKER_PATH):
            try:
                return json.loads(self.fs.read(path))
            except FileNotFoundError:
                pass
        return None

    def marker(self, data):
        self.fs.write(JOURNAL_PATH, json.dumps(data))
        self.fs.write(MARKER_PATH, json.dumps(data))

    def reload_service(self, name):
        command = self.reload_commands.get(name)
        if command and self.executor.run(command, 15).returncode:
            raise ApplyError('agent.reload_failed')

    def _install(self, contents, marker, validators):
        for name, content in contents.items():
            self.fs.write(PENDING_DIR / FILES[name], content)
            marker['phases'][name] = 'generated'
        for name in FILES:
            validator = validators[name]
            path = PENDING_DIR / FILES[name]
            result = (validator(name, path) if callable(validator) else
                      self.executor.run([*validator, str(path)], 15))
            if result.returncode:
                marker['phases'][name] = 'failed'
                raise ApplyError('agent.validation_failed')
            marker['phases'][name] = 'validated'
        # Journal before the first live mutation, so interrupted applications roll back.
        self.marker(marker)
        for name, filename in FILES.items():
            self.fs.atomic_move(PENDING_DIR / filename, APPLIED_DIR / filename)
            self.reload_service(name)
            marker['phases'][name] = 'applied'
            self.marker(marker)

    def _backup(self, version_id):
        contents = {n: self.fs.read(APPLIED_DIR / f) for n, f in FILES.items()}
        # One atomic bundle is the authority, avoiding mixed backup generations.
        self.fs.write(CONFIRMED_DIR / 'snapshot.json', json.dumps(
            {'version_id': version_id, 'files': contents,
             'version_snapshot': json.loads(self.fs.read(APPLIED_DIR / 'snapshot.json'))}))
        for name, content in contents.items():
            self.fs.write(CONFIRMED_DIR / FILES[name], content)

    def apply_version(self, version_snapshot: dict, safe_mode: bool = False,
                      confirmation_timeout: int = 180, validators=None) -> ApplyResult:
        previous = self.status()
        if previous and previous['status'] not in ('confirmed', 'rolled_back', 'failed'):
            raise ApplyError('agent.apply_pending')
        if not 60 <= confirmation_timeout <= 600:
            raise ApplyError('agent.invalid_timeout')
        version = ConfigurationVersion.model_validate(version_snapshot)
        if safe_mode:
            try:
                self.fs.read(CONFIRMED_DIR / 'snapshot.json')
            except FileNotFoundError:
                raise ApplyError('agent.no_confirmed_version') from None
        now = self.clock()
        marker = {'version_id': version.id, 'applied_at': now,
                  'deadline': now + confirmation_timeout if safe_mode else None,
                  'status': 'applying', 'phases': {}}
        try:
            contents = {name: gen(version) for name, gen in (
                ('nftables', generate_nftables), ('unbound', generate_unbound), ('kea', generate_kea))}
            self._install(contents, marker, self.validators if validators is None else validators)
            self.fs.write(APPLIED_DIR / 'snapshot.json', json.dumps(version_snapshot))
            marker['status'] = 'pending' if safe_mode else 'confirmed'
            if safe_mode and self.panel_probe is not None and not self.panel_probe():
                return self.rollback('panel.unavailable')
            if not safe_mode:
                self._backup(version.id)
            self.marker(marker)
            return ApplyResult(version.id, marker['status'], marker['phases'])
        except (OSError, subprocess.SubprocessError, ValueError, ApplyError, KeyError) as exc:
            code = exc.code if isinstance(exc, ApplyError) else 'agent.apply_failed'
            mutated = any(v == 'applied' for v in marker['phases'].values()) or self.status() == marker
            marker.update(status='failed', error={'code': code, 'message': code, 'details': []})
            self.marker(marker)
            if mutated:
                return self.rollback(code)
            return ApplyResult(version.id, 'failed', marker['phases'], marker['error'])

    def confirm_version(self, version_id):
        marker = self.status()
        if not marker or marker['version_id'] != version_id or marker['status'] != 'pending':
            raise ApplyError('agent.version_mismatch')
        if marker['deadline'] is not None and self.clock() >= marker['deadline']:
            self.rollback('timeout')
            raise ApplyError('agent.confirmation_expired')
        self._backup(version_id)
        self.fs.remove(MARKER_PATH)
        self.fs.remove(JOURNAL_PATH)
        return {'version_id': version_id, 'status': 'confirmed'}

    def rollback(self, reason):
        try:
            backup = json.loads(self.fs.read(CONFIRMED_DIR / 'snapshot.json'))
        except FileNotFoundError:
            raise ApplyError('agent.no_confirmed_version') from None
        marker = {'version_id': backup['version_id'], 'applied_at': self.clock(),
                  'deadline': self.clock(), 'status': 'rolling_back', 'reason': reason, 'phases': {}}
        try:
            self._install(backup['files'], marker, self.validators)
        except (OSError, subprocess.SubprocessError, ApplyError) as exc:
            marker.update(status='rollback_failed', deadline=self.clock())
            self.marker(marker)
            raise ApplyError('agent.rollback_failed') from exc
        self.fs.write(APPLIED_DIR / 'snapshot.json', json.dumps(backup['version_snapshot']))
        marker['deadline'] = None
        marker['status'] = 'rolled_back'
        marker['phases']['rollback'] = 'rolled_back'
        self.marker(marker)
        return ApplyResult(backup['version_id'], 'rolled_back', marker['phases'])


def apply_version(version_snapshot, safe_mode=False, confirmation_timeout=180, validators=None, **dependencies):
    return ApplyEngine(**dependencies).apply_version(version_snapshot, safe_mode, confirmation_timeout, validators)


def confirm_version(version_id, **dependencies):
    return ApplyEngine(**dependencies).confirm_version(version_id)


def rollback(reason, **dependencies):
    return ApplyEngine(**dependencies).rollback(reason)
