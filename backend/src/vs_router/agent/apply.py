"""Host-side application pipeline. All effects can be replaced in tests."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from typing import Callable, Protocol

from ..generators import generate_kea, generate_nftables, generate_unbound, generate_networkd, serialize_networkd
import json as _json
from ..generators.wireguard import generate_wg_bundle, serialize_wireguard
from ..generators.caddy import generate_caddy_bundle, serialize_caddy
from ..secrets import decrypt_secret as _decrypt
from ..schema import ConfigurationVersion

PENDING_DIR = Path('/run/vs-router/pending')
APPLIED_DIR = Path('/etc/vs-router/applied')
CONFIRMED_DIR = Path('/etc/vs-router/confirmed')
MARKER_PATH = Path('/run/vs-router/marker.json')
# /run is volatile: retain the same journal across host reboots.
JOURNAL_PATH = Path('/etc/vs-router/marker.json')
FILES = {'nftables': 'nftables.conf', 'unbound': 'unbound.conf', 'kea': 'kea.json',
         'networkd': 'networkd.conf', 'wireguard': 'wireguard.conf', 'caddy': 'caddy.conf',
         'ddns': 'ddns.conf', 'ssh': 'ssh.json'}
VALIDATORS = {'nftables': ['nft', '-c', '-f'], 'unbound': ['unbound-checkconf'],
              'kea': ['kea-dhcp4', '-t'], 'networkd': ['true'], 'wireguard': ['true'], 'caddy': ['true'], 'ddns': ['true'], 'ssh': ['true']}


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
                 validators=None, reload_commands=None, panel_probe: Callable | None = None,
                 management_provider=None, ssh_controller=None):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.clock = clock
        self.validators = VALIDATORS if validators is None else validators
        self.reload_commands = reload_commands or {}
        self.panel_probe = panel_probe
        self.management_provider = management_provider
        self.ssh_controller = ssh_controller

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
        if callable(command):
            command(APPLIED_DIR / FILES[name])
        elif command and self.executor.run(command, 15).returncode:
            raise ApplyError('agent.reload_failed')

    def _install(self, contents, marker, validators):
        # Upgrade pre-SSH backups to the closed default.
        contents = dict(contents)
        contents.setdefault('ssh', '{"interfaces": [], "wan_confirmed_interfaces": []}')
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
        if self.ssh_controller is not None:
            self.ssh_controller.close()
        for name, filename in FILES.items():
            self.fs.atomic_move(PENDING_DIR / filename, APPLIED_DIR / filename)
            self.reload_service(name)
            marker['phases'][name] = 'applied'
            self.marker(marker)
        if self.ssh_controller is not None:
            self.ssh_controller.activate(json.loads(contents['ssh']))

    def _backup(self, version_id):
        contents = {n: self.fs.read(APPLIED_DIR / f) for n, f in FILES.items()}
        # One atomic bundle is the authority, avoiding mixed backup generations.
        self.fs.write(CONFIRMED_DIR / 'snapshot.json', json.dumps(
            {'version_id': version_id, 'files': contents,
             'version_snapshot': json.loads(self.fs.read(APPLIED_DIR / 'snapshot.json'))}))
        for name, content in contents.items():
            self.fs.write(CONFIRMED_DIR / FILES[name], content)

    def reveal_secret(self, secret):
        import os
        return _decrypt(secret, os.environ.get('VS_ROUTER_SECRET_KEY', '').encode())

    def apply_version(self, version_snapshot: dict, safe_mode: bool = False,
                      confirmation_timeout: int = 180, validators=None) -> ApplyResult:
        previous = self.status()
        if previous and previous['status'] not in ('confirmed', 'rolled_back', 'failed'):
            raise ApplyError('agent.apply_pending')
        if not 60 <= confirmation_timeout <= 600:
            raise ApplyError('agent.invalid_timeout')
        version = ConfigurationVersion.model_validate(version_snapshot)
        try:
            backup = json.loads(self.fs.read(CONFIRMED_DIR / 'snapshot.json'))
        except FileNotFoundError:
            backup = None
        management = None
        if self.management_provider is not None:
            try:
                from ..management import validate_management, validate_site_bindings
                management = self.management_provider()
                if management is not None:
                    validate_management(version.configuration, management)
                    validate_site_bindings(version, management)
            except (OSError, ValueError) as exc:
                raise ApplyError('management.access_invalid') from exc
            if management is None:
                raise ApplyError('management.assignment_required')
        if management is not None and backup is None:
            # No rollback target exists: never mutate the host if the panel is
            # already unreachable over the provisioned management HTTPS path.
            if self.panel_probe is None or not self.panel_probe():
                raise ApplyError('panel.unavailable')
            safe_mode = False
        elif management is not None and backup is not None:
            old = ConfigurationVersion.model_validate(backup['version_snapshot']).configuration
            old_lan = next((i for i in old.interfaces if i.name == management.interface), None)
            new_lan = next(i for i in version.configuration.interfaces if i.name == management.interface)
            if old_lan != new_lan or old.anti_lockout != version.configuration.anti_lockout:
                safe_mode = True
        elif safe_mode and backup is None:
            raise ApplyError('agent.no_confirmed_version')
        now = self.clock()
        marker = {'version_id': version.id, 'applied_at': now,
                  'deadline': now + confirmation_timeout if safe_mode else None,
                  'status': 'applying', 'phases': {}}
        try:
            contents = {name: gen(version) for name, gen in (
                ('nftables', lambda v: generate_nftables(v, management)), ('unbound', generate_unbound), ('kea', generate_kea))}
            # DDNS jobs (plaintext tokens live only in this 0600 file).
            # No jobs or missing key -> empty config, worker does nothing.
            try:
                ddns_jobs = [
                    {'name': j.name, 'provider': j.provider, 'hostname': j.hostname,
                     'zone': j.zone, 'server': j.server, 'key_name': j.key_name,
                     'api_token': self.reveal_secret(j.api_token),
                     'wan_interface': j.wan_interface}
                    for j in version.configuration.ddns
                ]
            except ValueError:
                ddns_jobs = []
            contents['ddns'] = _json.dumps({'ddns': ddns_jobs})
            network = generate_networkd(version)
            if management is not None:
                name = f'10-vs-router-{management.interface}.network'
                network[name] = network[name].replace(
                    f'Name={management.interface}\n',
                    f'Name={management.interface}\nMACAddress={management.mac}\n', 1)
            contents["networkd"] = serialize_networkd(network)
            contents["wireguard"] = serialize_wireguard(generate_wg_bundle(version, {}))
            contents["ssh"] = version.configuration.ssh.model_dump_json()
            contents["caddy"] = serialize_caddy(generate_caddy_bundle(version, management))
            self._install(contents, marker, self.validators if validators is None else validators)
            self.fs.write(APPLIED_DIR / 'snapshot.json', json.dumps(version_snapshot))
            marker['status'] = 'pending' if safe_mode else 'confirmed'
            if self.panel_probe is not None and not self.panel_probe():
                if backup is not None:
                    return self.rollback('panel.unavailable')
                raise ApplyError('panel.unavailable')
            if not safe_mode:
                self._backup(version.id)
            self.marker(marker)
            return ApplyResult(version.id, marker['status'], marker['phases'])
        except (OSError, subprocess.SubprocessError, ValueError, ApplyError, KeyError) as exc:
            code = exc.code if isinstance(exc, ApplyError) else 'agent.apply_failed'
            mutated = any(v == 'applied' for v in marker['phases'].values()) or self.status() == marker
            marker.update(status='failed', error={'code': code, 'message': code, 'details': []})
            self.marker(marker)
            if self.ssh_controller is not None:
                try:
                    self.ssh_controller.close()
                except (OSError, subprocess.SubprocessError, ApplyError):
                    marker['error']['code'] = 'ssh.close_failed'
                    self.marker(marker)
            if mutated and backup is not None:
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
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, ApplyError) as exc:
            if self.ssh_controller is not None:
                try:
                    self.ssh_controller.close()
                except (OSError, subprocess.SubprocessError, ApplyError):
                    pass  # Preserve retryable rollback failure; never report success.
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
