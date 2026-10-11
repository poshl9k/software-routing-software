"""Privileged, fixed-command sing-box lifecycle and read-only host telemetry."""
import json
import re
from pathlib import Path

from .apply import ApplyError, LocalFileSystem, SubprocessExecutor, APPLIED_DIR
from .singbox_service import (SingboxService, SINGBOX_BINARY, SINGBOX_VERSION_ARGV,
                              SINGBOX_UNIT, _VERSION_RE)
from .tproxy_apply import owned_tables

IP_FORWARD = Path('/proc/sys/net/ipv4/ip_forward')


def clash_port(filesystem):
    """Read applied engine config only; refuse remote Clash listeners."""
    try:
        config = json.loads(filesystem.read(APPLIED_DIR / 'singbox.json'))
        controller = config.get('experimental', {}).get('clash_api', {}).get('external_controller')
        if not isinstance(controller, str):
            return 9099
        match = re.fullmatch(r'127\.0\.0\.1:([0-9]{1,5})', controller)
        if not match or not 1 <= int(match.group(1)) <= 65535:
            raise ApplyError('clash.unavailable')
        return int(match.group(1))
    except FileNotFoundError:
        return 9099
    except (ValueError, TypeError, KeyError):
        raise ApplyError('clash.unavailable') from None


class EngineControl:
    def __init__(self, executor=None, filesystem=None, clash=None, service=None,
                 binary=SINGBOX_BINARY, ip_forward=IP_FORWARD):
        self.executor = executor if executor is not None else SubprocessExecutor()
        self.fs = filesystem if filesystem is not None else LocalFileSystem()
        self.binary = Path(binary)
        self.ip_forward = Path(ip_forward)
        self.service = service if service is not None else SingboxService(self.executor, self.fs)
        self.clash = clash

    def status(self):
        installed = self.binary.is_file()
        try:
            running = self.service.is_active()
        except (OSError, ValueError):
            running = False
        pid = None
        if running:
            try:
                result = self.executor.run(['systemctl', 'show', '--property=MainPID',
                                            '--value', SINGBOX_UNIT], 5)
                text = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
                if result.returncode == 0 and text.strip().isdigit() and int(text.strip()) > 0:
                    pid = int(text.strip())
            except (OSError, ValueError, AttributeError):
                pass
        try:
            ip_forward = self.fs.read(self.ip_forward).strip() == '1'
        except (OSError, ValueError):
            ip_forward = None
        try:
            result = self.executor.run(['/usr/sbin/nft', 'list', 'tables'], 5)
            text = result.stdout.decode('utf-8', 'replace') if isinstance(result.stdout, bytes) else result.stdout
            present = set(re.findall(r'^table\s+(\w+)\s+(\w+)\s*$', text, re.M)) if result.returncode == 0 else set()
            nft_tables = all(tuple(table.split()) in present for table in owned_tables())
        except (OSError, ValueError, AttributeError):
            nft_tables = False
        reachable = False
        if running:
            try:
                if self.clash is None:
                    from .clash import ClashClient
                    client = ClashClient(port=clash_port(self.fs))
                else:
                    client = self.clash
                client.version()
                reachable = True
            except (ApplyError, OSError, ValueError):
                pass
        version = None
        if installed:
            try:
                result = self.executor.run(list(SINGBOX_VERSION_ARGV), 5)
                text = result.stdout.decode('utf-8', 'replace') if isinstance(result.stdout, bytes) else result.stdout
                match = _VERSION_RE.search(text) if result.returncode == 0 else None
                version = match.group(1) if match else None
            except (OSError, ValueError, AttributeError):
                pass
        return {'installed': installed, 'version': version,
                'running': running, 'pid': pid, 'clash_api': reachable,
                'ip_forward': ip_forward, 'nft_tproxy_tables': nft_tables}

    def control(self, action):
        if action not in ('start', 'stop', 'restart'):
            raise ApplyError('engine.invalid_action')
        if action == 'stop':
            self.service.stop()
        else:
            # SingboxService.start verifies the pinned binary and staged config,
            # installs the fixed unit, and waits for actual readiness.
            self.service.start()
        return self.status()
