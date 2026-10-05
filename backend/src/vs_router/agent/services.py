"""Live service adapters; commands and HTTP transport are injectable."""
import base64
import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, ProxyHandler, build_opener

from .apply import ApplyError, LocalFileSystem, SubprocessExecutor


def checked(executor, argv):
    if executor.run(argv, 15).returncode:
        raise ApplyError('agent.reload_failed')


class NftApply:
    def __init__(self, executor=None):
        self.executor = executor or SubprocessExecutor()

    def __call__(self, path):
        # Generated file destroys only our table and recreates it in one transaction.
        checked(self.executor, ['nft', '-f', str(path)])


class UnboundReloader:
    def __init__(self, executor=None, filesystem=None,
                 include_path=Path('/etc/unbound/unbound.conf.d/vs-router.conf'),
                 config_path=Path('/etc/unbound/unbound.conf')):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.include_path = include_path
        self.config_path = config_path

    def __call__(self, path):
        self.fs.write(self.include_path, f'include: "{path}"\n')
        # HUP rereads configuration after Unbound has dropped privileges.
        checked(self.executor, ['chmod', '0644', str(path), str(self.include_path)])
        checked(self.executor, ['unbound-checkconf', str(self.config_path)])
        if self.executor.run(['systemctl', 'is-active', '--quiet', 'unbound'], 15).returncode:
            checked(self.executor, ['systemctl', 'start', 'unbound'])
            return
        if self.executor.run(['systemctl', 'reload', 'unbound'], 15).returncode:
            checked(self.executor, ['systemctl', 'kill', '--kill-whom=main', '-s', 'HUP', 'unbound'])


class KeaReloader:
    def __init__(self, executor=None, filesystem=None, http_client=None,
                 config_path=Path('/etc/kea/kea-dhcp4.conf'),
                 password_path=Path('/etc/kea/kea-api-password')):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        # Do not send localhost credentials through environment-configured proxies.
        self.http_client = http_client or build_opener(ProxyHandler({})).open
        self.config_path = config_path
        self.password_path = password_path

    def __call__(self, path):
        password = self.fs.read(self.password_path).rstrip('\r\n')
        if not password:
            raise ApplyError('agent.reload_failed')
        self.fs.write(self.config_path, self.fs.read(path))
        # Debian runs DHCPv4 as _kea; directory /etc/kea remains restricted.
        checked(self.executor, ['chmod', '0644', str(self.config_path)])
        token = base64.b64encode(f'kea-api:{password}'.encode()).decode()
        request = Request('http://127.0.0.1:8000/',
                          data=json.dumps({'command': 'config-reload', 'service': ['dhcp4']}).encode(),
                          headers={'Content-Type': 'application/json', 'Authorization': f'Basic {token}'},
                          method='POST')
        try:
            with self.http_client(request, timeout=15) as response:
                if response.status != 200:
                    raise ApplyError('agent.reload_failed')
                result = json.load(response)
            if (not isinstance(result, list) or len(result) != 1
                    or not isinstance(result[0], dict)
                    or type(result[0].get('result')) is not int or result[0]['result'] != 0):
                raise ApplyError('agent.reload_failed')
        except (OSError, URLError, ValueError) as exc:
            raise ApplyError('agent.reload_failed') from exc


class NetworkdReloader:
    """Install owned files and reload networkd; retain ownership across failures.

    Only files recorded in our manifest are removed. networkctl reload applies
    changed .network files but does not delete existing virtual kernel devices
    when their .netdev disappears; device teardown is outside this adapter.
    """
    def __init__(self, executor=None, filesystem=None,
                 network_dir=Path('/etc/systemd/network'),
                 manifest_path=Path('/etc/vs-router/networkd-manifest.conf')):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.network_dir = network_dir
        self.manifest_path = manifest_path

    def __call__(self, path):
        from ..generators.networkd import deserialize_networkd, serialize_networkd

        try:
            files = deserialize_networkd(self.fs.read(path))
            try:
                previous = deserialize_networkd(self.fs.read(self.manifest_path))
            except FileNotFoundError:
                previous = {}
        except ValueError as exc:
            raise ApplyError('agent.reload_failed') from exc
        # Journal the union first: interrupted writes remain discoverable on rollback.
        self.fs.write(self.manifest_path, serialize_networkd(previous | files))
        for name, content in files.items():
            destination = self.network_dir / name
            self.fs.write(destination, content)
            checked(self.executor, ['chmod', '0644', str(destination)])
        for name in sorted(previous.keys() - files.keys()):
            self.fs.remove(self.network_dir / name)
        # networkd may be absent on non-networkd hosts (lab/other init):
        # files are still installed; reload failure must not roll back apply.
        active = self.executor.run(
            ['systemctl', 'is-active', '--quiet', 'systemd-networkd'], 15)
        if active.returncode == 0:
            checked(self.executor, ['networkctl', 'reload'])
        else:
            self.executor.run(['systemctl', 'restart', 'systemd-networkd'], 15)
        self.fs.write(self.manifest_path, serialize_networkd(files))


class WireGuardReloader:
    """Install private bundles, then configure userspace devices after readiness."""
    def __init__(self, executor=None, filesystem=None,
                 config_dir=Path('/etc/vs-router/wireguard'), sleep=None):
        import time
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.config_dir = config_dir
        self.sleep = sleep or time.sleep

    def install(self, path):
        from ..generators.wireguard import deserialize_wireguard
        import re
        files = deserialize_wireguard(self.fs.read(path))
        manifest = json.loads(files['manifest.json'])
        for iface, entry in manifest.items():
            if (not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,14}', iface)
                    or entry['protocol'] not in ('wg', 'awg') or entry['file'] not in files):
                raise ValueError('wireguard.invalid_manifest')
        try:
            previous = json.loads(self.fs.read(self.config_dir / 'manifest.json'))
        except FileNotFoundError:
            previous = {}
        try:
            owned = json.loads(self.fs.read(self.config_dir / 'owned.json'))
        except FileNotFoundError:
            owned = []
        # Record ownership before writes so a failed apply cannot strand exports.
        self.fs.write(self.config_dir / 'owned.json', json.dumps(sorted(set(owned) | set(files))))
        for name in set(owned) - set(files):
            self.fs.remove(self.config_dir / name)
        for name, content in files.items():
            if name != 'manifest.json':
                self.fs.write(self.config_dir / name, content)
        self.fs.write(self.config_dir / 'owned.json', json.dumps(sorted(files)))
        return files, manifest, previous

    def __call__(self, path):
        files, manifest, previous = self.install(path)
        # Keep union ownership across partial failures, including first application.
        self.fs.write(self.config_dir / 'manifest.json', json.dumps(previous | manifest))
        for iface, old in previous.items():
            new = manifest.get(iface)
            if new is None or old['protocol'] != new['protocol']:
                checked(self.executor, ['systemctl', 'disable', '--now', f'vs-router-{old["protocol"]}@{iface}.service'])
            elif new:
                for route in sorted(set(old['routes']) - set(new['routes'])):
                    checked(self.executor, self.route('del', route, iface))
                for address in sorted(set(old['addresses']) - set(new['addresses'])):
                    checked(self.executor, ['ip', 'addr', 'del', address, 'dev', iface])
        for iface, entry in manifest.items():
            unit = f'vs-router-{entry["protocol"]}@{iface}.service'
            checked(self.executor, ['systemctl', 'enable', unit])
            present = self.executor.run(['ip', 'link', 'show', 'dev', iface], 15).returncode == 0
            alive = self.executor.run(['systemctl', 'is-active', '--quiet', unit], 15).returncode == 0
            if not (present and alive):
                checked(self.executor, ['systemctl', 'restart', unit])
                for attempt in range(50):
                    if self.executor.run([entry['protocol'], 'show', iface], 15).returncode == 0:
                        break
                    self.sleep(0.1)
                else:
                    raise ApplyError('agent.reload_failed')
            checked(self.executor, [entry['protocol'], 'setconf', iface, str(self.config_dir / entry['file'])])
            for address in entry['addresses']:
                checked(self.executor, ['ip', 'addr', 'replace', address, 'dev', iface])
            checked(self.executor, ['ip', 'link', 'set', 'dev', iface, 'up'])
            for route in entry['routes']:
                checked(self.executor, self.route('replace', route, iface))
        for entry in previous.values():
            if entry['file'] not in files:
                self.fs.remove(self.config_dir / entry['file'])
        self.fs.write(self.config_dir / 'manifest.json', files['manifest.json'])

    @staticmethod
    def route(action, value, iface):
        from ipaddress import ip_network
        network = ip_network(value)
        return (['ip', '-6' if network.version == 6 else '-4', 'route', action,
                 'default' if network.prefixlen == 0 else str(network), 'dev', iface]
                + (['metric', '100'] if network.prefixlen == 0 else []))


class CaddyReloader:
    def __init__(self, executor=None, filesystem=None, http_client=None,
                 config_path=Path('/etc/caddy/caddy.json'), cert_dir=Path('/etc/caddy/vs-router')):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.http_client = http_client or build_opener(ProxyHandler({})).open
        self.config_path, self.cert_dir = config_path, cert_dir

    def install(self, path):
        from ..generators.caddy import deserialize_caddy
        files = deserialize_caddy(self.fs.read(path))
        json.loads(files['caddy.json'])
        for name, content in files.items():
            if name != 'caddy.json':
                if not name.endswith(('.crt', '.key')):
                    raise ValueError('caddy.invalid_bundle')
                self.fs.write(self.cert_dir / name, content)
        self.fs.write(self.config_path, files['caddy.json'])
        return files

    def __call__(self, path):
        files = self.install(path)
        # Caddy's unprivileged service must be able to reopen JSON and TLS keys.
        for target in [self.config_path] + [self.cert_dir / n for n in files if n != 'caddy.json']:
            checked(self.executor, ['chown', 'root:caddy', str(target)])
            checked(self.executor, ['chmod', '0640', str(target)])
        checked(self.executor, ['caddy', 'validate', '--config', str(self.config_path)])
        request = Request('http://127.0.0.1:2019/load', data=files['caddy.json'].encode(),
                          headers={'Content-Type': 'application/json'}, method='POST')
        try:
            with self.http_client(request, timeout=15) as response:
                if response.status != 200:
                    raise ApplyError('agent.reload_failed')
        except (OSError, URLError, ValueError):
            raise ApplyError('agent.reload_failed') from None
