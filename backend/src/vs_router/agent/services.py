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
