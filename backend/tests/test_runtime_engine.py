import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from vs_router.agent import daemon
from vs_router.agent.engine import EngineControl, clash_port
from vs_router.agent.rpc import PARAMS, build_request
from vs_router.generators.singbox import generate_singbox
from vs_router.schema import ConfigurationVersion


class FS:
    def __init__(self, controller='127.0.0.1:9099'):
        self.controller = controller
    def read(self, path):
        if str(path).endswith('ip_forward'):
            return '1\n'
        return json.dumps({'experimental': {'clash_api': {'external_controller': self.controller}}})


class Executor:
    def __init__(self):
        self.calls = []
    def run(self, argv, timeout):
        self.calls.append((argv, timeout))
        if argv[0] == '/usr/sbin/nft':
            from vs_router.agent.tproxy_apply import owned_tables
            return SimpleNamespace(returncode=0, stdout=''.join(f'table {t}\n' for t in owned_tables()))
        if argv[0] == '/usr/local/lib/vs-router/sing-box':
            return SimpleNamespace(returncode=0, stdout='sing-box version 1.14.2\n')
        return SimpleNamespace(returncode=0, stdout='1234\n')


class Service:
    def __init__(self):
        self.events = []
    def is_active(self):
        return True
    def start(self):
        self.events.append('start')
    def stop(self):
        self.events.append('stop')


class Clash:
    def version(self):
        return {'version': '1.14.2'}
    def connections(self):
        return {'connections': []}
    def close_connection(self, id):
        return {'closed': id}
    def logs(self, level, limit):
        return [{'level': level, 'limit': limit}]
    def proxies(self):
        return {'proxies': {}}
    def select_proxy(self, group, name):
        return {'group': group, 'name': name}
    def proxy_delay(self, tag, url, timeout_ms):
        return {'tag': tag, 'delay': timeout_ms}


def test_clash_config_golden():
    assert 'experimental' not in generate_singbox(ConfigurationVersion())
    tproxy_enabled = {'interfaces': [{'name': 'lan0', 'zone': 'lan'}],
                      'tproxy': {'enabled': True, 'ingress_interfaces': ['lan0'],
                                 'rules': [{'name': 'r', 'ip_cidr': ['198.18.0.0/15']}]}}
    for configuration in (tproxy_enabled, {'proxies': {'enabled': True}}):
        config = generate_singbox(ConfigurationVersion.model_validate({'configuration': configuration}))
        assert config['experimental'] == {'clash_api': {'external_controller': '127.0.0.1:9099'}}
        assert '0.0.0.0' not in json.dumps(config['experimental'])
    tproxy_enabled['tproxy']['clash_api_port'] = 9199
    custom = ConfigurationVersion.model_validate({'configuration': tproxy_enabled})
    assert generate_singbox(custom)['experimental'] == {'clash_api': {'external_controller': '127.0.0.1:9199'}}
    with pytest.raises(ValidationError):
        ConfigurationVersion.model_validate({'configuration': {'tproxy': {'clash_api_port': 0}}})


def test_engine_status_and_control(tmp_path):
    executor, service = Executor(), Service()
    binary = tmp_path / 'sing-box'
    binary.write_bytes(b'test')
    control = EngineControl(executor=executor, filesystem=FS(), service=service,
                            clash=Clash(), binary=binary)
    assert control.status() == {'installed': True, 'version': '1.14.2', 'running': True,
                                'pid': 1234, 'clash_api': True, 'ip_forward': True,
                                'nft_tproxy_tables': True}
    assert control.control('restart')['running'] is True
    control.control('stop')
    assert service.events == ['start', 'stop']
    from vs_router.agent.apply import ApplyError
    with pytest.raises(ApplyError, match='engine.invalid_action'):
        control.control('shell')
    assert all(argv[0] in ('systemctl', '/usr/sbin/nft', '/usr/local/lib/vs-router/sing-box')
               for argv, _ in executor.calls)


def test_applied_clash_port_rejects_external_binding():
    assert clash_port(FS('127.0.0.1:9111')) == 9111
    from vs_router.agent.apply import ApplyError
    with pytest.raises(ApplyError, match='clash.unavailable'):
        clash_port(FS('0.0.0.0:9099'))


@pytest.mark.parametrize('method,params', [
    ('engine_control', {'action': 'install'}), ('engine_control', {'action': 'start', 'extra': 1}),
    ('clash_close', {'id': '../other'}), ('clash_logs', {'limit': 10000}),
    ('clash_delay', {'tag': 'a', 'url': 'http://a.test', 'timeout_ms': True}),
    ('clash_select', {'group': 'group/name', 'name': 'p'}),
])
def test_rpc_rejects_invalid_params(method, params):
    result = daemon.dispatch(json.dumps({'id': 1, 'method': method, 'params': params}).encode(), {})
    assert result.error.message == 'rpc.invalid_request'


def test_rpc_dispatch_typed_mock_handlers():
    runtime = SimpleNamespace(status=lambda: {'running': True}, control=lambda action: {'action': action})
    handlers = daemon.make_handlers(None, None, runtime_engine=runtime, clash_client=Clash())
    cases = [('engine_status', {}, {'running': True}),
             ('engine_control', {'action': 'start'}, {'action': 'start'}),
             ('clash_connections', {}, {'connections': []}),
             ('clash_close', {'id': 'abc'}, {'closed': 'abc'}),
             ('clash_logs', {'level': 'error', 'limit': 2}, [{'level': 'error', 'limit': 2}]),
             ('clash_proxies', {}, {'proxies': {}}),
             ('clash_select', {'group': 'main', 'name': 'node'}, {'group': 'main', 'name': 'node'}),
             ('clash_delay', {'tag': 'node', 'url': 'https://example.com/204', 'timeout_ms': 3000},
              {'tag': 'node', 'delay': 3000})]
    for method, params, expected in cases:
        assert method in PARAMS
        result = daemon.dispatch(build_request(method, params).model_dump_json().encode(), handlers)
        assert result.error is None, (method, result.error)
        assert result.result == expected
