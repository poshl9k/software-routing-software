import socket
import threading
import pytest
from vs_router.agent import daemon
from vs_router.agent.rpc import AgentClient, AgentRPCError


@pytest.fixture
def server(tmp_path, monkeypatch):
    path = tmp_path / 'agent.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(str(path))
        except PermissionError:
            pytest.skip('Environment prohibits AF_UNIX bind')
    path.unlink()
    stop, ready = threading.Event(), threading.Event()
    monkeypatch.setattr(daemon, 'peer_uid', lambda connection: 123)
    thread = threading.Thread(target=daemon.serve, args=(path, {'status': lambda: {'ok': True}}, {123}),
                              kwargs={'stop_event': stop, 'ready_event': ready}, daemon=True)
    thread.start()
    assert ready.wait(3)
    yield path
    stop.set()
    thread.join(3)
    assert not thread.is_alive()


def test_roundtrip(server):
    client = AgentClient(daemon.UnixSocketTransport(server))
    assert client.call('status') == {'ok': True}
    assert client.call('status') == {'ok': True}


def test_peer_filter(server, monkeypatch):
    monkeypatch.setattr(daemon, 'peer_uid', lambda connection: 456)
    with pytest.raises((OSError, EOFError)):
        AgentClient(daemon.UnixSocketTransport(server)).call('status')


def test_whitelist():
    result = daemon.dispatch(b'{"jsonrpc":"2.0","id":1,"method":"shell","params":{}}', {})
    assert result.error.message == 'rpc.invalid_request'


def test_fragmented_frame():
    import struct
    class Connection:
        def __init__(self):
            self.data = bytearray(struct.pack('!I', 5) + b'hello')
        def recv(self, size):
            part = self.data[:1]
            del self.data[:1]
            return bytes(part)
    assert daemon.receive(Connection()) == b'hello'


def test_oversized_frame():
    import struct
    class Connection:
        def recv(self, size):
            return struct.pack('!I', daemon.MAX_FRAME + 1)
    with pytest.raises(ValueError, match='invalid_frame'):
        daemon.receive(Connection())


def test_db_handlers_confirm_exact_applied_snapshot(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from vs_router.db import Base, ConfigurationRow
    from vs_router.agent.apply import ApplyEngine
    from test_agent_apply import FakeFS, FakeExecutor, snapshot
    database = create_engine('sqlite://')
    Base.metadata.create_all(database)
    engine = ApplyEngine(filesystem=FakeFS(), executor=FakeExecutor())
    engine.apply_version(snapshot())
    with Session(database) as db:
        db.add(ConfigurationRow(id=2, status='draft', configuration={}))
        db.commit()
    handlers = daemon.make_handlers(engine, database)
    assert handlers['apply_version'](2, True).status == 'pending'
    with Session(database) as db:
        db.get(ConfigurationRow, 2).configuration = {'panel_port': 8443}
        db.commit()
    assert handlers['confirm_version'](2)['status'] == 'confirmed'
    with Session(database) as db:
        row = db.get(ConfigurationRow, 2)
        assert row.status == 'confirmed'
        assert row.configuration.panel_port != 8443
    database.dispose()


def test_list_interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import Mock
    from subprocess import CompletedProcess
    from vs_router.agent.rpc import build_request

    command = ['ip', '-br', 'link']
    run = Mock(return_value=CompletedProcess(command, 0, stdout=(
        'lo UNKNOWN 00:00:00:00:00:00\n'
        'eth0 UP aa:bb:cc:dd:ee:ff <UP>\n'
        'vlan10@eth0 DOWN aa:bb:cc:dd:ee:ff\n'
        'br0 UP aa:bb:cc:dd:ee:ff\n'
        'bond0 DOWN aa:bb:cc:dd:ee:ff\n\n'
    )))
    monkeypatch.setattr(daemon.subprocess, 'run', run)
    handlers = daemon.make_handlers(None, None)
    result = daemon.dispatch(build_request('list_interfaces', {}).model_dump_json(), handlers)
    assert result.error is None
    assert result.result == [
        {'name': 'lo', 'kind': 'physical', 'parent': None, 'operstate': 'UNKNOWN', 'mac': '00:00:00:00:00:00'},
        {'name': 'eth0', 'kind': 'physical', 'parent': None, 'operstate': 'UP', 'mac': 'aa:bb:cc:dd:ee:ff'},
        {'name': 'vlan10', 'kind': 'vlan', 'parent': 'eth0', 'operstate': 'DOWN', 'mac': 'aa:bb:cc:dd:ee:ff'},
        {'name': 'br0', 'kind': 'bridge', 'parent': None, 'operstate': 'UP', 'mac': 'aa:bb:cc:dd:ee:ff'},
        {'name': 'bond0', 'kind': 'bond', 'parent': None, 'operstate': 'DOWN', 'mac': 'aa:bb:cc:dd:ee:ff'},
    ]
    run.assert_called_once_with(command, capture_output=True, text=True, timeout=5, check=True)
    invalid = daemon.dispatch(
        b'{"id":1,"method":"list_interfaces","params":{"command":"bad"}}', handlers)
    assert invalid.error.message == 'rpc.invalid_request'
    assert run.call_count == 1


@pytest.mark.parametrize('failure', [FileNotFoundError(),
                                     daemon.subprocess.TimeoutExpired('ip', 5),
                                     daemon.subprocess.CalledProcessError(1, 'ip')])
def test_list_interfaces_failure(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    from unittest.mock import Mock
    from vs_router.agent.rpc import build_request

    monkeypatch.setattr(daemon.subprocess, 'run', Mock(side_effect=failure))
    result = daemon.dispatch(build_request('list_interfaces').model_dump_json(),
                             daemon.make_handlers(None, None))
    assert result.error.message == 'host.interfaces_unavailable'
