"""Length-framed JSON RPC on a peer-authenticated Unix socket."""
import json
import logging
import os
from pathlib import Path
import pwd
import socket
import struct

from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from .apply import ApplyEngine, ApplyError, ApplyResult, APPLIED_DIR
from .rpc import PARAMS, RPCRequest, RPCResponse, RPCError
from ..db import ConfigurationRow

SOCKET_PATH = '/run/vs-router/agent.sock'
MAX_FRAME = 4 * 1024 * 1024
log = logging.getLogger(__name__)


def read_exact(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError('agent.connection_closed')
        chunks.extend(chunk)
    return bytes(chunks)


def receive(connection):
    size = struct.unpack('!I', read_exact(connection, 4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError('agent.invalid_frame')
    return read_exact(connection, size)


def send(connection, message):
    if not 0 < len(message) <= MAX_FRAME:
        raise ValueError('agent.invalid_frame')
    connection.sendall(struct.pack('!I', len(message)) + message)


class UnixSocketTransport:
    def __init__(self, socket_path=SOCKET_PATH, timeout=120):
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self.connection = None

    def send(self, message):
        self.close()
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(self.timeout)
        try:
            self.connection.connect(self.socket_path)
            send(self.connection, message)
        except BaseException:
            self.close()
            raise

    def recv(self):
        try:
            return receive(self.connection)
        finally:
            self.close()

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def dispatch(payload, handlers):
    request = None
    try:
        request = RPCRequest.model_validate_json(payload)
        log.info('agent.rpc method=%s', request.method)
        params = PARAMS[request.method].model_validate(request.params).model_dump()
        result = handlers[request.method](**params)
        if isinstance(result, ApplyResult):
            result = result.to_dict()
        return RPCResponse(id=request.id, result=result)
    except ValidationError:
        error = RPCError(code=-32600, message='rpc.invalid_request')
    except ApplyError as exc:
        error = RPCError(code=-32000, message=exc.code,
                         data={'code': exc.code, 'message': exc.code, 'details': []})
    except Exception:
        log.exception('agent.rpc failed')
        error = RPCError(code=-32603, message='agent.internal_error')
    return RPCResponse(id=request.id if request else None, error=error)


def serve(socket_path, handlers, allowed_uids=None, *, stop_event=None, ready_event=None,
          socket_gid=None):
    allowed_uids = {0} if allowed_uids is None else set(allowed_uids)
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never unlink a live server or an unrelated file.
    if path.exists():
        import stat
        if not stat.S_ISSOCK(path.stat().st_mode):
            raise RuntimeError('agent.socket_path_occupied')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            try:
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise RuntimeError('agent.already_running')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        try:
            os.chmod(path, 0o660)
            if socket_gid is not None:
                os.chown(path, -1, socket_gid)
            server.listen(16)
            server.settimeout(0.2)
            if ready_event is not None:
                ready_event.set()
            while stop_event is None or not stop_event.is_set():
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(5)
                    if peer_uid(connection) not in allowed_uids:
                        log.warning('agent.peer_denied')
                        continue
                    try:
                        response = dispatch(receive(connection), handlers)
                        send(connection, response.model_dump_json(exclude_unset=True).encode())
                    except (OSError, EOFError, ValueError):
                        log.warning('agent.invalid_connection')
        finally:
            path.unlink(missing_ok=True)


def panel_probe():
    """Probe uvicorn's local Unix socket (compatible with AF_UNIX confinement)."""
    path = os.environ.get('VS_ROUTER_PANEL_SOCKET', '/run/vs-router/web/web.sock')
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(path)
            connection.sendall(b'GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n')
            return connection.recv(1024).split(b'\r\n', 1)[0].split()[1] == b'200'
    except (OSError, IndexError):
        return False


def make_handlers(engine, database):
    def apply_version(version_id, safe_mode=False, confirmation_timeout=180):
        with Session(database) as db:
            row = db.get(ConfigurationRow, version_id)
            if row is None:
                raise ApplyError('version.not_found')
            if row.status != 'draft':
                raise ApplyError('version.not_draft')
            result = engine.apply_version(row.snapshot().model_dump(mode='json'), safe_mode,
                                          confirmation_timeout)
            if result.status == 'confirmed':
                row.status = 'confirmed'
                db.commit()
            return result

    def confirm_version(version_id):
        with Session(database) as db:
            row = db.get(ConfigurationRow, version_id)
            if row is None:
                raise ApplyError('version.not_found')
            applied = json.loads(engine.fs.read(APPLIED_DIR / 'snapshot.json'))
            result = engine.confirm_version(version_id)
            # A draft can be edited in the web process while awaiting confirmation.
            # Persist the exact snapshot that was actually installed.
            row.configuration = applied['configuration']
            row.status = 'confirmed'
            db.commit()
            return result

    def status():
        from .rollback_check import check_deadline
        check_deadline(engine.status(), engine.rollback, engine.clock)
        return engine.status()

    return {'apply_version': apply_version, 'confirm_version': confirm_version,
            'rollback': lambda: engine.rollback('requested'), 'status': status}


def main():
    logging.basicConfig(level=logging.INFO)
    web_user = pwd.getpwnam('vs-router-web')
    database = create_engine(os.environ.get('VS_ROUTER_DATABASE_URL', 'sqlite:///vs-router.db'))
    from .services import NftApply, UnboundReloader, KeaReloader, NetworkdReloader, WireGuardReloader, CaddyReloader
    engine = ApplyEngine(panel_probe=panel_probe, reload_commands={
        'nftables': NftApply(), 'unbound': UnboundReloader(), 'kea': KeaReloader(),
        'networkd': NetworkdReloader(),
        'wireguard': WireGuardReloader(), 'caddy': CaddyReloader(),
    })
    serve(os.environ.get('VS_ROUTER_AGENT_SOCKET', SOCKET_PATH), make_handlers(engine, database),
          {0, web_user.pw_uid}, socket_gid=None)


if __name__ == '__main__':
    main()
