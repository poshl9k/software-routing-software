"""Length-framed JSON RPC on a peer-authenticated Unix socket."""
import json
import logging
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess

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
    """Probe provisioned HTTPS only; Unix API health is not LAN access."""
    from ..management import host_management, TLS_DIR
    try:
        management = host_management()
        if management is None:
            return False
        import ssl
        from urllib.request import build_opener, ProxyHandler, HTTPSHandler
        context = ssl.create_default_context(cafile=str(TLS_DIR / 'ca.crt'))
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        with opener.open(f'https://{management.ip}/health', timeout=3) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


def list_interfaces() -> list[dict[str, str | None]]:
    """Read the host's link inventory without changing network configuration."""
    try:
        output = subprocess.run(['ip', '-br', 'link'], capture_output=True,
                                text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        raise ApplyError('host.interfaces_unavailable') from None
    interfaces: list[dict[str, str | None]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name, separator, parent = fields[0].partition('@')
        kind = ('vlan' if separator else 'bridge' if name.startswith('br')
                else 'bond' if name.startswith('bond') else 'physical')
        # Field 2 is the MAC (e.g. aa:bb:cc:dd:ee:ff); point-to-point links
        # have no MAC and show the flag list there instead.
        mac = fields[2] if len(fields) > 2 and not fields[2].startswith('<') else None
        interfaces.append({'name': name, 'kind': kind,
                           'parent': parent if separator else None,
                           'operstate': fields[1], 'mac': mac})
    return interfaces


def list_addresses() -> dict[str, list[str]]:
    """Read live IPv4 addresses per interface without changing configuration.

    Used to show the address a DHCP client actually received, distinct from the
    configured desired state.
    """
    try:
        output = subprocess.run(['ip', '-j', '-4', 'addr', 'show'], capture_output=True,
                                text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        raise ApplyError('host.interfaces_unavailable') from None
    try:
        entries = json.loads(output)
    except ValueError:
        raise ApplyError('host.interfaces_unavailable') from None
    addresses: dict[str, list[str]] = {}
    for entry in entries:
        name = entry.get('ifname')
        if not name:
            continue
        addresses[name] = [f"{info.get('local')}/{info.get('prefixlen')}"
                           for info in entry.get('addr_info', [])
                           if info.get('family') == 'inet' and info.get('local')]
    return addresses


def make_handlers(engine, database, updater=None):
    def safe_host(host):
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return bool(re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host))

    def diag_ping(host, count, source_interface=None):
        if not safe_host(host):
            raise ApplyError('diag.invalid_input')
        command = ['ping', '-c', str(count), '-W', '2']
        if source_interface:
            command += ['-I', source_interface]
        command += [host]
        try:
            out = subprocess.run(command, capture_output=True, text=True, timeout=10,
                                 check=False).stdout
        except subprocess.TimeoutExpired:
            raise ApplyError('diag.timeout') from None
        from ..api.diag import parse_ping
        try:
            return parse_ping(out)
        except Exception:
            raise ApplyError('diag.parse_failed') from None

    def diag_traceroute(host):
        if not safe_host(host):
            raise ApplyError('diag.invalid_input')
        try:
            out = subprocess.run(['traceroute', '-n', host], capture_output=True, text=True,
                                 timeout=20, check=False).stdout
        except subprocess.TimeoutExpired:
            raise ApplyError('diag.timeout') from None
        return out.splitlines()

    def nft_counters():
        try:
            out = subprocess.run(['nft', '-j', 'list', 'table', 'inet', 'vs_router'],
                                 capture_output=True, text=True, timeout=5, check=True).stdout
        except Exception:
            raise ApplyError('nft.unavailable') from None
        try:
            data = json.loads(out)
            result = {}
            for entry in data.get('nftables', []):
                rule = entry.get('rule', {})
                comment = rule.get('comment')
                for expr in rule.get('expr', []):
                    counter = expr.get('counter')
                    if comment and counter:
                        result[comment] = {'packets': counter.get('packets', 0),
                                           'bytes': counter.get('bytes', 0)}
            return result
        except Exception:
            raise ApplyError('nft.unavailable') from None

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

    def update_status():
        from .update import release_status
        return release_status()

    def apply_update(release):
        from .update import apply_update as start_update
        return start_update(release)

    # Lazily construct the default downloader so merely building handlers (e.g.
    # in tests) neither touches the network nor the source store. The updater,
    # its transport, resolver and limits are all injectable.
    updater_holder = [updater]

    def get_updater():
        if updater_holder[0] is None:
            from .downloader import SourceUpdater
            updater_holder[0] = SourceUpdater()
        return updater_holder[0]

    def update_source(name, url, kind="rule_set", format="auto", authorized=False,
                      max_bytes=5_000_000, timeout=20):
        # Typed, whitelisted data only: the URL is never handed to a shell and
        # the agent re-applies its own allowlist/SSRF policy in build_spec.
        return get_updater().update(name=name, url=url, kind=kind, format=format,
                                    authorized=authorized, max_bytes=max_bytes,
                                    timeout=timeout)

    def source_status():
        return get_updater().status()

    return {'apply_version': apply_version, 'confirm_version': confirm_version,
            'rollback': lambda: engine.rollback('requested'), 'status': status,
            'diag_ping': diag_ping, 'diag_traceroute': diag_traceroute,
            'nft_counters': nft_counters, 'list_interfaces': list_interfaces,
            'list_addresses': list_addresses, 'update_status': update_status,
            'apply_update': apply_update,
            'update_source': update_source, 'source_status': source_status}


def main():
    logging.basicConfig(level=logging.INFO)
    web_user = pwd.getpwnam('vs-router-web')
    database = create_engine(os.environ.get('VS_ROUTER_DATABASE_URL', 'sqlite:///vs-router.db'))
    from .services import NftApply, UnboundReloader, KeaReloader, NetworkdReloader, WireGuardReloader, CaddyReloader
    from ..management import host_management
    from .ssh import SSHController
    engine = ApplyEngine(panel_probe=panel_probe, management_provider=host_management, ssh_controller=SSHController(), reload_commands={
        'nftables': NftApply(), 'unbound': UnboundReloader(), 'kea': KeaReloader(),
        'networkd': NetworkdReloader(),
        'wireguard': WireGuardReloader(), 'caddy': CaddyReloader(),
    })
    serve(os.environ.get('VS_ROUTER_AGENT_SOCKET', SOCKET_PATH), make_handlers(engine, database),
          {0, web_user.pw_uid}, socket_gid=None)


if __name__ == '__main__':
    main()
