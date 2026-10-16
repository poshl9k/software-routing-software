"""Local root console menu. Pending network edits remain in memory until apply.

Every user-facing string is plain ASCII English on purpose: the menu runs on the
physical console (tty1) of the installed image, whose console font has no Cyrillic
glyphs, so Russian labels render as mojibake (`0$)B0...`). English keeps the menu
readable on any console and any locale.
"""
import getpass
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface
import os
from pathlib import Path
import re
import subprocess
import sys

from argon2 import PasswordHasher, Type
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from ..api.configuration import parse_configuration, validate
from ..api.errors import APIError
from ..db import ConfigurationRow, UserRow
from ..management import Management, STATE_DIR, read_management, verify_identity, wired_ports
from ..schema import Configuration
from .management_console import Console
from .rpc import AgentRPCError


@dataclass
class Addressing:
    mode: str
    address: str | None = None
    gateway: str | None = None
    dns: tuple[str, ...] = ()


@dataclass
class Selection:
    roles: dict[str, str] = field(default_factory=dict)
    addresses: dict[str, Addressing] = field(default_factory=dict)


def local_guard(uid=None, tty=None, ssh=None):
    if (os.geteuid() if uid is None else uid) != 0 or not (
            sys.stdin.isatty() if tty is None else tty) or (
            os.environ.get('SSH_CONNECTION') if ssh is None else ssh):
        raise ValueError('console.local_root_required')


def parse_role(value):
    role = value.strip().lower()
    if role not in ('wan', 'lan', '', '-'):
        raise ValueError('console.invalid_role')
    return None if role in ('', '-') else role


def static_address(address, gateway='', dns=''):
    try:
        interface = IPv4Interface(address.strip())
        Management(interface='lan0', mac='00:00:00:00:00:01', address=str(interface))
        router = gateway.strip() or None
        servers = tuple(part.strip() for part in dns.replace(',', ' ').split())
        if router:
            IPv4Address(router)
        for server in servers:
            IPv4Address(server)
        if router and IPv4Address(router) not in interface.network:
            raise ValueError('console.invalid_address')
    except (ValueError, TypeError):
        raise ValueError('console.invalid_address') from None
    return Addressing('static', str(interface), router, servers)


def build_configuration(selection, previous=None):
    if sum(role == 'lan' for role in selection.roles.values()) != 1 or not any(
            role == 'wan' for role in selection.roles.values()):
        raise ValueError('console.roles_required')
    lan = next(name for name, role in selection.roles.items() if role == 'lan')
    if lan not in selection.addresses or selection.addresses[lan].mode != 'static':
        raise ValueError('management.dhcp_forbidden')
    base = (previous or Configuration()).model_dump(mode='json')
    existing = {i['name']: i for i in base['interfaces'] if i['type'] == 'physical'}
    base['interfaces'] = [dict(existing.get(name, {}), name=name, type='physical', zone=role,
                               addressing=selection.addresses.get(name, Addressing('static')).mode,
                               addresses=([selection.addresses[name].address]
                                          if name in selection.addresses and
                                          selection.addresses[name].mode == 'static' else []))
                          for name, role in sorted(selection.roles.items())] + [
                              i for i in base['interfaces'] if i['type'] != 'physical']
    # Retain non-default static routes on selected interfaces.
    base['static_routes'] = [route for route in base['static_routes']
                             if route['interface'] not in selection.roles or
                             route['destination'] != '0.0.0.0/0']
    for name, spec in sorted(selection.addresses.items()):
        if name in selection.roles and spec.gateway:
            base['static_routes'].append(dict(destination='0.0.0.0/0',
                                              interface=name, gateway=spec.gateway))
    dns = [server for name, spec in sorted(selection.addresses.items())
           if name in selection.roles for server in spec.dns]
    if dns:
        base['dns']['upstreams'] = [dict(address=server) for server in dict.fromkeys(dns)]
    return parse_configuration(base, (previous or Configuration()).model_dump(mode='json'))


def render_status(ports, selection, version, services, management=None, fingerprint=None):
    lines = [f'Version: {version if version is not None else "not applied"}']
    for name, mac in sorted(ports.items()):
        role = selection.roles.get(name, 'unassigned')
        spec = selection.addresses.get(name)
        lines.append(f'{name} {mac}: {role}, {spec.address if spec and spec.address else spec.mode if spec else "no address"}')
    for name, state in services.items():
        lines.append(f'{name}: {state}')
    lines.append(f'Panel: https://{management.ip}/' if management else 'Panel: not configured')
    lines.append(f'CA SHA-256: {fingerprint}' if fingerprint else 'CA: not installed')
    return '\n'.join(lines)


class Menu:
    def __init__(self, *, input_fn=input, print_fn=print, password_fn=getpass.getpass,
                 runner=None, sysnet=Path('/sys/class/net'), console=None, database=None,
                 apply_fn=None):
        self.input = input_fn
        self.print = print_fn
        self.password = password_fn
        self.runner = runner or self.run
        self.sysnet = sysnet
        self.console = console
        # The panel/agent store their database at an absolute product path;
        # fall back to it (not a cwd-relative file) so the console sees the real
        # configuration even without an inherited environment.
        self.database = database or create_engine(os.environ.get(
            'VS_ROUTER_DATABASE_URL', 'sqlite:////var/lib/vs-router/vs-router.db'))
        self.apply_fn = apply_fn or self.apply_rpc
        self.selection = Selection()

    @staticmethod
    def run(argv):
        if argv == ['/bin/sh']:
            return subprocess.run(argv, timeout=3600, check=False)
        return subprocess.run(argv, capture_output=True, timeout=15, check=False)

    @staticmethod
    def apply_rpc(version_id):
        from .daemon import UnixSocketTransport
        from .rpc import AgentClient, ApplyParams
        transport = UnixSocketTransport(os.environ.get('VS_ROUTER_AGENT_SOCKET',
                                                       '/run/vs-router/agent.sock'))
        try:
            return AgentClient(transport).call('apply_version', ApplyParams(version_id=version_id))
        finally:
            transport.close()

    def ports(self):
        return wired_ports(self.sysnet)

    def assign(self):
        ports = self.ports()
        roles = {}
        for name, mac in sorted(ports.items()):
            try:
                carrier = (self.sysnet / name / 'carrier').read_text().strip()
            except OSError:
                carrier = '?'
            roles[name] = parse_role(self.input(f'{name} {mac} link={carrier} [WAN/LAN/-]: '))
        roles = {name: role for name, role in roles.items() if role}
        self.print('Assignment: ' + ', '.join(f'{name}={role}' for name, role in roles.items()))
        if self.input('Confirm? [y/n]: ').strip().lower() in ('y', 'yes'):
            self.selection.roles = roles
            self.selection.addresses = {name: spec for name, spec in self.selection.addresses.items()
                                        if name in roles}

    def set_address(self):
        if not self.selection.roles:
            with Session(self.database) as db:
                row = db.scalar(select(ConfigurationRow).where(
                    ConfigurationRow.status == 'confirmed').order_by(ConfigurationRow.id.desc()))
                if row:
                    self.selection.roles = {i.name: i.zone for i in row.configuration.interfaces
                                            if i.type == 'physical' and i.zone in ('wan', 'lan')}
                    self.selection.addresses = {
                        i.name: Addressing(i.addressing, i.addresses[0] if i.addresses else None,
                                           next((r.gateway for r in row.configuration.static_routes
                                                 if r.interface == i.name and
                                                 r.destination == '0.0.0.0/0'), None))
                        for i in row.configuration.interfaces if i.name in self.selection.roles}
        names = sorted(self.selection.roles)
        if not names:
            raise ValueError('console.roles_required')
        self.print(', '.join(names))
        name = self.input('Interface: ').strip()
        if name not in names:
            raise ValueError('console.invalid_interface')
        mode = self.input('Addressing (dhcp/static): ').strip().lower()
        if mode == 'dhcp':
            if self.selection.roles[name] == 'lan':
                raise ValueError('management.dhcp_forbidden')
            spec = Addressing('dhcp')
        elif mode == 'static':
            default = '192.168.10.1/24' if self.selection.roles[name] == 'lan' else ''
            address = self.input(f'IP/prefix [{default}]: ').strip() or default
            spec = static_address(address, self.input('Gateway (empty = none): '),
                                  self.input('DNS (space separated, empty = none): '))
        else:
            raise ValueError('console.invalid_addressing')
        self.selection.addresses[name] = spec

    def set_password(self):
        secret = self.password('New admin password: ')
        if not 8 <= len(secret) <= 1024 or secret != self.password('Repeat password: '):
            raise ValueError('console.password_invalid')
        hashed = PasswordHasher(type=Type.ID).hash(secret)
        with Session(self.database) as db:
            db.execute(text('BEGIN IMMEDIATE'))
            user = db.scalar(select(UserRow).where(UserRow.username == 'admin'))
            if user is None:
                user = UserRow(username='admin', password_hash=hashed, role='admin')
                db.add(user)
            else:
                user.password_hash = hashed
                user.role = 'admin'
            db.commit()
        self.print('Password updated.')

    def status(self):
        row = None
        try:
            with Session(self.database) as db:
                row = db.scalar(select(ConfigurationRow).where(
                    ConfigurationRow.status == 'confirmed').order_by(ConfigurationRow.id.desc()))
        except Exception:
            # A not-yet-created/empty database must not crash the console.
            self.print('Configuration unavailable yet (database not initialized).')
        state = read_management((self.console.path(STATE_DIR) if self.console else STATE_DIR)
                                / 'management.json')
        if state:
            verify_identity(state, self.sysnet)
        ca_path = (self.console.path(STATE_DIR) if self.console else STATE_DIR) / 'ca/ca.crt'
        fingerprint = (x509.load_pem_x509_certificate(ca_path.read_bytes()).fingerprint(
            hashes.SHA256()).hex(':') if ca_path.exists() else None)
        services = {}
        for name in ('vs-router-agent', 'vs-router-web', 'caddy', 'vs-router-singbox'):
            result = self.runner(['systemctl', 'is-active', name])
            services[name] = 'active' if result.returncode == 0 else 'inactive'
        displayed = Selection(dict(self.selection.roles), dict(self.selection.addresses))
        if row:
            for interface in row.configuration.interfaces:
                displayed.roles.setdefault(interface.name, interface.zone or 'unassigned')
                displayed.addresses.setdefault(interface.name, Addressing(
                    interface.addressing, interface.addresses[0] if interface.addresses else None))
        self.print(render_status(self.ports(), displayed, row.id if row else None,
                                 services, state, fingerprint))

    def save_apply(self):
        ports = self.ports()
        lan = next((name for name, role in self.selection.roles.items() if role == 'lan'), None)
        if lan not in ports or any(name not in ports for name in self.selection.roles):
            raise ValueError('management.identity_mismatch')
        with Session(self.database) as db:
            db.execute(text('BEGIN IMMEDIATE'))
            pending = db.scalar(select(ConfigurationRow).where(ConfigurationRow.status == 'draft'))
            previous = (pending or db.scalars(select(ConfigurationRow).order_by(
                ConfigurationRow.id.desc())).first())
            configuration = build_configuration(self.selection, previous.configuration if previous else None)
            state = read_management(self.console.path(STATE_DIR / 'management.json')
                                    if self.console else STATE_DIR / 'management.json')
            expected = Management(interface=lan, mac=ports[lan],
                                  address=self.selection.addresses[lan].address)
            if state is not None and state != expected:
                raise ValueError('management.migration_not_supported')
            payload = configuration.model_dump(mode='json')
            verdict = validate(payload)
            if not verdict['valid']:
                raise ValueError('configuration.invalid')
            from ..management import validate_management
            validate_management(configuration, expected)
            if pending:
                if pending.configuration != configuration:
                    raise ValueError('draft.exists')
                row = pending
            else:
                row = ConfigurationRow(id=(db.scalar(select(func.max(ConfigurationRow.id))) or 0) + 1,
                                       status='draft', configuration=configuration,
                                       profile=previous.profile if previous else 'router')
                db.add(row)
            db.commit()
            version_id = row.id
        applied_path = (self.console.path('/etc/vs-router/applied/snapshot.json')
                        if self.console else Path('/etc/vs-router/applied/snapshot.json'))
        if not applied_path.exists():
            # A failed provisioning run can leave management.json behind.
            # Console.provision validates identity and resumes without replacing the CA.
            (self.console or Console()).provision(ports[lan], expected.address)
        else:
            if state is None:
                raise ValueError('management.state_missing')
            verify_identity(state, self.sysnet)
        try:
            result = self.apply_fn(version_id)
        except AgentRPCError as exc:
            raise ValueError(exc.error.message if re.fullmatch(
                r'[a-z0-9]+(?:\.[a-z0-9_]+)+', exc.error.message)
                else 'agent.apply_failed') from None
        status = result.get('status') if isinstance(result, dict) else result.status
        if status != 'confirmed':
            raise ValueError('agent.apply_failed')
        self.print(f'Version {version_id} applied. Panel: https://{expected.ip}/')

    def ping(self):
        host = self.input('Host (IP or name): ').strip()
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}', host) or host.startswith('-'):
            raise ValueError('console.invalid_host')
        result = self.runner(['ping', '-c', '3', '-W', '2', host])
        self.print('Ping: success' if result.returncode == 0 else 'Ping: no reply')

    def loop(self):
        local_guard()
        actions = {'1': self.assign, '2': self.set_address, '3': self.set_password,
                   '4': self.status, '5': self.save_apply, '8': self.ping,
                   '6': lambda: self.runner(['systemctl', 'reboot']),
                   '7': lambda: self.runner(['systemctl', 'poweroff']),
                   '9': lambda: self.runner(['/bin/sh'])}
        while True:
            self.print('0) Logout | 1) Assign interfaces (WAN/LAN) | 2) Set interface IP address\n'
                       '3) Reset administrator password | 4) Show status | 5) Save and apply\n'
                       '6) Reboot | 7) Power off | 8) Ping | 9) Shell')
            try:
                choice = self.input('> ').strip()
                if choice == '0':
                    return 0
                if choice not in actions:
                    raise ValueError('console.invalid_option')
                actions[choice]()
            except (EOFError, KeyboardInterrupt):
                return 0
            except (ValueError, APIError, OSError, subprocess.SubprocessError) as exc:
                code = exc.code if isinstance(exc, APIError) else str(exc)
                self.print(code if re.fullmatch(r'[a-z0-9]+(?:\.[a-z0-9_]+)+', code)
                           else 'console.operation_failed')
            except Exception:
                # Never leak a traceback to the physical console.
                self.print('console.operation_failed')


def main():
    try:
        local_guard()
        return Menu().loop()
    except ValueError:
        print('console.local_root_required', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
