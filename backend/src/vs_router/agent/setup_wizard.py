"""ASCII-only first-boot setup wizard for the panel portal."""
import getpass
import os
import re
import sys

from typing import cast

from argon2 import PasswordHasher, Type
from sqlalchemy import Table, create_engine, inspect, insert, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from vs_portal.models import Setting

from ..db import UserRow
from ..management import read_management
from .rpc import AgentClient, PanelDomainParams

PANEL_DATABASE_URL = 'sqlite:////var/lib/vs-router/vs-router.db'
PORTAL_DATABASE_URL = 'sqlite:////var/lib/vs-router/portal/vs-portal.db'
AGENT_SOCKET = '/run/vs-router/agent.sock'
LOGIN_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{1,64}$')
BOT_TOKEN_PATTERN = re.compile(r'^\d+:[a-zA-Z0-9_-]+$')
SUPPORT_URL_PATTERN = re.compile(r'^https://t\.me/[a-zA-Z0-9_][a-zA-Z0-9_/-]*$')


def set_panel_domain(hostname):
    """Publish a panel domain through the privileged agent RPC."""
    from .daemon import UnixSocketTransport

    transport = UnixSocketTransport(os.environ.get('VS_ROUTER_AGENT_SOCKET', AGENT_SOCKET))
    try:
        return AgentClient(transport).call(
            'set_panel_domain', PanelDomainParams(hostname=hostname))
    finally:
        transport.close()


class SetupWizard:
    def __init__(self, *, input_fn=input, password_fn=getpass.getpass, print_fn=print,
                 panel_engine=None, portal_engine=None, management_reader=read_management,
                 domain_setter=set_panel_domain):
        self.input = input_fn
        self.password = password_fn
        self.print = print_fn
        self.panel_engine = panel_engine or create_engine(
            os.environ.get('VS_ROUTER_DATABASE_URL', PANEL_DATABASE_URL))
        self.portal_engine = portal_engine or create_engine(
            os.environ.get('VS_PORTAL_DATABASE_URL', PORTAL_DATABASE_URL))
        self.management_reader = management_reader
        self.domain_setter = domain_setter
        self.hasher = PasswordHasher(type=Type.ID)

    def configured(self):
        """Return true only when portal settings and an admin both exist."""
        try:
            if not inspect(self.portal_engine).has_table(Setting.__tablename__):
                return False
            with Session(self.portal_engine) as portal_db:
                setting = portal_db.scalar(select(Setting.key).where(
                    Setting.key.in_(('support_url', 'bot_token'))).limit(1))
            if setting is None or not inspect(self.panel_engine).has_table(UserRow.__tablename__):
                return False
            with Session(self.panel_engine) as panel_db:
                admin = panel_db.scalar(select(UserRow.id).where(
                    UserRow.role == 'admin').limit(1))
            return admin is not None
        except SQLAlchemyError:
            return False

    def prompt_login(self):
        while True:
            login = self.input('Admin login [admin]: ').strip() or 'admin'
            if LOGIN_PATTERN.fullmatch(login):
                return login
            self.print('Login must use 1-64 letters, digits, dot, underscore, or dash.')

    def prompt_password(self):
        while True:
            password = self.password('Admin password: ')
            repeated = self.password('Repeat password: ')
            if 8 <= len(password) <= 1024 and password == repeated:
                return password
            self.print('Passwords must match and contain 8-1024 characters.')

    def prompt_domain(self):
        state = self.management_reader()
        if state is None:
            raise ValueError('management.state_missing')
        current = state.custom_hostname or state.hostname or state.ip
        self.print(f'Current panel hostname: {current}')
        while True:
            domain = self.input(f'Panel domain [{current}]: ').strip() or current
            try:
                PanelDomainParams(hostname=domain)
            except ValueError:
                self.print('Invalid panel domain.')
                continue
            return current, domain

    def prompt_token(self):
        while True:
            token = self.password('Telegram bot token: ').strip()
            if BOT_TOKEN_PATTERN.fullmatch(token) and len(token) <= 256:
                return token
            self.print('Invalid Telegram bot token format.')

    def prompt_support_url(self):
        while True:
            url = self.input('Support Telegram link (https://t.me/...): ').strip()
            if SUPPORT_URL_PATTERN.fullmatch(url) and len(url) <= 256:
                return url
            self.print('Invalid Telegram support link.')

    def write_admin(self, login, password_hash):
        with Session(self.panel_engine) as db:
            db.execute(text('BEGIN IMMEDIATE'))
            user_id = db.scalar(select(UserRow.id).where(UserRow.username == login))
            if user_id is None:
                db.execute(insert(UserRow).values(
                    username=login, password_hash=password_hash, role='admin'))
            else:
                db.execute(update(UserRow).where(UserRow.id == user_id).values(
                    password_hash=password_hash, role='admin'))
            db.commit()

    def write_settings(self, bot_token, support_url):
        cast(Table, Setting.__table__).create(self.portal_engine, checkfirst=True)
        with Session(self.portal_engine) as db:
            db.execute(text('BEGIN IMMEDIATE'))
            for key, value in (('bot_token', bot_token), ('support_url', support_url)):
                if db.get(Setting, key) is None:
                    db.execute(insert(Setting).values(key=key, value=value))
                else:
                    db.execute(update(Setting).where(Setting.key == key).values(value=value))
            db.commit()

    def run(self):
        if self.configured():
            self.print('Portal already configured')
            return 0

        login = self.prompt_login()
        password = self.prompt_password()
        current_domain, domain = self.prompt_domain()
        token = self.prompt_token()
        support_url = self.prompt_support_url()

        self.print('Setup summary:')
        self.print(f'Admin login: {login}')
        self.print('Admin password: [set]')
        self.print(f'Panel domain: {domain}')
        self.print('Telegram bot token: [set]')
        self.print(f'Support contact: {support_url}')
        if self.input('Write configuration? [y/n]: ').strip().lower() not in ('y', 'yes'):
            self.print('Setup cancelled.')
            return 1

        password_hash = self.hasher.hash(password)
        if domain != current_domain:
            self.domain_setter(domain)
        self.write_admin(login, password_hash)
        self.write_settings(token, support_url)
        self.print('Portal setup complete.')
        return 0


def main():
    try:
        return SetupWizard().run()
    except (EOFError, KeyboardInterrupt):
        print('Setup cancelled.', file=sys.stderr)
        return 1
    except (OSError, SQLAlchemyError, ValueError) as exc:
        code = str(exc)
        print(code if re.fullmatch(r'[a-z0-9]+(?:\.[a-z0-9_]+)+', code)
              else 'portal.setup_failed', file=sys.stderr)
        return 1
    except Exception:
        print('portal.setup_failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
