"""One-time token bootstrap on a node, invoked by a restricted SSH key.

Read the one-time master UI token from stdin, not argv, shell history or logs.
The wrapper supplies the host encryption key via its protected EnvironmentFile.
"""
import os
import re
import secrets
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from .db import MasterBridgeSetting
from .internal_app import MASTER_TOKEN_KEY, _read_master_tokens, _write_master_tokens

TOKEN = re.compile(rb'[A-Za-z0-9_-]{43}(?:\r?\n)?\Z')


def store_token(db, token, *, allow_same=False):
    """Install one master-issued token, optionally accepting an exact retry."""
    try:
        encoded = token.encode('ascii')
    except (AttributeError, UnicodeEncodeError):
        raise ValueError('invalid master bridge token') from None
    if not TOKEN.fullmatch(encoded):
        raise ValueError('invalid master bridge token')
    db.execute(text('BEGIN IMMEDIATE'))
    row = db.get(MasterBridgeSetting, MASTER_TOKEN_KEY)
    if row is not None:
        current, _ = _read_master_tokens(db)
        if allow_same and current and secrets.compare_digest(current, token):
            db.commit()
            return False
        if allow_same and isinstance(row.value, dict) and row.value.get('setup_pending') is True:
            _write_master_tokens(db, token, '', setup_pending=True)
            return True
        db.rollback()
        raise ValueError('master bridge token already installed')
    _write_master_tokens(db, token, '', setup_pending=True)
    return True


def install_token(engine, stream):
    token = stream.read(129)
    if not TOKEN.fullmatch(token):
        raise ValueError('invalid master bridge token')
    with Session(engine) as db:
        store_token(db, token.strip(b'\r\n').decode('ascii'))


def main():
    if getattr(os, 'geteuid', lambda: -1)() != 0:
        raise SystemExit('root required')
    if 'VS_ROUTER_SECRET_KEY' not in os.environ:
        raise SystemExit('node encryption key unavailable')
    engine = create_engine('sqlite:////var/lib/vs-router/vs-router.db')
    try:
        install_token(engine, sys.stdin.buffer)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    finally:
        engine.dispose()
    print('Node bridge token installed')


if __name__ == '__main__':
    main()
