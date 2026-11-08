"""One-time token bootstrap on a node, invoked by a restricted SSH key.

Read the one-time master UI token from stdin, not argv, shell history or logs.
The wrapper supplies the host encryption key via its protected EnvironmentFile.
"""
import os
import re
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from .db import MasterBridgeSetting
from .internal_app import MASTER_TOKEN_KEY, _write_master_tokens

TOKEN = re.compile(rb'[A-Za-z0-9_-]{43}(?:\r?\n)?\Z')


def install_token(engine, stream):
    token = stream.read(129)
    if not TOKEN.fullmatch(token):
        raise ValueError('invalid master bridge token')
    with Session(engine) as db:
        db.execute(text('BEGIN IMMEDIATE'))
        if db.get(MasterBridgeSetting, MASTER_TOKEN_KEY) is not None:
            raise ValueError('master bridge token already installed')
        _write_master_tokens(db, token.strip(b'\r\n').decode('ascii'), '')


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
