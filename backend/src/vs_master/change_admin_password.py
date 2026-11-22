"""Change an existing master administrator password from the server console.

Run ``python -m vs_master.change_admin_password`` with VS_MASTER_DATABASE_URL
set to the same database as vs-master-web.service. Passwords are accepted only
through getpass on an interactive terminal, never arguments or environment.
"""
import getpass
import os
import sys
import warnings

from argon2 import PasswordHasher, Type
from argon2.exceptions import HashingError
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .auth import ADMIN_PASSWORD_KEY
from .models import Audit, Setting, make_engine


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments in (['--help'], ['-h']):
        print(__doc__)
        return 0
    if arguments:
        print('No arguments accepted; enter the password at the console prompts.', file=sys.stderr)
        return 1
    if not os.environ.get('VS_MASTER_DATABASE_URL', '').strip():
        print('Set VS_MASTER_DATABASE_URL to the master service database first.', file=sys.stderr)
        return 1
    if not sys.stdin.isatty():
        print('An interactive server terminal is required.', file=sys.stderr)
        return 1
    try:
        # getpass must not fall back to echoing input if terminal control fails.
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('New administrator password: ')
            repeated = getpass.getpass('Repeat new administrator password: ')
        if password != repeated:
            print('Passwords do not match; nothing changed.', file=sys.stderr)
            return 1
        if not 8 <= len(password) <= 1024:
            print('Password must contain 8 to 1024 characters; nothing changed.', file=sys.stderr)
            return 1
        if input('Change the administrator password and revoke all admin sessions? Type yes: ') != 'yes':
            print('Cancelled; nothing changed.', file=sys.stderr)
            return 1
        password_hash = PasswordHasher(type=Type.ID).hash(password)
    except (EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print('\nCancelled; secure console input unavailable or interrupted.', file=sys.stderr)
        return 1
    except HashingError:
        print('Password hashing failed; nothing changed.', file=sys.stderr)
        return 1

    engine = None
    try:
        engine = make_engine()
        with Session(engine) as db, db.begin():
            if engine.dialect.name == 'sqlite':
                db.execute(text('BEGIN IMMEDIATE'))
            setting = db.scalar(select(Setting).where(
                Setting.key == ADMIN_PASSWORD_KEY).with_for_update())
            if setting is None:
                print('Administrator is not initialized; nothing changed.', file=sys.stderr)
                return 1
            # The salted hash is also the durable session revision checked by
            # current_admin in every worker. Audit and password commit together.
            setting.value = password_hash
            db.add(Audit(actor='console', action='admin.password.change', detail=None))
    except (SQLAlchemyError, ValueError):
        # Database exceptions can contain URLs, SQL parameters and hashes.
        print('Password change failed; check the master database configuration and permissions.',
              file=sys.stderr)
        return 1
    finally:
        if engine is not None:
            engine.dispose()
    print('Administrator password changed; existing admin sessions revoked.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
