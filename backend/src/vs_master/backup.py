"""Consistent, local-only master SQLite backups (no key or off-host transfer)."""
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from urllib.parse import quote

from sqlalchemy.engine import make_url


def backup(source: Path, directory: Path, *, keep: int = 7) -> Path:
    """Copy a live WAL database and atomically publish an integrity-checked backup."""
    source, directory = Path(source), Path(directory)
    if not source.is_file() or source.is_symlink():
        raise FileNotFoundError(source)
    if keep < 1 or directory.is_symlink():
        raise ValueError('invalid backup destination or retention')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    name = datetime.now(timezone.utc).strftime('master-%Y%m%dT%H%M%S%fZ.db')
    target = directory / name
    partial = directory / (name + '.partial')
    source_uri = 'file:' + quote(source.resolve().as_posix(), safe='/:') + '?mode=ro'
    try:
        descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(source_uri, uri=True, timeout=30)) as src:
            if src.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='master_accounts'").fetchone() is None:
                raise ValueError('master database schema is missing')
            with closing(sqlite3.connect(partial, timeout=30)) as dst:
                src.backup(dst)
                dst.commit()
                if dst.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                    raise RuntimeError('backup integrity check failed')
        os.chmod(partial, 0o600)
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    for stale in sorted(directory.glob('master-*.db'), reverse=True)[keep:]:
        stale.unlink()
    return target


def main() -> None:
    url = make_url(os.environ['VS_MASTER_DATABASE_URL'])
    if url.get_backend_name() != 'sqlite' or not url.database:
        raise ValueError('master backup requires a file-based SQLite database')
    source = Path(url.database)
    if not source.is_absolute():
        raise ValueError('master database path must be absolute')
    backup(source, source.parent / 'backups')


if __name__ == '__main__':
    main()
