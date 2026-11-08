"""Consistent local master SQLite backups; no external transmission."""
from contextlib import closing
from importlib import import_module
import os
from pathlib import Path
import sqlite3
import stat

from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from vs_master.models import Account, make_engine

ROOT = Path(__file__).resolve().parents[1]


def test_master_release_installs_daily_local_backup_timer():
    from vs_router.profiles import module_profile

    service = ROOT / 'packaging/vs-master-backup.service'
    timer = ROOT / 'packaging/vs-master-backup.timer'
    assert service.is_file() and timer.is_file()
    assert 'User=vs-master-web' in service.read_text()
    assert 'vs_master.backup' in service.read_text()
    assert 'OnCalendar=daily' in timer.read_text()
    release = (ROOT / 'packaging/make-master-release.sh').read_text()
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    assert 'vs-master-backup.service' in release and 'vs-master-backup.timer' in release
    assert 'vs-master-backup.service' in installer and 'vs-master-backup.timer' in installer
    assert 'systemctl enable --now vs-master-backup.timer' in installer
    assert module_profile('vs_master.backup') == 'master'


def test_master_backup_restores_wal_rows_and_retains_history(tmp_path, monkeypatch):
    source = tmp_path / 'master.db'
    monkeypatch.setenv('VS_MASTER_DATABASE_URL', f'sqlite:///{source}')
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic-master/alembic.ini'))
    command.upgrade(config, 'head')
    engine = make_engine(f'sqlite:///{source}')
    with Session(engine) as db:
        db.add(Account(display_name='Synthetic', telegram_chat_id='42', password_hash='test'))
        db.commit()
    engine.dispose()

    backup = import_module('vs_master.backup').backup
    directory = tmp_path / 'backups'
    first = backup(source, directory)
    assert first.is_file() and first.parent == directory
    assert not list(directory.glob('*.partial'))
    with closing(sqlite3.connect(first)) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert db.execute('SELECT telegram_chat_id FROM master_accounts').fetchone() == ('42',)
    if os.name != 'nt':
        assert stat.S_IMODE(first.stat().st_mode) & 0o077 == 0
    second = backup(source, directory)
    assert second != first and first.exists() and second.exists()
    third = backup(source, directory, keep=2)
    assert not first.exists() and second.exists() and third.exists()


def test_backup_rejects_missing_database_without_creating_it(tmp_path):
    backup = import_module('vs_master.backup').backup
    source = tmp_path / 'missing.db'
    try:
        backup(source, tmp_path / 'backups')
    except FileNotFoundError:
        pass
    else:
        assert False, 'missing source must fail closed'
    assert not source.exists()
