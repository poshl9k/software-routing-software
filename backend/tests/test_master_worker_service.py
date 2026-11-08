"""Master worker must run outside the web process and ship in its release."""
import asyncio
import importlib
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def anyio_backend():
    return 'asyncio'


def test_master_release_installs_background_worker():
    service = ROOT / 'packaging/vs-master-worker.service'
    assert service.is_file()
    unit = service.read_text()
    assert 'User=vs-master-web' in unit
    assert 'vs_master.worker_main' in unit
    assert 'ReadWritePaths=/var/lib/vs-router/master' in unit
    release = (ROOT / 'packaging/make-master-release.sh').read_text()
    assert 'vs-master-worker.service' in release
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    assert 'vs-master-worker.service' in installer
    assert 'systemctl enable --now vs-master-worker.service' in installer
    assert 'systemctl is-active --quiet vs-master-worker.service' in installer


def test_worker_module_is_master_owned():
    from vs_router.profiles import module_profile
    assert module_profile('vs_master.worker_main') == 'master'


def test_master_bot_is_separate_and_waits_for_encrypted_settings():
    from vs_router.profiles import module_profile
    service = ROOT / 'packaging/vs-master-bot.service'
    assert service.is_file()
    unit = service.read_text()
    assert 'vs_master.telegram_bot' in unit
    assert 'User=vs-master-web' in unit
    assert 'EnvironmentFile=/etc/vs-router/master.env' in unit
    assert 'master-bot.env' not in unit
    assert 'vs-master-bot.service' in (ROOT / 'packaging/make-master-release.sh').read_text()
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    assert 'systemctl enable --now vs-master-bot.service' in installer
    assert 'systemctl is-active --quiet vs-master-bot.service' in installer
    assert module_profile('vs_master.telegram_bot') == 'master'


@pytest.mark.anyio
async def test_background_worker_runs_off_event_loop_and_retries(monkeypatch):
    runner = importlib.import_module('vs_master.worker_main')
    main_thread = threading.get_ident()
    observed = []
    delays = []

    def process(engine):
        observed.append((engine, threading.get_ident()))
        if len(observed) == 1:
            raise RuntimeError('synthetic failure, not for logs')

    async def sleep(seconds):
        delays.append(seconds)
        if len(delays) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(runner, 'process_pending', process)
    with pytest.raises(asyncio.CancelledError):
        await runner.serve(object(), interval=45, sleep=sleep)
    assert len(observed) == 2
    assert all(worker_thread != main_thread for _, worker_thread in observed)
    assert delays == [45, 45]
