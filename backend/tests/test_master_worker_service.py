"""Master worker must run outside the web process and ship in its release."""
import asyncio
import importlib
import os
import shutil
import subprocess
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
    assert 'systemctl enable vs-master-bot.service' in installer
    assert 'VS_MASTER_SKIP_ACTIVE_BOT_RESTART' in installer
    guard = ('if [ "${VS_MASTER_SKIP_ACTIVE_BOT_RESTART:-0}" = 1 ] && \\\n'
             '        systemctl is-active --quiet vs-master-bot.service; then')
    assert guard in installer
    assert installer.index(guard) < installer.index('systemctl restart vs-master-bot.service')
    assert 'systemctl is-active --quiet vs-master-bot.service' in installer
    assert module_profile('vs_master.telegram_bot') == 'master'


def test_master_staging_install_does_not_start_second_bot_or_worker():
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    guard = 'if [ "${VS_MASTER_STAGING:-0}" = 1 ]; then'
    assert guard in installer
    assert installer.index(guard) < installer.index('apt-get update')
    assert 'systemctl is-enabled --quiet "$unit"' in installer
    assert 'systemctl is-active --quiet "$unit"' in installer
    assert 'vs-master-worker.service vs-master-bot.service vs-master-backup.timer' in installer
    assert 'VS_MASTER_STAGING=1: worker, bot and backup timer remain stopped' in installer
    assert installer.index('else\n    systemctl enable --now vs-master-worker.service') > installer.index(guard)
    assert installer.index('systemctl restart vs-master-bot.service') < installer.index('fi\n\n# This host may already serve the panel.')


@pytest.mark.parametrize('staging', ['0', '1'])
def test_master_installer_service_start_block_in_isolation(staging):
    bash = shutil.which('bash')
    if bash is None:
        pytest.skip('requires Bash')
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    block = installer.split('systemctl daemon-reload\n', 1)[1].split(
        '# This host may already serve the panel.', 1)[0]
    script = r'''systemctl() {
    printf '%s\n' "$*"
    if [ "$1" = is-active ] || [ "$1" = is-enabled ]; then return 1; fi
}
''' + block
    result = subprocess.run([bash, '-c', script], capture_output=True, text=True,
                            timeout=10, env={**os.environ, 'VS_MASTER_STAGING': staging})
    assert result.returncode == 0, result.stderr
    assert 'enable --now vs-master-web.service' in result.stdout
    for unit in ('vs-master-worker.service', 'vs-master-bot.service', 'vs-master-backup.timer'):
        assert ('enable --now ' + unit in result.stdout or 'enable ' + unit in result.stdout) == (staging == '0')
    assert ('restart vs-master-bot.service' in result.stdout) == (staging == '0')


@pytest.mark.parametrize('already_enabled', [False, True])
def test_master_staging_preflight_refuses_an_existing_poller(already_enabled):
    bash = shutil.which('bash')
    if bash is None:
        pytest.skip('requires Bash')
    installer = (ROOT / 'packaging/install-master.sh').read_text()
    block = installer.split('# A restored candidate may coexist with the old master.', 1)[1].split(
        '# Keep the master runtime separate from the panel', 1)[0]
    script = r'''systemctl() {
    if [ "$1" = is-enabled ] && [ "$3" = vs-master-bot.service ] && [ "$EXISTING_BOT" = 1 ]; then return 0; fi
    return 1
}
''' + block
    result = subprocess.run([bash, '-c', script], capture_output=True, text=True,
                            timeout=10, env={**os.environ, 'VS_MASTER_STAGING': '1',
                                             'EXISTING_BOT': '1' if already_enabled else '0'})
    assert (result.returncode != 0) == already_enabled
    assert ('staging requires vs-master-bot.service' in result.stderr) == already_enabled


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
