"""Kea provisioning must survive the order it is installed in.

The panel reloads DHCP through the Kea control agent and validates a staged config,
so it needs state the installer used to create only when Kea already existed. A
router with Kea installed afterwards came up unable to serve a single subnet: the
first DHCP apply failed with `kea.api_password_missing`, and the syntax check was
denied by AppArmor before that.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'


def run_setup(tmp_path, **env):
    root = tmp_path
    (root / 'kea').mkdir(parents=True, exist_ok=True)
    (root / 'units').mkdir(exist_ok=True)
    environment = {
        'PATH': os.environ['PATH'],
        'VS_ROUTER_KEA_DIR': str(root / 'kea'),
        'VS_ROUTER_UNIT_DIR': str(root / 'units'),
        'VS_ROUTER_APPLIED_DIR': str(root / 'applied'),
        'VS_ROUTER_APPARMOR_DIR': str(root / 'apparmor'),
        'VS_ROUTER_KEA_SETUP_NO_RESTART': '1',
        **env,
    }
    return subprocess.run(['sh', str(PACKAGING / 'kea-setup.sh')],
                          capture_output=True, text=True, env=environment, timeout=60)


def test_the_installer_ships_and_calls_the_kea_script():
    assert (PACKAGING / 'kea-setup.sh').is_file()
    install = (PACKAGING / 'install.sh').read_text(encoding='utf-8')
    assert 'kea-setup.sh' in install
    # The router product owns DHCP, so it installs the server instead of warning
    # about a service the operator forgot to add before the panel.
    assert 'kea-dhcp4-server kea-ctrl-agent' in install
    assert '[ "$PROFILE" = router ]' in install


def test_the_script_creates_the_control_channel(tmp_path):
    result = run_setup(tmp_path)
    assert result.returncode == 0, result.stderr
    password = tmp_path / 'kea' / 'kea-api-password'
    assert password.is_file()
    assert len(password.read_text().strip()) >= 32
    assert password.stat().st_mode & 0o777 == 0o640

    dropin = tmp_path / 'units' / 'vs-router-agent.service.d' / 'kea.conf'
    assert f'ReadWritePaths={tmp_path / "kea"}' in dropin.read_text()
    assert (tmp_path / 'units' / 'vs-router-bootrestore.service.d' / 'kea.conf').is_file()

    web = (tmp_path / 'units' / 'vs-router-web.service.d' / 'kea-api.conf').read_text()
    assert 'LoadCredential=kea-api-password:' in web
    assert 'VS_ROUTER_KEA_API_USER=kea-api' in web

    seeded = (tmp_path / 'kea' / 'kea-dhcp4.conf').read_text()
    assert '"subnet4": []' in seeded


def test_a_second_run_is_a_no_op(tmp_path):
    run_setup(tmp_path)
    password = (tmp_path / 'kea' / 'kea-api-password').read_text()
    seeded = (tmp_path / 'kea' / 'kea-dhcp4.conf').read_text()
    assert run_setup(tmp_path).returncode == 0
    assert (tmp_path / 'kea' / 'kea-api-password').read_text() == password
    assert (tmp_path / 'kea' / 'kea-dhcp4.conf').read_text() == seeded


def test_a_configuration_the_panel_owns_is_never_overwritten(tmp_path):
    (tmp_path / 'applied').mkdir()
    (tmp_path / 'applied' / 'kea.json').write_text('{"Dhcp4": {}}')
    panel_owned = tmp_path / 'kea'
    panel_owned.mkdir(exist_ok=True)
    (panel_owned / 'kea-dhcp4.conf').write_text('{"Dhcp4": {"subnet4": [1]}}')
    assert run_setup(tmp_path).returncode == 0
    assert '"subnet4": [1]' in (panel_owned / 'kea-dhcp4.conf').read_text()
