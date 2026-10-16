"""The installers record the product and can say what they installed (ADR-0026).

Read as text, like ``test_no_dhcp_host.py`` reads a unit: an install is not run
here, so the guarantees are asserted on the scripts themselves.
"""
import re
from pathlib import Path

PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'


def _read(name):
    return (PACKAGING / name).read_text(encoding='utf-8')


def test_criterion_1_install_writes_the_profile_and_rejects_an_unknown_one():
    install = _read('install.sh')
    assert '"profile":"%s"' in install.replace(' ', '')
    assert 'VS_ROUTER_PROFILE:-router' in install
    # A value outside the contract is a bug in the caller, not a warning.
    assert re.search(r'router\|panel\)\s*;;', install)
    assert 'must be router or panel' in install
    assert 'exit 1' in install


def test_criterion_2_the_marker_is_recorded_by_the_installer():
    install = _read('install.sh')
    assert 'python3 -m vs_router.profile write "$PROFILE"' in install


def test_criterion_3_a_failed_marker_write_warns_but_does_not_fail_the_install():
    install = _read('install.sh')
    # Guarded by `if !`, so `set -e` cannot abort the install on it…
    assert re.search(r'if ! python3 -m vs_router\.profile write', install)
    # …and it is loud, never silent.
    assert 'WARNING: could not record the product profile' in install
    # The guarded call must not be followed by an unconditional exit.
    block = install.split('python3 -m vs_router.profile write')[1][:200]
    assert 'exit 1' not in block


def test_criterion_4_each_install_path_declares_its_product():
    assert 'VS_ROUTER_PROFILE=panel' in _read('online-install.sh')
    assert 'VS_ROUTER_PROFILE=router' in _read('bootstrap.sh')


def test_criterion_5_semver_and_source_are_honest():
    install = _read('install.sh')
    # No hardcoded release version to drift: pyproject, then the installed wheel.
    assert 'importlib.metadata' in install
    assert "version('vs-router-backend')" in install
    assert not re.search(r'semver="?\d+\.\d+', install)
    # `source` is derived from what was actually found, not a fixed literal.
    assert 'elif [ -n "$semver" ]; then source=wheel' in install
    assert 'VS_ROUTER_RELEASE_SOURCE:-unknown' not in install
