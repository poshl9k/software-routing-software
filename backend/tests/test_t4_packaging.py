"""lab-37 defect 4 — split-resolver provisioning, config access, AppArmor and the
ordinary-resolver listener collision.

Scope of the fix this guards: ``backend/packaging/install.sh`` (provision the two
fixed resolver UIDs, AppArmor/traversal) and
``backend/src/vs_router/agent/unbound_service.py`` (config re-owning and the
product-resolver conflict). Generator output, the public gate
``tproxy.not_available`` and the apply/boot ordering are untouched.

The packaging tests run the provisioning block with fake ``id``/``useradd``; they
never touch a real account, service or network.
"""
import subprocess
from pathlib import Path

import pytest

from vs_router.agent import unbound_service
from vs_router.generators import tproxy_dns

ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / 'backend/packaging'
INSTALL = PACKAGING / 'install.sh'

SELECTED = unbound_service.SELECTED_ROLE
ORDINARY = unbound_service.ORDINARY_ROLE

UID_BLOCK_START = '# >>> resolver-uids'
UID_BLOCK_END = '# <<< resolver-uids'


def bash(code, env=None):
    return subprocess.run(['bash', '-c', code], text=True, capture_output=True,
                          env=env, timeout=10)


def _resolver_uid_block():
    """The install.sh provisioning block between its two marker comments."""
    source = INSTALL.read_text()
    start = source.index(UID_BLOCK_START)
    end = source.index(UID_BLOCK_END) + len(UID_BLOCK_END)
    return source[start:end]


# --------------------------------------------------------------------------
# Provisioning of the fixed resolver UIDs (packaging)
# --------------------------------------------------------------------------

def test_install_provisions_the_pinned_resolver_uids():
    source = INSTALL.read_text()
    # The UIDs are the single source of truth in the plan module, not literals
    # invented in packaging; the split unit's User= uses the same constants.
    assert tproxy_dns.TPROXY_SELECTED_UID == 29092
    assert tproxy_dns.TPROXY_ORDINARY_UID == 29093
    assert (f'provision_resolver_user vs-router-unbound-selected '
            f'{tproxy_dns.TPROXY_SELECTED_UID}') in source
    assert (f'provision_resolver_user vs-router-unbound-ordinary '
            f'{tproxy_dns.TPROXY_ORDINARY_UID}') in source
    # Both accounts are provisioned before the units are installed/started.
    assert source.index('provision_resolver_user vs-router-unbound-selected') < \
        source.index('systemctl restart vs-router-agent.service')


def test_provisioning_is_idempotent(tmp_path):
    """A rerun keeps existing accounts (no second useradd); the first run adds
    exactly the two fixed accounts with their pinned UIDs."""
    users = tmp_path / 'users'
    calls = tmp_path / 'calls'
    code = f'''set -eu
id() {{
    if [ "$1" = -u ] && [ -f "{users}" ]; then
        awk -v n="$2" '$1==n {{print $2; found=1}} END {{exit !found}}' "{users}"
        return
    fi
    return 1
}}
useradd() {{
    name=${{@: -1}}
    uid=''; prev=''
    for a in "$@"; do [ "$prev" = --uid ] && uid=$a; prev=$a; done
    echo "$name $uid" >> "{users}"
    echo "useradd $name $uid" >> "{calls}"
}}
{_resolver_uid_block()}
'''
    for _ in range(2):
        result = bash(code)
        assert result.returncode == 0, result.stdout + result.stderr
    recorded = sorted(line.split() for line in users.read_text().splitlines())
    assert recorded == [['vs-router-unbound-ordinary', '29093'],
                        ['vs-router-unbound-selected', '29092']]
    # useradd ran exactly once per account, i.e. the rerun was a no-op.
    assert calls.read_text().splitlines() == [
        'useradd vs-router-unbound-selected 29092',
        'useradd vs-router-unbound-ordinary 29093']


def test_provisioning_fails_closed_on_uid_mismatch(tmp_path):
    """An existing account with the wrong UID must abort install instead of
    silently starting a resolver under an unexpected identity."""
    (tmp_path / 'users').write_text('vs-router-unbound-selected 1234\n')
    code = f'''set -eu
id() {{
    if [ "$1" = -u ] && [ -f "{tmp_path}/users" ]; then
        awk -v n="$2" '$1==n {{print $2; found=1}} END {{exit !found}}' "{tmp_path}/users"
        return
    fi
    return 1
}}
useradd() {{ echo "useradd $*" >> "{tmp_path}/calls"; }}
{_resolver_uid_block()}
'''
    result = bash(code)
    assert result.returncode != 0
    assert 'expected 29092' in result.stdout + result.stderr
    assert not (tmp_path / 'calls').exists()  # no partial account was created


# --------------------------------------------------------------------------
# AppArmor override and directory traversal (packaging)
# --------------------------------------------------------------------------

def test_install_apparmor_override_covers_the_split_configs():
    """The Debian usr.sbin.unbound profile blocks /etc/vs-router/applied; the
    local override must grant the whole directory (both split configs) and the
    stock `#include <local/...>` directive needs the local file to exist."""
    source = INSTALL.read_text()
    block = source[source.index('# Allow the included configuration through Unbound'):
                   source.index('# Web UI static bundle')]
    assert '/etc/vs-router/applied/** r,' in block
    assert 'touch "$local_profile"' in block
    assert 'apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound' in block
    # Idempotent: the rule is appended only when absent.
    assert 'grep -qsF' in block


def test_install_keeps_traversal_for_resolver_configs():
    """A resolver not in the vs-router-web group must still reach its own file
    under the 0770 applied directory."""
    assert 'chmod o+x /etc/vs-router /etc/vs-router/applied' in INSTALL.read_text()


# --------------------------------------------------------------------------
# Config access: the unit re-owns its own 0600 config to the resolver UID
# --------------------------------------------------------------------------

@pytest.mark.parametrize('role', [SELECTED, ORDINARY])
def test_unit_reowns_its_config_to_the_resolver_uid(role):
    text = unbound_service.unit_content(role)
    expected = (f"ExecStartPre=+{unbound_service.CHOWN_BINARY} "
                f"{unbound_service.uid_for(role)} "
                f"{unbound_service.config_path(role)}")
    assert expected in text
    # Same fixed config path the apply artifact and readiness check use.
    assert str(unbound_service.config_path(role)) in text
    assert f"User={unbound_service.uid_for(role)}" in text


def test_execstartpre_is_privileged_and_shell_free():
    for role in unbound_service.ROLES:
        line = next(l for l in unbound_service.unit_content(role).splitlines()
                    if l.startswith('ExecStartPre='))
        # Privileged so it can re-own a root-owned file despite ProtectSystem.
        assert line.startswith('ExecStartPre=+')
        assert line.startswith(f'ExecStartPre=+{unbound_service.CHOWN_BINARY} ')
        # Fixed absolute argv: no shell, no caller-supplied value.
        for meta in (';', '|', '&', '$', '`', '>', '<', '"', "'"):
            assert meta not in line


# --------------------------------------------------------------------------
# Ordinary-resolver listener collision: the split units replace the product unit
# --------------------------------------------------------------------------

@pytest.mark.parametrize('role', [SELECTED, ORDINARY])
def test_units_conflict_with_the_product_resolver(role):
    assert unbound_service.PRODUCT_UNBOUND_UNIT == 'unbound.service'
    text = unbound_service.unit_content(role)
    unit_section = text.split('[Service]')[0]
    assert f'Conflicts={unbound_service.PRODUCT_UNBOUND_UNIT}' in unit_section
    after = next(l for l in unit_section.splitlines() if l.startswith('After='))
    assert unbound_service.PRODUCT_UNBOUND_UNIT in after.split()


def test_conflict_does_not_change_the_split_identity():
    """The conflict is additive: unit names, UIDs, config paths and the
    privilege-minimal service body stay the pinned constants."""
    for role in unbound_service.ROLES:
        text = unbound_service.unit_content(role)
        assert f"ExecStart={unbound_service.UNBOUND_BINARY} -d -c " \
               f"{unbound_service.config_path(role)}" in text
        assert 'NoNewPrivileges=true' in text
        assert 'AmbientCapabilities=CAP_NET_BIND_SERVICE' in text
        assert 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' in text
        assert 'ProtectSystem=strict' in text
        assert 'WantedBy=multi-user.target' in text
        lowered = text.lower()
        assert 'password' not in lowered and 'token' not in lowered
    assert 'User=29092' in unbound_service.unit_content(SELECTED)
    assert 'User=29093' in unbound_service.unit_content(ORDINARY)
