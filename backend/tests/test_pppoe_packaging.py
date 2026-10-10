"""Static packaging contract; real pppd negotiation needs the Debian VM."""
from pathlib import Path
import runpy


PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'


def test_pppoe_units_and_boot_enablement():
    template = (PACKAGING / 'vs-router-pppoe@.service').read_text()
    postboot = (PACKAGING / 'vs-router-pppoe-postboot.service').read_text()
    install = (PACKAGING / 'install.sh').read_text()
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert 'ExecStart=/usr/sbin/pppd call vs-router-%i nodetach' in template
    assert 'ExecStartPre=/usr/sbin/ip link set dev %i up' in template
    assert 'After=vs-router-bootrestore.service network.target' in postboot
    assert 'network-online.target' not in postboot
    caddy = (PACKAGING / 'caddy.service').read_text()
    assert 'After=network.target' in caddy
    assert 'network-online.target' not in caddy
    assert 'After=\nAfter=network.target\nWants=\n' in install
    assert 'kea-network-order.py' in install
    bootrestore = (PACKAGING / 'vs-router-bootrestore.service').read_text()
    assert 'Before=systemd-networkd.service' in bootrestore
    assert 'ExecStartPost=-/usr/bin/python3 /usr/local/libexec/vs-router/reconcile-networkd-boot.py' in bootrestore
    assert ' /etc/ppp ' in bootrestore
    assert '"$packaging_dir/reconcile-networkd-boot.py" /usr/local/libexec/vs-router/reconcile-networkd-boot.py' in install
    assert 'post_boot_pppoe()' in postboot
    assert 'vs-router-pppoe-postboot.service' in install
    assert '"$packaging_dir"/*.service' in install
    assert 'wireguard-tools ppp traceroute' in bootstrap
    assert 'chmod 0600 "$peer"' in install
    assert 'chmod 0600 "$secrets"' in install
    assert ' /etc/ppp ' in (PACKAGING / 'vs-router-agent.service').read_text()


def test_kea_units_do_not_wait_for_isolated_wan(tmp_path):
    source, target = tmp_path / 'vendor', tmp_path / 'override'
    source.mkdir()
    target.mkdir()
    for name in ('kea-ctrl-agent', 'kea-dhcp4-server'):
        (source / f'{name}.service').write_text(
            '[Unit]\nAfter=network-online.target time-sync.target\n'
            'Wants=network-online.target\n[Service]\nExecStart=/usr/sbin/kea-test\n')
    runpy.run_path(str(PACKAGING / 'kea-network-order.py'))['install'](source, target)
    for name in ('kea-ctrl-agent', 'kea-dhcp4-server'):
        content = (target / f'{name}.service').read_text()
        assert 'network-online.target' not in content
        assert 'After=time-sync.target network.target' in content
        assert 'ExecStart=/usr/sbin/kea-test' in content
