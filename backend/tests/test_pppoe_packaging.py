"""Static packaging contract; real pppd negotiation needs the Debian VM."""
from pathlib import Path


PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'


def test_pppoe_units_and_boot_enablement():
    template = (PACKAGING / 'vs-router-pppoe@.service').read_text()
    postboot = (PACKAGING / 'vs-router-pppoe-postboot.service').read_text()
    install = (PACKAGING / 'install.sh').read_text()
    bootstrap = (PACKAGING / 'bootstrap.sh').read_text()
    assert 'ExecStart=/usr/sbin/pppd call vs-router-%i nodetach' in template
    assert 'After=vs-router-bootrestore.service network-online.target' in postboot
    assert 'post_boot_pppoe()' in postboot
    assert 'vs-router-pppoe-postboot.service' in install
    assert '"$packaging_dir"/*.service' in install
    assert 'wireguard-tools ppp traceroute' in bootstrap
    assert 'chmod 0600 "$peer"' in install
    assert 'chmod 0600 "$secrets"' in install
    assert ' /etc/ppp ' in (PACKAGING / 'vs-router-agent.service').read_text()
