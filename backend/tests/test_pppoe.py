"""PPPoE contract and exact generated pppd files."""

import pytest
from cryptography.fernet import Fernet

from vs_router.generators import generate_networkd, generate_pppoe
from vs_router.schema import ConfigurationVersion
from vs_router.secrets import encrypt_secret


KEY = Fernet.generate_key()


def iface(**changes):
    value = {"name": "eth0", "zone": "wan", "addressing": "pppoe",
             "pppoe_username": "alice", "pppoe_password": encrypt_secret("s3cret", KEY)}
    value.update(changes)
    return value


def version(interfaces, **extra):
    return ConfigurationVersion(configuration={"interfaces": interfaces, **extra})


def test_exact_output_and_legacy_networkd():
    original = version([{"name": "eth1", "zone": "lan", "addresses": ["192.0.2.1/24"]}])
    current = version([iface(), {"name": "eth1", "zone": "lan", "addresses": ["192.0.2.1/24"]}])
    assert generate_networkd(current) == generate_networkd(original)
    assert generate_pppoe(current, KEY) == {
        "/etc/ppp/peers/vs-router-eth0":
        'plugin rp-pppoe.so\nnic-eth0\nuser "alice"\nnoauth\nnoipdefault\ndefaultroute\nusepeerdns\npersist\n',
        "/etc/ppp/chap-secrets": '"alice" * "s3cret" *\n',
        "/etc/ppp/pap-secrets": '"alice" * "s3cret" *\n',
    }
    assert "pppoe_username" not in original.configuration.interfaces[0].model_dump()
    assert "pppoe_password" not in original.configuration.model_dump(mode="json")["interfaces"][0]
    assert generate_pppoe(original, KEY) == {}


@pytest.mark.parametrize("changes,code", [
    ({"zone": "lan"}, "interface.pppoe_physical_wan_required"),
    ({"type": "bridge"}, "interface.pppoe_physical_wan_required"),
    ({"pppoe_username": " "}, "interface.pppoe_credentials_required"),
    ({"pppoe_password": None}, "interface.pppoe_credentials_required"),
    ({"addresses": ["192.0.2.1/24"]}, "interface.pppoe_with_addresses"),
    ({"members": ["eth1"]}, "interface.pppoe_on_bridge"),
])
def test_structural_guards(changes, code):
    with pytest.raises(ValueError, match=code):
        version([iface(**changes), {"name": "eth1", "zone": "lan"}])


def test_membership_trunk_and_kea_guards():
    with pytest.raises(ValueError, match="interface.pppoe_on_bridge"):
        version([iface(), {"name": "br0", "type": "bridge", "zone": "lan", "members": ["eth0"]}])
    with pytest.raises(ValueError, match="interface.pppoe_on_trunk"):
        version([iface(), {"name": "eth0.2", "type": "vlan", "zone": "lan", "parent": "eth0", "vlan_id": 2}])
    with pytest.raises(ValueError, match="interface.pppoe_kea_conflict"):
        version([iface()], dhcp_subnets=[{"id": 1, "interface": "eth0", "subnet": "192.0.2.0/24"}])


def test_credentials_on_other_mode_rejected():
    with pytest.raises(ValueError, match="interface.pppoe_credentials_unexpected"):
        version([iface(addressing="dhcp")])


def test_duplicate_username_and_password_file_reference_rejected():
    with pytest.raises(ValueError, match="interface.pppoe_duplicate_username"):
        version([iface(), iface(name="eth1")])
    unsafe = version([iface(pppoe_password=encrypt_secret("@/etc/shadow", KEY))])
    with pytest.raises(ValueError, match="pppoe.invalid_credential"):
        generate_pppoe(unsafe, KEY)


def test_escaping_and_safe_failure():
    special = version([iface(pppoe_username='a"b\\c',
                             pppoe_password=encrypt_secret('p"\\# q', KEY))])
    output = generate_pppoe(special, KEY)
    assert 'user "a\\"b\\\\c"\n' in output["/etc/ppp/peers/vs-router-eth0"]
    assert '"a\\"b\\\\c" * "p\\"\\\\# q" *\n' == output["/etc/ppp/chap-secrets"]
    with pytest.raises(ValueError, match="pppoe.secret_decryption_failed") as error:
        generate_pppoe(special, Fernet.generate_key())
    assert 'p"\\# q' not in str(error.value)
    newline = version([iface(pppoe_username="a\nb")])
    with pytest.raises(ValueError, match="pppoe.invalid_credential"):
        generate_pppoe(newline, KEY)
