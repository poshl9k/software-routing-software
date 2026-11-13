"""Tunnel links belong to the wireguard phase, not to systemd-networkd.

networkd takes over any link it has a .network for; on a reconfigure it then
drops the address the wireguard phase assigned. Live symptom: awg0 lost
10.66.66.5/32 on the second apply and tunnel traffic left with the management
address as its source, so the remote peer rejected it.
"""
from vs_router.generators.networkd import generate_networkd
from vs_router.schema import ConfigurationVersion

SECRET = {"encrypted": True, "ciphertext": "gAAAAplaceholder"}
AWG = {"Jc": 4, "Jmin": 10, "Jmax": 50, "S1": 20, "S2": 20, "S3": 20, "S4": 20,
       "H1": 1, "H2": 2, "H3": 3, "H4": 4}


def version():
    return ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [
            {"name": "awg0", "addresses": ["10.66.66.5/32"]},
            {"name": "lan0", "zone": "lan", "addresses": ["10.0.0.1/24"]},
        ],
        "tunnels": [{"name": "vpn", "interface": "awg0", "role": "client",
                     "protocol": "awg", "private_key": SECRET,
                     "endpoint": "vpn.example:51820",
                     "server_public_key": "S" * 44,
                     "allowed_ips": ["0.0.0.0/0"],
                     "obfuscation": AWG}],
    }})


def test_tunnel_interface_gets_no_networkd_file():
    files = generate_networkd(version())
    assert not [name for name in files if "awg0" in name]
    assert [name for name in files if "lan0" in name]


def test_tunnel_interface_can_still_be_an_explicit_exclusion():
    # The panel's management-link exclusion keeps working alongside the tunnel rule.
    files = generate_networkd(version(), exclude=["lan0"])
    assert not [name for name in files if "lan0" in name]


def test_tunnel_link_survives_the_fail_closed_firewall():
    from vs_router.generators.nftables import generate_nftables

    lines = generate_nftables(version()).splitlines()
    guard = [line for line in lines if "iifname !=" in line or "oifname !=" in line]
    assert guard, "the fail-closed interface sets disappeared"
    assert all('"awg0"' in line for line in guard), guard
