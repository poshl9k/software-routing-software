import pytest
from pydantic import ValidationError
from vs_router.schema import Configuration, ConfigurationVersion
from vs_router.validators import port_range
from scenarios import scenario


@pytest.mark.parametrize("ports", ["0", "65536", "80-1", "-1", "tcp/80", "1-2-3", "80; accept"])
def test_invalid_ports(ports):
    with pytest.raises(ValueError, match="port.invalid"):
        port_range(ports)


@pytest.mark.parametrize("elements", [["tcp/0"], ["udp/65536"], ["80"], ["icmp/80"]])
def test_invalid_port_alias(elements):
    with pytest.raises(ValidationError):
        Configuration(aliases=[{"name": "ports", "type": "port", "elements": elements}])


def test_cycles():
    with pytest.raises(ValidationError, match="alias.cycle"):
        Configuration(aliases=[{"name": "a", "type": "address", "includes": ["b"]},
                               {"name": "b", "type": "address", "includes": ["a"]}])


def test_incompatible_aliases():
    with pytest.raises(ValidationError, match="alias.incompatible_type"):
        Configuration(aliases=[{"name": "a", "type": "address", "includes": ["b"]},
                               {"name": "b", "type": "port"}])


@pytest.mark.parametrize("change", [
    {"pools": [{"start": "192.168.10.100", "end": "192.168.10.150"}, {"start": "192.168.10.150", "end": "192.168.10.200"}]},
    {"pools": [{"start": "192.168.10.200", "end": "192.168.10.100"}]},
    {"pools": [{"start": "192.168.10.1", "end": "192.168.10.100"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.10"}, {"hw_address": "AA:BB:CC:DD:EE:01", "ip_address": "192.168.10.11"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.10"}, {"hw_address": "aa:bb:cc:dd:ee:02", "ip_address": "192.168.10.10"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.11.10"}]},
    {"reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.255"}]},
])
def test_invalid_dhcp(change):
    data = scenario("typical").model_dump()
    data["configuration"]["dhcp_subnets"][0].update(change)
    with pytest.raises(ValidationError):
        ConfigurationVersion.model_validate(data)


def test_alias_overlap_allowed():
    Configuration(aliases=[{"name": "overlap", "type": "address", "elements": ["10.0.0.0/24", "10.0.0.1"]}])


def test_router_not_assignable():
    with pytest.raises(ValidationError, match="router_zone_reserved"):
        Configuration(interfaces=[{"name": "eth0", "zone": "router"}])


def test_config_injection_rejected():
    with pytest.raises(ValidationError):
        Configuration(interfaces=[{"name": 'eth0" accept'}])
