from pathlib import Path

import pytest
from pydantic import ValidationError

from vs_router.generators import generate_networkd, serialize_networkd
from vs_router.schema import ConfigurationVersion, StaticRoute


def version(routes=()):
    return ConfigurationVersion(configuration={
        "interfaces": [
            {"name": "eth0", "zone": "wan", "addresses": ["192.0.2.2/24"]},
            {"name": "eth1", "zone": "lan", "addresses": ["2001:db8::1/64"]},
        ],
        "static_routes": routes,
    })


def test_route_defaults_and_generation():
    route = StaticRoute(destination="198.51.100.0/24", interface="eth0")
    assert route.gateway is None and route.metric == 0 and route.enabled
    files = generate_networkd(version([route.model_dump(), {
        "destination": "2001:db8:1::/64", "interface": "eth1",
        "gateway": "2001:db8::2", "metric": 7,
    }]))
    assert "Address=192.0.2.2/24\n\n[Route]\nDestination=198.51.100.0/24\n" in files["10-vs-router-eth0.network"]
    assert "Gateway=" not in files["10-vs-router-eth0.network"]
    assert "Metric=" not in files["10-vs-router-eth0.network"]
    assert "Address=2001:db8::1/64\n\n[Route]\nDestination=2001:db8:1::/64\nGateway=2001:db8::2\nMetric=7\n" in files["10-vs-router-eth1.network"]


def test_routes_are_sorted_and_disabled_routes_omitted():
    routes = [
        {"destination": "203.0.113.0/24", "interface": "eth0"},
        {"destination": "192.0.2.0/24", "interface": "eth0", "gateway": "192.0.2.1"},
        {"destination": "198.51.100.0/24", "interface": "eth0", "enabled": False},
    ]
    first = generate_networkd(version(routes))["10-vs-router-eth0.network"]
    second = generate_networkd(version(list(reversed(routes))))["10-vs-router-eth0.network"]
    assert first == second
    assert first.index("Destination=192.0.2.0/24") < first.index("Destination=203.0.113.0/24")
    assert "198.51.100.0/24" not in first


@pytest.mark.parametrize("route,code", [
    ({"destination": "bad", "interface": "eth0"}, "route.destination"),
    ({"destination": "192.0.2.1/24", "interface": "eth0"}, "route.destination"),
    ({"destination": "192.0.2.0/24", "interface": "missing"}, "route.interface"),
    ({"destination": "192.0.2.0/24", "interface": "eth0", "gateway": "bad"}, "route.gateway"),
    ({"destination": "192.0.2.0/24", "interface": "eth0", "gateway": "2001:db8::1"}, "route.gateway_family"),
])
def test_invalid_route_rejected(route, code):
    with pytest.raises(ValidationError, match=code):
        version([route])


@pytest.mark.parametrize("route", [
    {"interface": "eth0"},
    {"destination": "192.0.2.0/24"},
    {"destination": "192.0.2.0/24", "interface": "bad name"},
    {"destination": "192.0.2.0/24", "interface": "eth0", "metric": -1},
])
def test_route_shape_rejected(route):
    with pytest.raises(ValidationError):
        version([route])


def test_unassigned_interface_cannot_carry_active_route():
    with pytest.raises(ValidationError, match="route.interface_unassigned"):
        ConfigurationVersion.model_validate({"configuration": {
            "interfaces": [{"name": "eth0"}],
            "static_routes": [{"destination": "192.0.2.0/24", "interface": "eth0"}],
        }})
    disabled = ConfigurationVersion.model_validate({"configuration": {
        "interfaces": [{"name": "eth0"}],
        "static_routes": [{"destination": "192.0.2.0/24", "interface": "eth0", "enabled": False}],
    }})
    assert "[Route]" not in generate_networkd(disabled)["10-vs-router-eth0.network"]


@pytest.mark.parametrize("name", ["empty", "typical", "edge"])
def test_existing_networkd_golden_unchanged(name):
    from test_networkd import scenario

    generated = serialize_networkd(generate_networkd(scenario(name)))
    assert generated == (Path(__file__).parent / "golden" / f"{name}.networkd").read_text()
