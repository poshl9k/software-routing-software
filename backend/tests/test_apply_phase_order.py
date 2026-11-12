"""Reload order: interfaces exist before the services that bind their addresses.

A fresh router's first version creates the LAN/VLAN addresses itself, so a
service restarted before networkd tries to bind an address that does not exist
yet and the whole apply fails with ``agent.reload_failed`` (observed live:
`unbound: can't bind socket: Cannot assign requested address for 10.10.10.1`).
This pins the order that prevents it.
"""
import pytest
from test_agent_apply import FakeExecutor, FakeFS, snapshot
from types import SimpleNamespace

from vs_router.agent import apply as apply_module
from vs_router.agent.apply import ApplyEngine, FILES


@pytest.fixture(autouse=True)
def no_host_profile(monkeypatch):
    """The order must not depend on the host this test runs on.

    ``apply_version`` compares the version profile with ``/etc/vs-router/profile``;
    a machine that is itself an installed router would otherwise fail the test
    with ``configuration.profile_mismatch`` instead of exercising the order.
    """
    monkeypatch.setattr(apply_module, "read_profile", lambda: None)


def recording_engine(order, **kwargs):
    def mark(name):
        return lambda path: order.append(name)
    return ApplyEngine(filesystem=FakeFS(), executor=FakeExecutor(),
                       reload_commands={name: mark(name) for name in FILES}, **kwargs)


def valid_validators():
    return {name: (lambda name, path: SimpleNamespace(returncode=0)) for name in FILES}

def test_networkd_and_wireguard_run_before_the_services_that_bind_them():
    order = []
    result = recording_engine(order).apply_version(snapshot(), validators=valid_validators())
    assert result.status == "confirmed"
    assert order.index("nftables") == 0
    assert order.index("networkd") < order.index("wireguard")
    assert order.index("networkd") < order.index("unbound")
    assert order.index("networkd") < order.index("kea")
    assert order.index("wireguard") < order.index("caddy")
    assert order.index("unbound") < order.index("caddy")


def test_phase_order_is_the_documented_one():
    # A new phase must be placed deliberately: it inherits the order it is
    # inserted at, and a service before networkd is a first-apply failure.
    assert list(FILES) == ["nftables", "networkd", "wireguard", "unbound",
                           "kea", "caddy", "ddns", "ssh"]
