"""Host-owned management identity and pure configuration guards.

The record is outside the web-writable configuration tree. Generators receive it
explicitly; reading host state is reserved for privileged entry points.
"""
from ipaddress import IPv4Interface, ip_interface
from pathlib import Path

from pydantic import Field, model_validator
from .schema import Model, InterfaceName

STATE_DIR = Path('/var/lib/vs-router-bootstrap')
STATE_PATH = STATE_DIR / 'management.json'
TLS_DIR = Path('/etc/caddy/management')


class Management(Model):
    interface: InterfaceName
    mac: str = Field(pattern=r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
    address: str

    @model_validator(mode='after')
    def valid_address(self):
        value = IPv4Interface(self.address)
        if (value.ip.is_unspecified or value.ip.is_loopback or value.ip.is_multicast
                or value.ip.is_link_local or value.network.prefixlen > 30
                or value.ip in (value.network.network_address, value.network.broadcast_address)):
            raise ValueError('management.invalid_address')
        return self

    @property
    def ip(self):
        return str(IPv4Interface(self.address).ip)


def read_management(path=STATE_PATH):
    try:
        return Management.model_validate_json(path.read_text())
    except FileNotFoundError:
        return None


def wired_ports(sysnet=Path('/sys/class/net')):
    return {p.name: (p / 'address').read_text().strip().lower()
            for p in sysnet.iterdir()
            if (p / 'device').exists() and not (p / 'wireless').exists()
            and (p / 'type').read_text().strip() == '1'}


def verify_identity(state, sysnet=Path('/sys/class/net')):
    ports = wired_ports(sysnet)
    if len(ports) < 2 or ports.get(state.interface) != state.mac:
        raise ValueError('management.identity_mismatch')


def host_management():
    state = read_management()
    if state is not None:
        verify_identity(state)
    return state


def validate_management(configuration, state):
    """Pinned endpoint: migration is deliberately rejected until transactional TLS exists."""
    iface = next((i for i in configuration.interfaces if i.name == state.interface), None)
    if iface is not None and iface.addressing == "dhcp":
        # The management endpoint is pinned to a static address; a DHCP client
        # would move it and lock the administrator out.
        raise ValueError('management.dhcp_forbidden')
    if (iface is None or iface.type != 'physical' or iface.zone != 'lan'
            or IPv4Interface(state.address) not in [ip_interface(a) for a in iface.addresses]
            or any(state.interface in i.members for i in configuration.interfaces)
            or configuration.panel_port != 443):
        raise ValueError('management.endpoint_required')
    # Linux uses a weak host model: do not allow another interface to own this IP.
    if any(str(ip_interface(a).ip) == state.ip for i in configuration.interfaces
           if i.name != state.interface for a in i.addresses):
        raise ValueError('management.address_conflict')
    for forward in configuration.port_forwards:
        if (forward.enabled and forward.protocol == 'tcp' and forward.external_port == 443
                and forward.wan_address in (None, state.ip)):
            raise ValueError('management.port_reserved')


def validate_site_bindings(version, state):
    sites = version.configuration.sites
    default = next((str(ip_interface(i.addresses[0]).ip)
                    for i in version.configuration.interfaces if i.zone == 'wan' and i.addresses),
                   '')
    for site in sites:
        bound = site.wan_address or default
        if bound in ('0.0.0.0', '::', ''):
            # No concrete bind address. An explicit wildcard would shadow the
            # management endpoint and is a conflict; a dynamic (DHCP) WAN simply
            # has no address to anchor the site listener, which is a distinct,
            # actionable condition rather than a hidden management conflict.
            raise ValueError('management.site_binding_conflict' if site.wan_address
                             else 'caddy.wan_address_unavailable')
        if bound == state.ip:
            raise ValueError('management.site_binding_conflict')
