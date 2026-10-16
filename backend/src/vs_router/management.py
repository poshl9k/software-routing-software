"""Host-owned management identity and pure configuration guards.

The record is outside the web-writable configuration tree. Generators receive it
explicitly; reading host state is reserved for privileged entry points.
"""
from ipaddress import IPv4Interface, ip_interface
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from .schema import Model, InterfaceName

STATE_DIR = Path('/var/lib/vs-router-bootstrap')
STATE_PATH = STATE_DIR / 'management.json'
# Written by the online installer before the agent is first started: a remote
# box has no console, so the fail-closed SSH lifecycle must be off from the very
# beginning — not only once the management record exists (ADR-0017).
ONLINE_MARKER = Path('/etc/vs-router/online-install')
TLS_DIR = Path('/etc/caddy/management')
# A public panel name: at least one label, dot-separated, no leading/trailing dot.
HOSTNAME_PATTERN = r'^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$'


class Management(Model):
    interface: InterfaceName
    mac: str = Field(pattern=r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
    address: str
    # separate-lan: a dedicated physical LAN port, pinned static address, exactly
    # as ADR-0002 requires. single-uplink: a one-NIC box (VPS) where the uplink is
    # also the panel endpoint; identity is still pinned by name + MAC, but there
    # is only one wired port and its address may be a DHCP lease. See ADR-0017.
    mode: Literal["separate-lan", "single-uplink"] = "separate-lan"
    # Optional public publication of the panel (ADR-0017). When `hostname` is set
    # the panel is served with an ACME (HTTP-01) certificate for that name
    # instead of the local CA; `path_prefix` puts the panel and its API behind a
    # secret path so the bare host root exposes nothing.
    hostname: str | None = Field(
        default=None, pattern=HOSTNAME_PATTERN)
    path_prefix: str | None = Field(default=None, pattern=r'^/[A-Za-z0-9_-]{8,64}$')

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


def panel_probe_target(state):
    """The HTTPS URL to probe and the CA file to trust (``None`` = system store).

    A public hostname is served by an ACME certificate, so it must be verified
    against the system trust store; the local CA only signs the IP certificate of
    the ``separate-lan`` mode and would reject the public one. ``/health`` is
    published outside any secret panel path, so it needs no prefix.
    """
    if state.hostname:
        return f'https://{state.hostname}/health', None
    return f'https://{state.ip}/health', TLS_DIR / 'ca.crt'


def with_hostname(state, hostname):
    """A copy of the management record republished under ``hostname`` (pure).

    ``None`` clears the public name and returns the panel to its IP/local-CA
    endpoint. Revalidates the whole record so a malformed name cannot bypass the
    contract via :meth:`model_copy <pydantic.BaseModel.model_copy>`.
    """
    return state.model_validate({**state.model_dump(), 'hostname': hostname})


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
    # separate-lan needs a second wired port beside the uplink; single-uplink has
    # only the one, so it verifies that port's identity alone.
    required = 1 if state.mode == "single-uplink" else 2
    if len(ports) < required or ports.get(state.interface) != state.mac:
        raise ValueError('management.identity_mismatch')


def host_management():
    state = read_management()
    if state is not None:
        verify_identity(state)
    return state


def validate_management(configuration, state):
    """Pinned endpoint: migration is deliberately rejected until transactional TLS exists.

    ``separate-lan`` (ADR-0002): a dedicated physical LAN port with a static
    address. ``single-uplink`` (ADR-0017): the one wired port is both uplink and
    panel endpoint, its address may be a DHCP lease, and its zone is ``wan``.
    """
    single = state.mode == "single-uplink"
    iface = next((i for i in configuration.interfaces if i.name == state.interface), None)
    if iface is not None and iface.addressing == "dhcp" and not single:
        # The management endpoint is pinned to a static address; a DHCP client
        # would move it and lock the administrator out. A one-NIC box whose panel
        # address IS the uplink lease is the explicit exception (ADR-0017).
        raise ValueError('management.dhcp_forbidden')
    zones = ("wan",) if single else ("lan",)
    # A DHCP uplink carries its address from the lease, not the configuration,
    # so only a static (or configured) address is matched against the record.
    address_pinned = (single and iface is not None and iface.addressing == "dhcp")
    if (iface is None or iface.type != 'physical' or iface.zone not in zones
            or (not address_pinned and IPv4Interface(state.address) not in [ip_interface(a) for a in iface.addresses])
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
        # On a one-NIC box the panel lives on the same address as the uplink, so a
        # site bound to it is expected; Caddy separates them by host and by the
        # panel's secret path prefix (ADR-0017). A separate-lan panel shares its
        # address with no site.
        if bound == state.ip and state.mode != "single-uplink":
            raise ValueError('management.site_binding_conflict')
