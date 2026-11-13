"""Pure systemd-networkd configuration and deterministic bundle encoding."""
from ipaddress import ip_interface
from typing import Iterable
import re

from ..schema import Configuration, ConfigurationVersion
from . import marks

_FILE = re.compile(r"10-vs-router-[a-zA-Z][a-zA-Z0-9_.-]{0,14}\.(?:network|netdev)")


def exit_policy_routes(configuration: Configuration) -> dict[str, list[tuple[str, str, int]]]:
    """Policy routes for exits that name their own gateway.

    Several upstream routers sit on one link, so the main table can only express
    one default per interface; anything else needs a route table selected by the
    packet's source address. Returns ``{interface: [(source, gateway, table)]}``
    in a stable order, with table ids handed out from the marks registry.
    """
    exits = [rule.exit for rule in configuration.routing_rules]
    exits += [member for group in configuration.proxies.groups for member in group.exits]
    wanted = sorted({(exit_value.interface, exit_value.source, exit_value.gateway)
                     for exit_value in exits
                     if exit_value.kind == "interface" and exit_value.interface and exit_value.gateway})
    if len(wanted) > marks.POLICY_TABLE_LIMIT:
        raise ValueError("networkd.policy_table_exhausted")
    routes: dict[str, list[tuple[str, str, int]]] = {}
    for index, (interface, source, gateway) in enumerate(wanted):
        table = marks.POLICY_TABLE_BASE + index
        if not source:
            # A gateway without a source has no selector: the main table already
            # offers one default per interface, so this cannot be expressed.
            raise ValueError("networkd.policy_route_source_required")
        routes.setdefault(interface, []).append((source, gateway, table))
    return routes


def generate_networkd(version: ConfigurationVersion, *, exclude: Iterable[str] = ()) -> dict[str, str]:
    """Return one .network per interface and .netdev files for assigned virtual links.

    ``exclude`` names interfaces this product must not write configuration for —
    on a panel, the uplink whose addressing belongs to the host (ADR-0027). The
    caller decides the set: whether another owner exists is knowledge about the
    host, and this function stays free of I/O.

    Convention: an interface with addressing="dhcp" uses DHCPv4 (any type or
    zone), including its gateway and routes; DHCP DNS is ignored in favor of the
    configured resolver. Unassigned
    interfaces get only a minimal .network with DHCP, RA and link-local disabled,
    ignoring their addresses and L2 attachments (firewall enforces transit deny).
    Bridge members must also have a zone; addresses belong on the bridge.
    VLANs attach through VLAN= in the parent's [Network], including bridge parents;
    [VLAN] Id= is the canonical netdev syntax, with no Parent= or BridgeVLAN needed.
    WAN order is retained: primary keeps its prefix, additional IPv4 addresses use
    /32 (IPv6 uses /128). Static gateways and DNS settings are not generated.
    """
    skip = set(exclude)
    # Tunnel interfaces are owned by the wireguard phase: it creates the link and
    # assigns the addresses from the tunnel manifest. Writing a .network here
    # makes networkd take the link over, and a reconfigure then drops the address
    # the tunnel just configured (observed live: awg0 lost 10.66.66.5/32 on a
    # second apply, so packets left the tunnel with the wrong source).
    skip |= {tunnel.interface for tunnel in version.configuration.tunnels if tunnel.interface}
    interfaces = sorted((i for i in version.configuration.interfaces if i.name not in skip),
                        key=lambda i: i.name)
    policy = exit_policy_routes(version.configuration)
    assigned = {i.name for i in interfaces if i.zone}
    bridges = {}
    for i in interfaces:
        if i.type == "bridge" and i.zone:
            for member in i.members:
                if member in assigned:
                    if member in bridges:
                        raise ValueError("networkd.multiple_bridges")
                    bridges[member] = i.name
    files = {}
    for i in interfaces:
        if i.addressing == "pppoe":
            continue
        prefix = f"10-vs-router-{i.name}"
        # DHCP is explicit (addressing="dhcp") and allowed for any assigned type
        # or zone; the management LAN and Kea server interfaces forbid it, and
        # bridge members / trunk parents are excluded by validation.
        dhcp = i.addressing == "dhcp"
        lines = ["[Match]", f"Name={i.name}", "", "[Network]",
                 f"DHCP={'ipv4' if dhcp else 'no'}", "IPv6AcceptRA=no", "LinkLocalAddressing=no"]
        if not i.zone:
            lines.append("# Unassigned: fail-closed, no addresses or L2 attachments.")
        else:
            if i.type != "physical":
                netdev = ["[NetDev]", f"Name={i.name}", f"Kind={i.type}"]
                if i.type == "vlan":
                    netdev += ["", "[VLAN]", f"Id={i.vlan_id}"]
                files[prefix + ".netdev"] = "\n".join(netdev) + "\n"
            if i.name in bridges:
                lines.append(f"Bridge={bridges[i.name]}")
            else:
                for index, value in enumerate(i.addresses):
                    addr = ip_interface(value)
                    if i.zone == "wan":
                        lines.append("# WAN primary" if index == 0 else "# WAN additional")
                        if index:
                            addr = ip_interface(f"{addr.ip}/{addr.max_prefixlen}")
                    lines.append(f"Address={addr}")
            if i.type == "bridge":
                members = sorted(m for m in i.members if m in assigned)
                if members:
                    lines.append("BindCarrier=" + " ".join(members))
            lines += [f"VLAN={v.name}" for v in interfaces
                      if v.type == "vlan" and v.zone and v.parent == i.name]
            for route in sorted((r for r in version.configuration.static_routes
                                 if r.enabled and r.interface == i.name),
                                key=lambda r: (r.destination, r.gateway or "", r.metric)):
                lines += ["", "[Route]", f"Destination={route.destination}"]
                if route.gateway is not None:
                    lines.append(f"Gateway={route.gateway}")
                if route.metric > 0:
                    lines.append(f"Metric={route.metric}")
            for source, gateway, table in policy.get(i.name, ()):
                # One table per (source, gateway): the selector is the source
                # address, so several upstream routers on the same link stay
                # independent instead of competing for the single main default.
                family = "ipv6" if ":" in source else "ipv4"
                lines += ["", "[RoutingPolicyRule]", f"Family={family}",
                          f"From={source}", f"Table={table}",
                          "", "[Route]",
                          f"Destination={'::/0' if family == 'ipv6' else '0.0.0.0/0'}",
                          f"Gateway={gateway}", f"Table={table}", f"PreferredSource={source}"]
            if dhcp:
                lines += ["", "[DHCPv4]", "UseDNS=no", "UseNTP=no", "UseHostname=no",
                          "UseRoutes=yes", "UseGateway=yes"]
        files[prefix + ".network"] = "\n".join(lines) + "\n"
    return dict(sorted(files.items()))


def serialize_networkd(files: dict[str, str]) -> str:
    """Encode a sorted bundle; the empty configuration is an empty string."""
    for name, content in files.items():
        if not _FILE.fullmatch(name) or any(line.startswith("### FILE:") for line in content.splitlines()):
            raise ValueError("networkd.invalid_bundle")
    return "".join(f"### FILE: {name}\n" + content.rstrip("\n") + "\n"
                   for name, content in sorted(files.items()))


def deserialize_networkd(content: str) -> dict[str, str]:
    """Decode an agent bundle, rejecting duplicate names and path traversal."""
    files = {}
    name = None
    for line in content.splitlines(keepends=True):
        if line.startswith("### FILE: "):
            name = line[len("### FILE: "):].rstrip("\n")
            if not _FILE.fullmatch(name) or name in files:
                raise ValueError("networkd.invalid_bundle")
            files[name] = ""
        elif name is None:
            raise ValueError("networkd.invalid_bundle")
        else:
            files[name] += line
    return files
