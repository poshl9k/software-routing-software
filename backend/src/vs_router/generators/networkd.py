"""Pure systemd-networkd configuration and deterministic bundle encoding."""
from ipaddress import ip_interface
import re

from ..schema import ConfigurationVersion

_FILE = re.compile(r"10-vs-router-[a-zA-Z][a-zA-Z0-9_.-]{0,14}\.(?:network|netdev)")


def generate_networkd(version: ConfigurationVersion) -> dict[str, str]:
    """Return one .network per interface and .netdev files for assigned virtual links.

    Convention: an addressless physical WAN uses DHCPv4, including its gateway
    and routes; DHCP DNS is ignored in favor of the configured resolver. Unassigned
    interfaces get only a minimal .network with DHCP, RA and link-local disabled,
    ignoring their addresses and L2 attachments (firewall enforces transit deny).
    Bridge members must also have a zone; addresses belong on the bridge.
    VLANs attach through VLAN= in the parent's [Network], including bridge parents;
    [VLAN] Id= is the canonical netdev syntax, with no Parent= or BridgeVLAN needed.
    WAN order is retained: primary keeps its prefix, additional IPv4 addresses use
    /32 (IPv6 uses /128). Static gateways and DNS settings are not generated.
    """
    interfaces = sorted(version.configuration.interfaces, key=lambda i: i.name)
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
        prefix = f"10-vs-router-{i.name}"
        dhcp = i.type == "physical" and i.zone == "wan" and not i.addresses and i.name not in bridges
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
