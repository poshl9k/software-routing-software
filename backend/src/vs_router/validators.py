"""Domain validation; errors are stable codes suitable for UI localization."""
from ipaddress import ip_address, ip_interface, ip_network
import re
import warnings


def fail(code):
    raise ValueError(code)


def port_range(value):
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", value):
        fail("port.invalid")
    parts = value.split("-")
    start, end = int(parts[0]), int(parts[-1])
    if not 1 <= start <= end <= 65535:
        fail("port.invalid")
    return start, end


def address(value):
    if "-" in value:
        a, b = map(ip_address, value.split("-"))
        if a.version != b.version or int(a) > int(b):
            fail("address.invalid_range")
        return a.version
    return ip_network(value).version


def expand_aliases(aliases):
    by_name = {a.name: a for a in aliases}
    if len(by_name) != len(aliases):
        fail("alias.duplicate")
    expanded, visiting = {}, set()

    def visit(name):
        if name in visiting:
            fail("alias.cycle")
        if name in expanded:
            return expanded[name]
        if name not in by_name:
            fail("alias.missing")
        visiting.add(name)
        alias = by_name[name]
        values = list(alias.elements)
        for value in values:
            if alias.type == "address":
                address(value)
            else:
                protocol, sep, ports = value.partition("/")
                if not sep or protocol not in ("tcp", "udp"):
                    fail("alias.port_protocol")
                port_range(ports)
        for child in alias.includes:
            if child not in by_name:
                fail("alias.missing")
            if by_name[child].type != alias.type:
                fail("alias.incompatible_type")
            values.extend(visit(child))
            if len(values) > 100000:
                fail("alias.too_large")
        if len(values) > 100000:
            fail("alias.too_large")
        if len(values) > 10000:
            warnings.warn("alias.large", UserWarning, stacklevel=2)
        visiting.remove(name)
        expanded[name] = tuple(dict.fromkeys(values))
        return expanded[name]

    for name in by_name:
        visit(name)
    return expanded


def validate_configuration(c):
    expand_aliases(c.aliases)
    aliases = {a.name: a for a in c.aliases}
    interfaces = {i.name: i for i in c.interfaces}
    if len(interfaces) != len(c.interfaces):
        fail("interface.duplicate")
    zones = {i.zone for i in c.interfaces if i.zone}
    for i in c.interfaces:
        if i.zone == "router":
            fail("interface.router_zone_reserved")
        for addr in i.addresses:
            ip_interface(addr)
        if i.type == "vlan" and (i.parent not in interfaces or i.vlan_id is None or i.parent == i.name):
            fail("interface.vlan_parent")
        if any(m not in interfaces or m == i.name for m in i.members):
            fail("interface.bridge_member")
    def selector(value, kind="address"):
        if value.startswith("@"):
            if value[1:] not in aliases or aliases[value[1:]].type != kind:
                fail("rule.alias_type_or_reference")
        elif kind == "port":
            port_range(value)
        elif value.startswith("zone:"):
            if value[5:] not in zones | {"router"}:
                fail("rule.zone_reference")
        elif value != "any":
            address(value)
    for r in c.firewall_rules:
        if r.ingress_zone not in zones:
            fail("rule.ingress_zone")
        selector(r.src)
        selector(r.dst)
        if r.src == "zone:router":
            fail("rule.router_source")
        if r.destination_ports:
            selector(r.destination_ports, "port")
            if r.protocol not in ("tcp", "udp"):
                fail("rule.port_protocol")
    for group in (c.firewall_rules, c.port_forwards, c.outbound_nat, c.tunnels, c.sites):
        if len({x.name for x in group}) != len(group):
            fail("object.duplicate_name")
    for r in c.port_forwards:
        if r.interface not in interfaces or interfaces[r.interface].zone is None:
            fail("nat.interface")
        if ip_address(r.target).version != 4:
            fail("nat.ipv4_required")
        if r.wan_address and r.wan_address not in [str(ip_interface(a).ip) for a in interfaces[r.interface].addresses]:
            fail("nat.wan_address")
    for r in c.outbound_nat:
        if r.egress_zone not in zones:
            fail("nat.egress_zone")
        selector(r.src)
        selector(r.dst)
        if r.src.startswith("zone:") or r.dst.startswith("zone:"):
            fail("nat.address_selector_required")
        if r.translation != "primary" and ip_address(r.translation).version != 4:
            fail("nat.ipv4_required")
    subnet_ids = set()
    networks = []
    for s in c.dhcp_subnets:
        if s.id in subnet_ids or s.interface not in interfaces:
            fail("dhcp.id_or_interface")
        subnet_ids.add(s.id)
        network = ip_network(s.subnet)
        if network.version != 4:
            fail("dhcp.ipv4_required")
        if any(network.overlaps(other) for other in networks):
            fail("dhcp.subnet_overlap")
        networks.append(network)
        own = {ip_interface(a).ip for a in interfaces[s.interface].addresses}
        def usable(value):
            ip = ip_address(value)
            if ip not in network or ip in (network.network_address, network.broadcast_address) or ip in own:
                fail("dhcp.unusable_address")
            return int(ip)
        pools = []
        for p in s.pools:
            start, end = usable(p.start), usable(p.end)
            if start > end or any(start <= b and a <= end for a, b in pools):
                fail("dhcp.pool_overlap_or_range")
            if any(start <= int(a) <= end for a in own if a.version == 4):
                fail("dhcp.pool_interface_address")
            pools.append((start, end))
        ips, macs = set(), set()
        for r in s.reservations:
            ip, mac = usable(r.ip_address), r.hw_address.lower()
            if ip in ips or mac in macs:
                fail("dhcp.duplicate_reservation")
            ips.add(ip)
            macs.add(mac)
        for ip in (*s.routers, *s.dns_servers):
            if ip_address(ip).version != 4:
                fail("dhcp.ipv4_required")
    for name in c.dns.interfaces:
        if name not in interfaces or not interfaces[name].addresses:
            fail("dns.interface_address_required")
    for network in c.dns.access_control:
        ip_network(network)
    if len({f.domain for f in c.dns.forwards}) != len(c.dns.forwards):
        fail("dns.duplicate_forward")
    if c.dns.upstreams and any(f.domain == "." for f in c.dns.forwards):
        fail("dns.duplicate_root_forward")
    for upstream in (*c.dns.upstreams, *(u for f in c.dns.forwards for u in f.upstreams)):
        ip_address(upstream)
    for r in c.dns.records:
        if any(ord(ch) < 32 for ch in r.value):
            fail("dns.invalid_record")
        if r.type in ("A", "AAAA") and ip_address(r.value).version != (4 if r.type == "A" else 6):
            fail("dns.record_family")
    for t in c.tunnels:
        if t.interface not in interfaces:
            fail("tunnel.interface")
        for value in (*t.allowed_ips, *(a for p in t.peers for a in p.allowed_ips)):
            ip_network(value)
    wan_addresses = {str(ip_interface(a).ip) for i in c.interfaces if i.zone == "wan" for a in i.addresses}
    for s in c.sites:
        if s.wan_address and s.wan_address not in wan_addresses:
            fail("caddy.wan_address")
