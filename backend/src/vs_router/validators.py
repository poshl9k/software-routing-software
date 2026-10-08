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
    ingress = c.tproxy.ingress_interfaces
    if len({r.name for r in c.tproxy.rules}) != len(c.tproxy.rules):
        fail("tproxy.duplicate_rule")
    if len(set(ingress)) != len(ingress) or any(
        name not in interfaces or interfaces[name].zone in (None, "wan")
        for name in ingress
    ):
        fail("tproxy.ingress_interface")
    # No sing-box process, packet interception or crash guard is installed yet.
    if c.tproxy.enabled:
        fail("tproxy.not_available")
    # A routing rule may only target an outbound that the generator actually
    # renders: a declared proxy outbound/group tag, and only while the proxies
    # section is enabled (otherwise it is not emitted).
    outbound_tags = ({o.tag for o in c.proxies.outbounds} | {g.tag for g in c.proxies.groups}
                     if c.proxies.enabled else set())
    if any(r.action == "route" and r.outbound not in outbound_tags for r in c.tproxy.rules):
        fail("tproxy.outbound_unavailable")
    # TProxy final action: a named route target must exist in the rendered
    # outbound set; setting it while final is not "route" is meaningless.
    final = c.tproxy.final
    if final == "route":
        if not c.tproxy.final_outbound:
            fail("tproxy.final_outbound_required")
        if c.tproxy.final_outbound not in outbound_tags:
            fail("tproxy.final_outbound_unavailable")
    elif c.tproxy.final_outbound is not None:
        fail("tproxy.final_outbound_unexpected")
    rule_set_names = {s.name for s in c.rule_sets}
    if any(name not in rule_set_names for rule in c.tproxy.rules for name in rule.rule_sets):
        fail("tproxy.ruleset_unavailable")
    zones = {i.zone for i in c.interfaces if i.zone}
    members = {m for i in c.interfaces for m in i.members}
    # A parent link that carries an assigned VLAN is a trunk: it must not also run
    # its own DHCP client (two clients on one port).
    vlan_parents = {i.parent for i in c.interfaces if i.type == "vlan" and i.zone and i.parent}
    for i in c.interfaces:
        if i.zone == "router":
            fail("interface.router_zone_reserved")
        for addr in i.addresses:
            ip_interface(addr)
        if i.type == "vlan" and (i.parent not in interfaces or i.vlan_id is None or i.parent == i.name):
            fail("interface.vlan_parent")
        if any(m not in interfaces or m == i.name for m in i.members):
            fail("interface.bridge_member")
        if i.addressing == "dhcp":
            if i.addresses:
                fail("interface.dhcp_with_addresses")
            if i.zone is None:
                fail("interface.dhcp_unassigned")
            if i.name in members:
                fail("interface.dhcp_on_member")
            if i.name in vlan_parents:
                fail("interface.dhcp_on_trunk")
    selected = set(c.ssh.interfaces)
    confirmed = set(c.ssh.wan_confirmed_interfaces)
    if len(selected) != len(c.ssh.interfaces) or len(confirmed) != len(c.ssh.wan_confirmed_interfaces):
        fail("ssh.duplicate_interface")
    for name in selected:
        if name not in interfaces or not interfaces[name].zone or name in members:
            fail("ssh.interface_binding_required")
    wan = {name for name in selected if interfaces[name].zone == "wan"}
    if confirmed != wan:
        fail("ssh.wan_confirmation_required")
    if c.panel_port == 22:
        fail("ssh.port_reserved")
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
        if interfaces[s.interface].addressing == "dhcp":
            # A Kea server interface must not also be a DHCP client: the router
            # would request the address it serves (lockout / ownership conflict).
            fail("dhcp.client_conflict")
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
        try:
            ip_address(upstream.address)
        except ValueError:
            fail("dns.upstream_invalid")
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
    if len({r.name for r in c.rule_sets}) != len(c.rule_sets):
        fail("ruleset.duplicate_name")
    validate_proxies(c)


IMPLICIT_DIRECT_TAG = "direct"
IMPLICIT_BLOCK_TAG = "block"


def validate_proxies(c):
    """Disabled-by-default sing-box outbound/subscription/group contract.

    Mirrors the plan's stage-1 semantics without any fetch, apply or UI:
    unique tags, https-only subscriptions, no open administrative inbound, and
    no recursive or self-addressed outbound. Secrets stay encrypted/redacted
    (enforced by the schema type, not here)."""
    proxies = c.proxies
    tags = [o.tag for o in proxies.outbounds]
    if len(set(tags)) != len(tags):
        fail("proxy.duplicate_tag")
    group_tags = [g.tag for g in proxies.groups]
    if len(set(group_tags)) != len(group_tags):
        fail("proxy.duplicate_group_tag")
    # The generator always emits its own local ``direct`` outbound and a local ``block`` outbound;
    # a contract object must not shadow those tags or the route target would be ambiguous.
    if IMPLICIT_DIRECT_TAG in tags or IMPLICIT_DIRECT_TAG in group_tags or \
       IMPLICIT_BLOCK_TAG in tags or IMPLICIT_BLOCK_TAG in group_tags:
        fail("proxy.tag_reserved")
    known_tags = set(tags) | set(group_tags)
    if len(known_tags) != len(tags) + len(group_tags):
        fail("proxy.tag_collision")
    if len({s.name for s in proxies.subscriptions}) != len(proxies.subscriptions):
        fail("proxy.duplicate_subscription")
    for s in proxies.subscriptions:
        if not s.url.lower().startswith("https://"):
            fail("proxy.subscription_https_required")
    own_addresses = {str(ip_interface(a).ip) for i in c.interfaces for a in i.addresses}
    for o in proxies.outbounds:
        if o.server:
            host = o.server.strip()
            if host.lower() == "localhost":
                fail("proxy.outbound_self_reference")
            try:
                ip = ip_address(host)
            except ValueError:
                ip = None
            if ip is not None and (ip.is_loopback or ip.is_unspecified or str(ip) in own_addresses):
                fail("proxy.outbound_self_reference")
        if o.admin_listen:
            try:
                listen = ip_address(o.admin_listen)
            except ValueError:
                fail("proxy.admin_inbound_open")
            else:
                if not listen.is_loopback:
                    fail("proxy.admin_inbound_open")
    group_refs = {g.tag: tuple(g.outbounds) for g in proxies.groups}

    def visit(tag, stack):
        if tag in stack:
            fail("proxy.group_recursive")
        for ref in group_refs.get(tag, ()):
            if ref in group_refs:
                visit(ref, stack | {tag})

    for tag, refs in group_refs.items():
        if not refs:
            fail("proxy.group_empty")
        if tag in refs:
            fail("proxy.group_recursive")
        for ref in refs:
            if ref not in known_tags:
                fail("proxy.group_reference")
        visit(tag, set())
