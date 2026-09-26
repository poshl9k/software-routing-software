"""Deterministic ruleset for a router-owned nftables table; no host I/O."""
from ipaddress import ip_interface
from ..schema import ConfigurationVersion
from ..validators import address, expand_aliases


def generate_nftables(version: ConfigurationVersion) -> str:
    c = version.configuration
    expanded = expand_aliases(c.aliases)
    interfaces = {i.name: i for i in c.interfaces}
    zones = {z: [i.name for i in c.interfaces if i.zone == z]
             for z in sorted({i.zone for i in c.interfaces if i.zone})}

    def names(values):
        return '{ ' + ', '.join(f'"{v}"' for v in values) + ' }'

    def selector(value, direction, family):
        if value == "any":
            return ""
        if value.startswith("zone:"):
            zone = value[5:]
            if zone == "router":
                return ""
            return f'{"iifname" if direction == "saddr" else "oifname"} {names(zones[zone])}'
        if value.startswith("@"):
            if not any(address(v) == family for v in expanded[value[1:]]):
                return None
            return f'{"ip" if family == 4 else "ip6"} {direction} @a_{value[1:]}_{family}'
        if address(value) != family:
            return None
        return f'{"ip" if family == 4 else "ip6"} {direction} {value}'

    def match(src, dst, protocol, family):
        if (protocol == "icmp" and family == 6) or (protocol == "ipv6-icmp" and family == 4):
            return None
        parts = [f'meta nfproto {"ipv4" if family == 4 else "ipv6"}',
                 selector(src, "saddr", family), selector(dst, "daddr", family)]
        if None in parts:
            return None
        if protocol != "any":
            parts.append(f"meta l4proto {protocol}")
        return " ".join(p for p in parts if p)

    def pf_dest(p):
        if p.wan_address:
            return f"ip daddr {p.wan_address}"
        return "fib daddr type local"

    lines = ["destroy table inet vs_router", "table inet vs_router {"]
    for a in c.aliases:
        if a.type != "address":
            continue
        for family in (4, 6):
            values = [v for v in expanded[a.name] if address(v) == family]
            if values:
                lines += [f"    set a_{a.name}_{family} {{", f"        type ipv{family}_addr",
                          "        flags interval", "        auto-merge",
                          "        elements = { " + ", ".join(values) + " }", "    }"]
    assigned = [i.name for i in c.interfaces if i.zone]
    for chain in ("input", "forward"):
        lines += [f"    chain {chain} {{", f"        type filter hook {chain} priority filter; policy drop;"]
        if chain == "input":
            lines.append('        iifname "lo" accept')
        if assigned:
            lines.append(f"        iifname != {names(assigned)} drop")
            if chain == "forward":
                lines.append(f"        oifname != {names(assigned)} drop")
        else:
            lines.append("        drop")
        lines += ["        ct state invalid drop", "        ct state established,related accept"]
        if chain == "input" and c.anti_lockout and "lan" in zones:
            lines.append(f'        iifname {names(zones["lan"])} tcp dport {c.panel_port} counter accept comment "anti_lockout"')
        if chain == "forward":
            for p in c.port_forwards:
                if not p.enabled:
                    continue
                original = f" ct original ip daddr {p.wan_address}" if p.wan_address else ""
                lines.append(f'        iifname "{p.interface}" meta nfproto ipv4 meta l4proto {p.protocol} '
                             f'ct status dnat{original} ct original proto-dst {p.external_port} '
                             f'ip daddr {p.target} {p.protocol} dport {p.target_port} '
                             f'counter accept comment "auto_{p.name}"')
        for r in sorted(c.firewall_rules, key=lambda r: (r.order, r.name)):
            if not r.enabled or (chain == "forward" and r.dst == "zone:router"):
                continue
            if chain == "input" and r.dst.startswith("zone:") and r.dst != "zone:router":
                continue
            for family in (4, 6):
                clause = match(r.src, r.dst, r.protocol, family)
                if clause is None:
                    continue
                if r.destination_ports:
                    if r.destination_ports.startswith("@"):
                        ports = [v.split("/", 1)[1] for v in expanded[r.destination_ports[1:]]
                                 if v.startswith(r.protocol + "/")]
                        if not ports:
                            continue
                        clause += f' {r.protocol} dport {{ ' + ", ".join(ports) + ' }'
                    else:
                        clause += f" {r.protocol} dport {r.destination_ports}"
                action = {"pass": "accept", "block": "drop", "reject": "reject"}[r.action]
                log = ' log prefix "vs-router "' if r.log else ""
                lines.append(f'        iifname {names(zones[r.ingress_zone])} {clause} counter{log} {action} comment "{r.name}"')
        lines.append("    }")
    lines += ["    chain prerouting {", "        type nat hook prerouting priority dstnat; policy accept;"]
    for p in c.port_forwards:
        if p.enabled:
            lines.append(f'        iifname "{p.interface}" meta nfproto ipv4 {pf_dest(p)} '
                         f'{p.protocol} dport {p.external_port} counter dnat ip to {p.target}:{p.target_port}')
    lines += ["    }", "    chain postrouting {", "        type nat hook postrouting priority srcnat; policy accept;"]
    if c.outbound_nat_mode in ("hybrid", "manual"):
        for r in sorted(c.outbound_nat, key=lambda r: (r.order, r.name)):
            clause = match(r.src, r.dst, r.protocol, 4)
            if clause is None:
                continue
            action = "return" if r.do_not_nat else ("masquerade" if r.translation == "primary" else f"snat ip to {r.translation}")
            lines.append(f'        oifname {names(zones[r.egress_zone])} {clause} counter {action} comment "{r.name}"')
    if c.outbound_nat_mode in ("hybrid", "automatic") and "wan" in zones:
        networks = sorted({str(ip_interface(a).network) for i in c.interfaces if i.zone and i.zone != "wan"
                           for a in i.addresses if ip_interface(a).version == 4})
        if networks:
            lines.append(f'        oifname {names(zones["wan"])} ip saddr {{ ' + ", ".join(networks) + " } counter masquerade")
    lines += ["    }", "}"]
    return "\n".join(lines) + "\n"
