"""Deterministic ruleset for a router-owned nftables table; no host I/O."""
from ipaddress import ip_interface
from ..schema import ConfigurationVersion
from ..validators import address, expand_aliases


def names(values):
    return '{ ' + ', '.join(f'"{v}"' for v in values) + ' }'


class _FirewallCompiler:
    """Shared matching, ordering, aliases and logging for both filter paths."""

    def __init__(self, configuration, egress="oifname"):
        self.expanded = expand_aliases(configuration.aliases)
        self.zones = {z: [i.name for i in configuration.interfaces if i.zone == z]
                      for z in sorted({i.zone for i in configuration.interfaces if i.zone})}
        self.egress = egress

    def selector(self, value, direction, family):
        if value == "any":
            return ""
        if value.startswith("zone:"):
            zone = value[5:]
            if zone == "router":
                return ""
            return f'{"iifname" if direction == "saddr" else self.egress} {names(self.zones[zone])}'
        if value.startswith("@"):
            if not any(address(v) == family for v in self.expanded[value[1:]]):
                return None
            return f'{"ip" if family == 4 else "ip6"} {direction} @a_{value[1:]}_{family}'
        if address(value) != family:
            return None
        return f'{"ip" if family == 4 else "ip6"} {direction} {value}'

    def match(self, src, dst, protocol, family):
        if (protocol == "icmp" and family == 6) or (protocol == "ipv6-icmp" and family == 4):
            return None
        parts = [f'meta nfproto {"ipv4" if family == 4 else "ipv6"}',
                 self.selector(src, "saddr", family), self.selector(dst, "daddr", family)]
        if None in parts:
            return None
        if protocol != "any":
            parts.append(f"meta l4proto {protocol}")
        return " ".join(p for p in parts if p)

    def rules(self, rules, chain, families=(4, 6), actions=None):
        if actions is None:
            actions = {"pass": "accept", "block": "drop", "reject": "reject"}
        for r in sorted(rules, key=lambda r: (r.order, r.name)):
            if not r.enabled or (chain == "forward" and r.dst == "zone:router"):
                continue
            if chain == "input" and r.dst.startswith("zone:") and r.dst != "zone:router":
                continue
            for family in families:
                clause = self.match(r.src, r.dst, r.protocol, family)
                if clause is None:
                    continue
                if r.destination_ports:
                    if r.destination_ports.startswith("@"):
                        ports = [v.split("/", 1)[1] for v in self.expanded[r.destination_ports[1:]]
                                 if v.startswith(r.protocol + "/")]
                        if not ports:
                            continue
                        clause += f' {r.protocol} dport {{ ' + ", ".join(ports) + ' }'
                    else:
                        clause += f" {r.protocol} dport {r.destination_ports}"
                action = actions[r.action]
                log = ' log prefix "vs-router "' if r.log else ""
                yield f'        iifname {names(self.zones[r.ingress_zone])} {clause} counter{log} {action} comment "{r.name}"'


def _address_sets(aliases, expanded):
    lines = []
    for a in aliases:
        if a.type != "address":
            continue
        for family in (4, 6):
            values = [v for v in expanded[a.name] if address(v) == family]
            if values:
                lines += [f"    set a_{a.name}_{family} {{", f"        type ipv{family}_addr",
                          "        flags interval", "        auto-merge",
                          "        elements = { " + ", ".join(values) + " }", "    }"]
    return lines


def generate_nftables(version: ConfigurationVersion, management=None) -> str:
    c = version.configuration
    compiler = _FirewallCompiler(c)
    zones = compiler.zones
    match = compiler.match

    def pf_dest(p):
        if p.wan_address:
            return f"ip daddr {p.wan_address}"
        return "fib daddr type local"

    lines = ["destroy table inet vs_router", "table inet vs_router {"]
    lines += _address_sets(c.aliases, compiler.expanded)
    assigned = [i.name for i in c.interfaces if i.zone]
    for chain in ("input", "forward"):
        lines += [f"    chain {chain} {{", f"        type filter hook {chain} priority filter; policy drop;"]
        if chain == "input":
            # SSH is an exhaustive decision, before loopback, conntrack,
            # management exceptions and user rules. Revocation kills old flows.
            if c.ssh.interfaces:
                lines.append(f'        iifname {names(sorted(c.ssh.interfaces))} tcp dport 22 ct state != invalid counter accept comment "ssh_selected"')
            lines.append('        tcp dport 22 counter drop comment "ssh_unselected"')
            lines.append('        iifname "lo" accept')
            if management is not None:
                lines += [f'        iifname "{management.interface}" ip daddr {management.ip} tcp dport 443 counter accept comment "management"',
                          f'        ip daddr {management.ip} tcp dport 443 drop']
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
        lines.extend(compiler.rules(c.firewall_rules, chain))
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


def generate_tproxy_containment(version: ConfigurationVersion) -> str:
    """Offline experiment only: close selected forwarding independently of interception.

    Deliberately blocks all selected transit, not only WAN. No bypass or readiness
    exceptions exist yet. Not included in bundles/apply; this is not authorization
    for intercepted LOCAL_IN traffic or a complete TProxy crash guard.
    """
    table = "inet vs_router_tproxy_guard"
    policy = version.configuration.tproxy
    if not policy.enabled:
        return f"destroy table {table}\n"
    sources = sorted(set(policy.ingress_interfaces))
    allowed = {i.name for i in version.configuration.interfaces if i.zone and i.zone != "wan"}
    if not sources or not set(sources).issubset(allowed):
        raise ValueError("tproxy.containment_invalid_ingress")
    selection = '{ ' + ', '.join(f'"{name}"' for name in sources) + ' }'
    return (f"destroy table {table}\n"
            f"table {table} {{\n"
            "    chain forward {\n"
            "        type filter hook forward priority -10; policy accept;\n"
            f'        iifname {selection} counter drop comment "tproxy_containment"\n'
            "    }\n"
            "}\n")


def generate_tproxy_preauthorization(version: ConfigurationVersion) -> str:
    """OFFLINE experiment, not shipped semantics or interception authorization.

    Only drops unauthorized selected transit. Returns (including firewall pass)
    grant no marker/permission to intercept. Later interception MUST repeat the
    unselected/local/DNAT exemptions and run after this hook and before marking.
    The FIB lookup is post-DNAT, with the incoming mark, before interception mark;
    its correspondence to real routing still requires packet-path verification.
    Do not add .iif: NFTA_FIB_F_IIF restricts the result to the input interface,
    rather than supplying the input interface to a normal forward-route lookup.
    The mark-only lookup does not reproduce iif/protocol/port-dependent policy
    routing or all ECMP semantics. Such hosts remain outside this experiment.

    Re-evaluates every packet, unlike ordinary established/related acceptance.
    Only IPv4 TCP/UDP transit is supported. Reject conservatively drops because
    nft reject is not supported at PREROUTING. Unknown routes cannot enter the
    rule chain. This does not authorize proxy OUTPUT or solve crash/apply/boot
    lifecycle, policy-route interference, bridge/offload or failure containment.
    Deliberately absent from bundles, API, apply and boot restoration.
    """
    table = "inet vs_router_tproxy_preauth"
    c = version.configuration
    if not c.tproxy.enabled:
        return f"destroy table {table}\n"
    sources = c.tproxy.ingress_interfaces
    allowed = {i.name for i in c.interfaces if i.zone and i.zone != "wan"}
    if not sources or len(set(sources)) != len(sources) or not set(sources) <= allowed:
        raise ValueError("tproxy.preauth_invalid_ingress")
    # model_copy is intentionally used by offline fixtures to bypass the public
    # enabled gate. Revalidate everything else so ambiguous/unknown semantics
    # cannot become a permissive rule through unvalidated copies.
    data = version.model_dump()
    data["configuration"]["tproxy"]["enabled"] = False
    ConfigurationVersion.model_validate(data)
    egress = "fib daddr . mark oifname"
    compiler = _FirewallCompiler(c, egress=egress)
    assigned = [i.name for i in c.interfaces if i.zone]
    lines = [f"destroy table {table}", f"table {table} {{"]
    lines += _address_sets(c.aliases, compiler.expanded)
    lines += ["    chain prerouting {",
              "        type filter hook prerouting priority -90; policy accept;",
              f"        iifname != {names(sorted(sources))} return",
              "        fib daddr type local return",
              "        ct status dnat return",
              "        meta nfproto != ipv4 drop",
              "        meta l4proto != { tcp, udp } drop",
              "        ct state invalid drop",
              f"        {egress} {names(assigned)} goto transit",
              "        counter drop", "    }", "    chain transit {"]
    # Positive assigned-egress gate also handles no-route lookups: a failed FIB
    # expression must never skip a negative guard and fall into a broad pass.
    lines.extend(compiler.rules(c.firewall_rules, "forward", families=(4,),
                                actions={"pass": "return", "block": "drop", "reject": "drop"}))
    lines += ["        counter drop", "    }", "}"]
    return "\n".join(lines) + "\n"
