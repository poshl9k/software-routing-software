"""Deterministic ruleset for a router-owned nftables table; no host I/O."""
from ipaddress import ip_address, ip_interface
from ..schema import ConfigurationVersion
from ..validators import address, expand_aliases
from . import marks
from .unbound import tproxy_unbound_listener_addresses


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

    def rules(self, rules, chain, families=(4, 6), actions=None, stamps=None):
        if actions is None:
            actions = {"pass": "accept", "block": "drop", "reject": "reject"}
        stamps = stamps or {}
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
                # ``stamp`` is a statement inserted after this rule's own match
                # (including any ``fib`` clause) and before the counter/verdict,
                # so a match-time FIB lookup never sees ink the rule itself writes.
                stamp = stamps.get(r.action, "")
                log = ' log prefix "vs-router "' if r.log else ""
                yield f'        iifname {names(self.zones[r.ingress_zone])} {clause} {stamp}counter{log} {action} comment "{r.name}"'


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
            # DHCP replies arrive before conntrack can classify a broadcast
            # exchange, so this rule must precede the invalid/established checks.
            # Applies to every interface that is a DHCP client, any zone/type.
            dhcp_clients = sorted(i.name for i in c.interfaces
                                  if i.zone and i.addressing == "dhcp")
            if dhcp_clients:
                lines.append(f'        iifname {names(dhcp_clients)} udp sport 67 udp dport 68 counter accept comment "dhcp_client"')
        if assigned:
            lines.append(f"        iifname != {names(assigned)} drop")
            if chain == "forward":
                lines.append(f"        oifname != {names(assigned)} drop")
        else:
            lines.append("        drop")
        lines += ["        ct state invalid drop", "        ct state established,related accept"]
        if chain == "input" and c.anti_lockout and "lan" in zones:
            lines.append(f'        iifname {names(zones["lan"])} tcp dport {c.panel_port} counter accept comment "anti_lockout"')
        if chain == "input" and "wan" in zones:
            # A server tunnel needs its listen port reachable from the WAN;
            # generated from the tunnel (toggle `open_port`), not hand-written.
            for tunnel in c.tunnels:
                if tunnel.role == "server" and tunnel.open_port and tunnel.listen_port:
                    lines.append(f'        iifname {names(zones["wan"])} udp dport {tunnel.listen_port} '
                                 f'counter accept comment "tunnel_{tunnel.name}"')
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


def generate_tproxy_ipv6_guard(version: ConfigurationVersion) -> str:
    """Gate the selected sources' IPv6 transit out of the router.

    The first TProxy delivery routes IPv4 only; there is no equivalent IPv6
    interception, so any selected-source IPv6 that is *routed* by this router
    would leave through the WAN outside the proxy (plan semantic §5). This
    offline, gated guard closes that escape fail-closed: on the FORWARD path it
    drops every IPv6 packet arriving on a selected ingress whose destination is
    not local to this router.

    Narrowness / what is deliberately preserved:

    * unselected ingress returns untouched -- only the configured
      ``tproxy.ingress_interfaces`` are gated;
    * ``fib daddr type local return`` keeps every destination the router owns
      (management/panel addresses, loopback, the router's own interface
      addresses) reachable -- these terminate locally anyway, but the explicit
      exemption documents that the panel is never blocked;
    * link-local (``fe80::/10``) and multicast (``ff00::/8``) destinations are
      preserved: they are link/scope-local and never a WAN escape;
    * IPv4 and non-IP are untouched (``meta nfproto != ipv6 return``), so the
      IPv4 TProxy tract is unaffected;
    * the source interface is matched, not its address, so a selected host
      cannot evade the guard by changing its IPv6 address.

    The independent FORWARD drop re-evaluates every packet: there is no
    per-flow ``established`` shortcut, so an already-open selected IPv6 flow is
    cut the moment the guard loads. Off returns ``destroy table`` for exactly
    its own table, removing nothing else. As with the other offline TProxy
    generators, an enabled snapshot is only reachable through an offline
    ``model_copy`` (the public ``tproxy.not_available`` gate stays closed), so
    the ingress is revalidated here rather than trusted.

    This is a fail-closed boundary for the specific routed-IPv6 escape on the
    ordinary FORWARD path. It does **not** cover bridge/flow-offload fast paths
    or iif/L4-dependent policy-routing/ECMP lookups that can bypass the regular
    forwarding decision; those remain outside this experiment.
    """
    table = "inet vs_router_tproxy_ipv6_guard"
    c = version.configuration
    if not c.tproxy.enabled:
        return f"destroy table {table}\n"
    sources = c.tproxy.ingress_interfaces
    allowed = {i.name for i in c.interfaces if i.zone and i.zone != "wan"}
    if not sources or len(set(sources)) != len(sources) or not set(sources) <= allowed:
        raise ValueError("tproxy.ipv6_guard_invalid_ingress")
    # Offline fixtures bypass only the public enabled gate; never render rules
    # from an otherwise invalid model_copy snapshot.
    data = version.model_dump()
    data["configuration"]["tproxy"]["enabled"] = False
    ConfigurationVersion.model_validate(data)
    return (f"destroy table {table}\n"
            f"table {table} {{\n"
            "    chain forward {\n"
            "        type filter hook forward priority -11; policy accept;\n"
            f"        iifname != {names(sorted(sources))} return\n"
            "        meta nfproto != ipv6 return\n"
            "        fib daddr type local return\n"
            "        ip6 daddr { fe80::/10, ff00::/8 } return\n"
            '        counter drop comment "tproxy_ipv6_guard"\n'
            "    }\n"
            "}\n")


def generate_tproxy_dns_ingress_guard(version: ConfigurationVersion) -> str:
    """OFFLINE experiment: drop selected clients' direct IPv4 DNS before routing.

    Local router DNS remains reachable. This does not classify queries entering
    Unbound or constrain its OUTPUT, and must not enter bundle/apply/boot until
    those paths, DNAT exceptions and crash/established-flow behavior are proven.
    """
    table = "inet vs_router_tproxy_dns_ingress"
    c = version.configuration
    if not c.tproxy.enabled:
        return f"destroy table {table}\n"
    sources = c.tproxy.ingress_interfaces
    allowed = {i.name for i in c.interfaces if i.zone and i.zone != "wan"}
    if not sources or len(set(sources)) != len(sources) or not set(sources) <= allowed:
        raise ValueError("tproxy.dns_invalid_ingress")
    # Offline fixtures bypass only the public enabled gate. Never render rules
    # from an otherwise invalid model_copy snapshot.
    data = version.model_dump()
    data["configuration"]["tproxy"]["enabled"] = False
    ConfigurationVersion.model_validate(data)
    return (f"destroy table {table}\n"
            f"table {table} {{\n"
            "    chain prerouting {\n"
            "        type filter hook prerouting priority -110; policy accept;\n"
            f"        iifname != {names(sorted(sources))} return\n"
            "        meta nfproto != ipv4 return\n"
            "        meta l4proto != { tcp, udp } return\n"
            "        fib daddr type local return\n"
            '        th dport 53 counter drop comment "tproxy_dns_direct"\n'
            "    }\n"
            "}\n")


def generate_tproxy_dns_listener_guard(version: ConfigurationVersion) -> str:
    """OFFLINE-only INPUT boundary for a future two-process Unbound split.

    DNS access to selected listener addresses is limited by actual ingress, not
    just destination IP. No service is started and live nft/apply remain unchanged.
    """
    table = "inet vs_router_tproxy_dns_listener"
    if not version.configuration.tproxy.enabled:
        return f"destroy table {table}\n"
    listeners = tproxy_unbound_listener_addresses(version)
    sources = names(sorted(version.configuration.tproxy.ingress_interfaces))
    selected = '{ ' + ', '.join(listeners["selected"]) + ' }'
    return (f"destroy table {table}\n"
            f"table {table} {{\n"
            "    chain input {\n"
            "        type filter hook input priority -10; policy accept;\n"
            "        meta nfproto != ipv4 return\n"
            "        meta l4proto != { tcp, udp } return\n"
            '        iifname != "lo" ip daddr 127.0.0.1 th dport 15353 counter drop comment "tproxy_dns_stub_external"\n'
            "        th dport != 53 return\n"
            f'        iifname {sources} ip daddr != {selected} counter drop comment "tproxy_dns_selected_wrong_listener"\n'
            f'        iifname != {sources} ip daddr {selected} counter drop comment "tproxy_dns_unselected_wrong_listener"\n'
            "    }\n"
            "}\n")


def generate_tproxy_dns_output_guard(version: ConfigurationVersion, selected_uid: int) -> str:
    """OFFLINE-only selected-resolver socket boundary, not client attribution.

    The selected resolver may reach the local stub or configured explicit
    forward destinations. Its unmatched upstream must never use the ordinary
    resolver's global WAN upstream. No service/UID lifecycle is implemented.
    """
    table = "inet vs_router_tproxy_dns_output"
    if not version.configuration.tproxy.enabled:
        return f"destroy table {table}\n"
    tproxy_unbound_listener_addresses(version)
    if type(selected_uid) is not int or not 100 <= selected_uid <= 65535:
        raise ValueError("tproxy.dns_output_invalid_uid")
    upstreams = sorted({u.address for f in version.configuration.dns.forwards for u in f.upstreams})
    if any(ip_address(u).version != 4 for u in upstreams):
        raise ValueError("tproxy.dns_output_ipv4_required")
    lines = [f"destroy table {table}", f"table {table} {{",
             "    chain output {", "        type filter hook output priority -20; policy accept;"]
    interfaces = {i.name: i for i in version.configuration.interfaces}
    for name in sorted(version.configuration.tproxy.ingress_interfaces):
        for value in sorted(interfaces[name].addresses):
            listener_ip = ip_interface(value).ip
            lines.append(f'        meta skuid {selected_uid} oifname "{name}" '
                         f'ip saddr {listener_ip} meta l4proto {{ tcp, udp }} th sport 53 '
                         'counter return comment "tproxy_dns_client_reply"')
    lines.append(f'        meta skuid {selected_uid} ip daddr 127.0.0.1 '
                 'meta l4proto { tcp, udp } th dport 15353 counter return comment "tproxy_dns_stub"')
    if upstreams:
        destinations = '{ ' + ', '.join(upstreams) + ' }'
        lines.append(f'        meta skuid {selected_uid} ip daddr {destinations} '
                     'meta l4proto { tcp, udp } th dport 53 counter return comment "tproxy_dns_explicit_forward"')
    lines += [f'        meta skuid {selected_uid} counter drop comment "tproxy_dns_output_denied"',
              "    }", "}"]
    return "\n".join(lines) + "\n"


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
    rule chain. On every authorized (``pass``) transit rule it also stamps the
    reserved preauth capture gate mark (:data:`marks.MARK_TPROXY_AUTH_VALUE`,
    lab-31) that ``generate_tproxy_interception`` requires before capture; the
    stamp is emitted inside the matched rule after its own ``fib`` clause, so the
    match-time FIB lookup never sees ink the rule itself writes. This couples
    capture to a live preauth table (losing it fails closed). This does not
    authorize proxy OUTPUT or solve crash/apply/boot lifecycle, policy-route
    interference, bridge/offload or failure containment. Deliberately absent from
    bundles, API, apply and boot restoration.
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
    # Capture gate (lab-31): authorized selected transit is stamped with the
    # reserved packet mark so interception capture requires evidence that a live
    # preauth evaluated and passed this flow. The stamp is emitted inside the
    # matched rule, after its own ``fib`` clause, so the FIB lookup never sees it.
    # If this table is lost the mark is absent, capture does not fire and the
    # flow falls through to the independent containment/default-deny.
    auth = marks.MARK_TPROXY_AUTH_VALUE
    marks.assert_no_collisions(auth, marks.Owner.TPROXY)
    stamp = f"meta mark set meta mark | {auth:#x} "
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
                                actions={"pass": "return", "block": "drop", "reject": "drop"},
                                stamps={"pass": stamp}))
    lines += ["        counter drop", "    }", "}"]
    return "\n".join(lines) + "\n"


def generate_tproxy_interception(version: ConfigurationVersion) -> str:
    """Deterministic TProxy capture + conntrack-mark INPUT authorization.

    Offline, no host I/O. Emits three tables sharing one ownership contract
    (:mod:`generators.marks`): a PREROUTING reset (``-85``), the PREROUTING
    capture (``-80``) and an INPUT guard (``-20``). nft evaluates lower hook
    priorities first, so a packet sees preauth (``-90``) → reset (``-85``) →
    capture (``-80``); the guard then runs at INPUT (``-20``). Preauth therefore
    strictly precedes capture and every packet re-enters it — there is no
    per-flow ``established`` shortcut.

    The reset clears the reserved conntrack-proof bit
    (:data:`marks.MARK_TPROXY_CT_PROOF_VALUE`) on every selected packet *before*
    capture can re-set it. Capture keeps the proven exemptions (non-selected
    ingress, non-IPv4/non-TCP/UDP, local FIB destinations, post-DNAT
    ``ct status dnat``), then requires the reserved preauth gate mark
    (:data:`marks.MARK_TPROXY_AUTH_VALUE`): a selected packet without it returns
    and stays on the ordinary FORWARD path, so losing the preauth table disables
    capture and fails closed at the independent containment/default-deny instead
    of diverting a policy-unchecked flow into LOCAL_IN. For matched selected IPv4
    TCP/UDP it sets the routing packet mark
    (:data:`marks.MARK_TPROXY_ROUTE_VALUE`, drives the policy route)
    **and** the conntrack-proof bit after the successful ``tproxy`` expression,
    then ``tproxy``-redirects to the loopback sing-box listeners
    (:data:`marks.TPROXY_TCP_PORT` / :data:`marks.TPROXY_UDP_PORT`).

    The independent INPUT guard authorizes on the **conntrack** mark, never the
    forgeable packet mark: a selected IPv4 TCP/UDP packet that reaches LOCAL_IN
    with ``ct mark`` lacking the proof bit is dropped. The proof lives in the
    separate 32-bit ``ct mark`` space (``docs/lab-26``), so the lab-09 packet-mark
    forge (``meta mark set meta mark | 0x200``) does not reproduce the token. It
    is **not** unforgeable against a competing privileged writer of ``ct mark``;
    the real boundary is ADR-0013's single root apply-writer.

    Disabled returns ``destroy table`` for each of its own tables: an explicit
    off removes exactly the tables this generator owns and no other. As with the
    other offline TProxy generators, an enabled snapshot is only reachable
    through an offline ``model_copy`` (the public gate stays closed), so
    everything else is revalidated against the public contract instead of
    trusted.
    """
    table = "inet vs_router_tproxy_interception"
    reset_table = "inet vs_router_tproxy_ct_reset"
    guard_table = "inet vs_router_tproxy_input"
    c = version.configuration
    if not c.tproxy.enabled:
        return (f"destroy table {reset_table}\n"
                f"destroy table {table}\n"
                f"destroy table {guard_table}\n")
    sources = c.tproxy.ingress_interfaces
    allowed = {i.name for i in c.interfaces if i.zone and i.zone != "wan"}
    if not sources or len(set(sources)) != len(sources) or not set(sources) <= allowed:
        raise ValueError("tproxy.interception_invalid_ingress")
    # Offline fixtures bypass only the public enabled gate; never render capture
    # from an otherwise invalid model_copy snapshot.
    data = version.model_dump()
    data["configuration"]["tproxy"]["enabled"] = False
    ConfigurationVersion.model_validate(data)
    mark = marks.MARK_TPROXY_ROUTE_VALUE
    # Ownership check: the routing packet mark must stay inside the TProxy
    # namespace. The conntrack proof bit is a separate space (marks module) and
    # is intentionally absent from the packet-mark REGISTRY.
    marks.assert_no_collisions(mark, marks.Owner.TPROXY)
    ct_proof = marks.MARK_TPROXY_CT_PROOF_VALUE
    ct_clear = marks.MARK_TPROXY_CT_PROOF_CLEAR_MASK
    auth = marks.MARK_TPROXY_AUTH_VALUE
    marks.assert_no_collisions(auth, marks.Owner.TPROXY)
    ingress = names(sorted(sources))
    marked = f"meta mark set {mark:#x}"
    set_ct = f"ct mark set ct mark | {ct_proof:#x}"
    # Every own chain repeats the same exemptions the proven lab tracts use.
    exemptions = (
        f"        iifname != {ingress} return",
        "        fib daddr type local return",
        "        ct status dnat return",
        "        meta nfproto != ipv4 return",
        "        meta l4proto != { tcp, udp } return",
    )
    # Coupling to preauth (lab-31): capture fires only on transit already stamped
    # by a live preauthorization. With preauth lost the mark is absent, this
    # returns and the flow stays on the ordinary FORWARD path where the
    # independent containment (-10) / default-deny hold it -- fail-closed rather
    # than a LOCAL_IN -> proxy bypass of the FORWARD policy.
    gate = f"        meta mark & {auth:#x} == 0 return"
    lines = [f"destroy table {reset_table}", f"table {reset_table} {{",
             "    chain prerouting {",
             "        type filter hook prerouting priority -85; policy accept;",
             *exemptions,
             f"        ct mark set ct mark & {ct_clear:#x}",
             "    }", "}",
             f"destroy table {table}", f"table {table} {{",
             "    chain prerouting {",
             "        type filter hook prerouting priority -80; policy accept;",
             *exemptions,
             gate,
             f'        meta nfproto ipv4 meta l4proto tcp {marked} {set_ct} '
             f'tproxy ip to 127.0.0.1:{marks.TPROXY_TCP_PORT} counter accept comment "tproxy_tcp"',
             f'        meta nfproto ipv4 meta l4proto udp {marked} {set_ct} '
             f'tproxy ip to 127.0.0.1:{marks.TPROXY_UDP_PORT} counter accept comment "tproxy_udp"',
             "    }", "}",
             f"destroy table {guard_table}", f"table {guard_table} {{",
             "    chain input {",
             "        type filter hook input priority -20; policy accept;",
             *exemptions,
             f'        ct mark & {ct_proof:#x} == 0 counter drop comment "tproxy_input_denied"',
             "    }", "}"]
    return "\n".join(lines) + "\n"


def tproxy_policy_route_commands(action: str = "add") -> tuple[tuple[str, ...], ...]:
    """Deterministic ``ip rule`` / ``ip route`` argv for the TProxy capture mark.

    Data only — no shell, no I/O. The rule steers the marked packets into the
    registered loopback table and the local route makes them deliverable to the
    ``127.0.0.1`` TProxy listeners. Values come from the single ownership
    registry (:data:`marks.POLICY_ROUTES`), so the generator, the agent scaffold
    and a future typed loader cannot drift. ``action`` is ``"add"`` or ``"del"``;
    the inverse of add removes exactly these two owned entries.
    """
    if action not in ("add", "del"):
        raise ValueError("tproxy.policy_route_action")
    route = marks.POLICY_ROUTES[0]
    return (
        ("ip", "rule", action, "priority", str(route.rule_priority),
         "fwmark", f"{route.fwmark:#x}", "lookup", str(route.table_id)),
        ("ip", "route", action, "local", "0.0.0.0/0", "dev", "lo",
         "table", str(route.table_id)),
    )
