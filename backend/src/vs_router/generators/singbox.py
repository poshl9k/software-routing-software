"""Deterministic sing-box configuration preview; never installs or activates interception.

The TProxy inbounds/route skeleton is always rendered for offline validation.
The disabled-by-default ``proxies`` section adds sing-box ``outbounds`` (local
direct/block plus contract proxy types) and ``outbounds`` groups (selector /
urltest) when ``proxies.enabled`` is true. Product routing exits also render
explicitly referenced proxy outbounds and interface-bound client-tunnel exits.
Without product rules, a disabled or empty proxies section keeps legacy output.

Generators stay I/O-free and never read a key. Without an injected provider,
secret-bearing fields carry fixed placeholders (safe for previews). The agent
injects decrypted credentials only when staging the apply artifact.
"""
from ipaddress import ip_address
from typing import Callable

from vs_router.schema import Configuration, ConfigurationVersion, ProxyOutbound
from vs_router.validators import (
    derive_dns_detours, routing_exit_tag, routing_referenced_tags,
    routing_subject_interface_cidrs, validate_routing,
)

from . import marks

# Fixed, non-secret stand-ins so a preview is structurally valid for
# ``sing-box check`` without ever exposing encrypted material. They are not
# credentials and are not derived from any secret.
PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"
PLACEHOLDER_PASSWORD = "redacted"
# Shadowsocks needs a cipher name; the contract does not model it yet.
PLACEHOLDER_SHADOWSOCKS_METHOD = "chacha20-ietf-poly1305"

# Tags owned by the generator itself; a contract object may not shadow them.
IMPLICIT_DIRECT_TAG = "direct"
#: The loopback DNS stub inbound: the subscriber resolver's unmatched upstream.
DNS_STUB_TAG = "dns-in"
IMPLICIT_BLOCK_TAG = "block"

# Generator-owned local set. Apply must materialize this file before sing-box
# validates/reloads the main config; membership-only updates replace this file
# atomically instead of rewriting ``singbox.json``.
SUBSCRIBER_PEERS_RULE_SET_TAG = "vs_subscriber_peers"
SUBSCRIBER_PEERS_RULE_SET_PATH = "/etc/vs-router/applied/subscriber-peers.json"


def _subscriber_peer_addresses(configuration: Configuration) -> list[str]:
    """Return every subscriber peer CIDR in stable order."""
    return sorted({address for tunnel in configuration.tunnels
                   for peer in tunnel.peers if peer.subscriber is not None
                   for address in peer.allowed_ips})


def generate_subscriber_peers_rule_set(version: ConfigurationVersion) -> dict:
    """Render sing-box source rule-set for dynamic subscriber membership.

    Empty membership produces no headless rules. It must not produce a rule with
    an empty ``source_ip_cidr`` because an empty matcher can become match-all.
    """
    addresses = _subscriber_peer_addresses(version.configuration)
    rules = [{"source_ip_cidr": addresses}] if addresses else []
    return {"version": 3, "rules": rules}


def _tls_block(outbound):
    if not outbound.tls:
        return None
    tls: dict[str, object] = {"enabled": True}
    if outbound.tls_server_name:
        tls["server_name"] = outbound.tls_server_name
    if outbound.tls_insecure:
        tls["insecure"] = True
    if outbound.tls_utls_fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": outbound.tls_utls_fingerprint}
    if outbound.reality_public_key:
        tls["reality"] = {"enabled": True, "public_key": outbound.reality_public_key,
                          "short_id": outbound.reality_short_id or ""}
    return tls


def _render_outbound(outbound: ProxyOutbound,
                     secret_provider: Callable[[ProxyOutbound], dict] | None = None):
    """Map a proxy to sing-box; credentials come only from an explicit provider."""
    rendered = {"type": outbound.type, "tag": outbound.tag}
    if outbound.type in ("direct", "block"):
        return rendered
    credentials = secret_provider(outbound) if secret_provider is not None else {}
    rendered["server"] = outbound.server
    rendered["server_port"] = outbound.port
    if outbound.type == "shadowsocks":
        rendered["method"] = credentials.get("method", outbound.method or PLACEHOLDER_SHADOWSOCKS_METHOD)
        rendered["password"] = credentials.get("password", PLACEHOLDER_PASSWORD)
        if outbound.plugin:
            rendered["plugin"] = outbound.plugin
            if outbound.plugin_opts:
                rendered["plugin_opts"] = outbound.plugin_opts
    elif outbound.type == "vmess":
        rendered["uuid"] = credentials.get("uuid", PLACEHOLDER_UUID)
        rendered["security"] = outbound.security or "auto"
        rendered["alter_id"] = outbound.alter_id if outbound.alter_id is not None else 0
    elif outbound.type == "vless":
        rendered["uuid"] = credentials.get("uuid", PLACEHOLDER_UUID)
        if outbound.flow:
            rendered["flow"] = outbound.flow
    elif outbound.type == "trojan":
        rendered["password"] = credentials.get("password", PLACEHOLDER_PASSWORD)
    elif outbound.type == "hysteria2":
        rendered["password"] = credentials.get("password", PLACEHOLDER_PASSWORD)
        if outbound.obfs_type:
            rendered["obfs"] = {"type": outbound.obfs_type,
                                "password": credentials.get("obfs_password", PLACEHOLDER_PASSWORD)}
    elif outbound.type == "tuic":
        rendered["uuid"] = credentials.get("uuid", PLACEHOLDER_UUID)
        rendered["password"] = credentials.get("password", PLACEHOLDER_PASSWORD)
    elif outbound.type in ("naive", "mieru"):
        rendered["username"] = credentials.get("username", outbound.username or "redacted")
        rendered["password"] = credentials.get("password", PLACEHOLDER_PASSWORD)
    tls = _tls_block(outbound)
    if tls is not None:
        rendered["tls"] = tls
    if outbound.transport:
        rendered["transport"] = outbound.transport
    return rendered


def _render_group(group):
    rendered = {"type": group.type, "tag": group.tag, "outbounds": list(group.outbounds)}
    if group.type == "urltest":
        if group.url:
            rendered["url"] = group.url
        if group.interval_minutes:
            rendered["interval"] = f"{group.interval_minutes}m"
        if group.tolerance_ms is not None:
            rendered["tolerance"] = group.tolerance_ms
    return rendered


def _default_outbound_tag(groups):
    """Pick the deterministic default outbound for unmatched traffic.

    Prefer the first selector group (traffic explicitly routed by an operator),
    then the first urltest group; otherwise fall back to the local ``direct``
    tag so a disabled/empty section keeps the legacy behaviour.
    """
    for wanted in ("selector", "urltest"):
        for group in sorted((g for g in groups if g.type == wanted), key=lambda g: g.tag):
            return group.tag
    return IMPLICIT_DIRECT_TAG


def _rule_matchers(rule):
    """All matcher keys in one rule are AND; each list is OR within its key."""
    matchers = []
    if rule.domain_suffix:
        matchers.append({"domain_suffix": list(rule.domain_suffix)})
    for field, key in (("domain_exact", "domain"), ("domain_keyword", "domain_keyword"),
                       ("domain_regex", "domain_regex")):
        if getattr(rule, field):
            matchers.append({key: list(getattr(rule, field))})
    if rule.ip_cidr:
        matchers.append({"ip_cidr": list(rule.ip_cidr)})
    if rule.source_ip_cidr:
        matchers.append({"source_ip_cidr": list(rule.source_ip_cidr)})
    for field, key in (("source_mac", "source_mac_address"), ("inbound", "inbound")):
        if getattr(rule, field):
            matchers.append({key: list(getattr(rule, field))})
    if rule.ip_is_private is not None:
        matchers.append({"ip_is_private": rule.ip_is_private})
    if rule.rule_sets:
        matchers.append({"rule_set": list(rule.rule_sets)})
    singles = [int(port) for port in rule.ports if "-" not in port]
    if singles:
        matchers.append({"port": singles})
    ranges = [port.replace("-", ":") for port in rule.ports if "-" in port]
    if ranges:
        matchers.append({"port_range": ranges})
    network = rule.network or (rule.protocol if rule.protocol != "any" else None)
    if network:
        matchers.append({"network": [network]})
    return {key: value for matcher in matchers for key, value in matcher.items()}


def _render_rule_match(rule):
    if rule.logical_mode is not None:
        return {"type": "logical", "mode": rule.logical_mode,
                "rules": [_rule_matchers(child) for child in rule.logical_rules]}
    return _rule_matchers(rule)


def _render_destination_disjunction(rule):
    """The rule's destination is a disjunction, not a set of AND-ed matchers.

    ``ip_cidr``, ``domain_suffix`` and ``domain_exact`` are three ways to name
    where the traffic goes, and the panel presents them as alternatives. Inside
    one sing-box rule every matcher key is AND-ed by the engine, so a flat rule
    that lists a network and a domain matches traffic that is *both* — an
    operator who meant OR gets an intersection that matches almost nothing and
    silently fails to route. The three destination families therefore form a
    logical OR: one family stays flat, two or more become
    ``{"type": "logical", "mode": "or", "rules": [...]}``.

    Returns ``None`` when the rule names no destination at all (the whole
    address space is the destination, as before).
    """
    matchers = []
    if rule.ip_cidr:
        matchers.append({"ip_cidr": list(rule.ip_cidr)})
    if rule.domain_suffix:
        matchers.append({"domain_suffix": list(rule.domain_suffix)})
    if rule.domain_exact:
        matchers.append({"domain": list(rule.domain_exact)})
    if rule.rule_sets:
        # ADR-0031: declared rule sets are a destination family of their own.
        matchers.append({"rule_set": list(rule.rule_sets)})
    if not matchers:
        return None
    if len(matchers) == 1:
        return matchers[0]
    return {"type": "logical", "mode": "or", "rules": matchers}


def _wrap_subject_and_destination(subject_match, destination, action):
    """Subject matcher is AND-ed with the destination, never part of its OR.

    A product routing rule means traffic *from* the subject *and* to any one of
    the listed destinations *and* through the chosen exit. The subject's
    ``source_ip_cidr`` is an outer matcher beside the destination; the
    destination disjunction is nested inside it. With no subject, or a single
    destination family, the rule stays flat and no ``logical`` wrapper appears.
    """
    if destination is None:
        # No destination names the whole address space, so the subject alone
        # decides. Keeping the subject here matters: dropping it would widen
        # the rule to every source on the host.
        return {**subject_match, **action}
    if not subject_match:
        return {**destination, **action}
    if destination.get("type") == "logical":
        # sing-box 1.14.2 rejects a flat rule that mixes ``source_ip_cidr`` with
        # a ``logical`` matcher (unknown field), so the subject and the
        # destination disjunction are themselves nested in an AND node.
        return {"type": "logical", "mode": "and",
                "rules": [subject_match, destination], **action}
    return {**subject_match, **destination, **action}


def _render_product_routing(configuration: Configuration) -> tuple[list[dict], list[dict]]:
    """Render validated egress policy without capturing traffic or allocating addresses."""
    if not configuration.routing_rules:
        return [], []
    # model_copy/model_construct can bypass the contract; never emit dangling
    # exits, colliding tags or an addressless interface as an unrestricted rule.
    validate_routing(configuration)
    tunnels = {tunnel.name: tunnel for tunnel in configuration.tunnels}
    devices = {(peer.subscriber, peer.name): peer
               for tunnel in configuration.tunnels for peer in tunnel.peers
               if peer.subscriber is not None}
    rules = []
    bound_outbounds = {}
    for rule in configuration.routing_rules:
        subject_match = {}
        if rule.subject.kind == "device":
            # Guaranteed by RoutingSubject validation, before generation.
            assert rule.subject.subscriber is not None and rule.subject.peer is not None
            peer = devices[(rule.subject.subscriber, rule.subject.peer)]
            if not peer.allowed_ips:
                raise ValueError("routing.device_address_required")
            subject_match["source_ip_cidr"] = list(peer.allowed_ips)
        elif rule.subject.kind == "interface":
            sources = routing_subject_interface_cidrs(configuration, rule.subject.interface)
            if not sources:
                # Tunnel subject with no subscriber peers (last device gone):
                # the rule matches nothing. Skip it — an empty source_ip_cidr
                # would be read by sing-box as "no condition" and catch ALL
                # traffic, so the rule must not be rendered at all.
                continue
            subject_match["source_ip_cidr"] = list(sources)
        destination = _render_destination_disjunction(rule)
        # Domain matching needs DNS visibility (ADR-0020). Do not pretend that
        # sniffing implements the subscriber resolver, or enable it implicitly.
        target = rule.exit
        if target.kind == "block":
            rules.append(_wrap_subject_and_destination(
                subject_match, destination, {"action": "reject"}))
            continue
        tag = routing_exit_tag(target) or IMPLICIT_DIRECT_TAG
        if target.kind in ("tunnel", "interface"):
            interface = (tunnels[target.name].interface if target.kind == "tunnel"
                         else target.interface)
            bound_outbounds.setdefault(tag, {"type": "direct", "tag": tag,
                                             "bind_interface": interface})
        rules.append(_wrap_subject_and_destination(
            subject_match, destination, {"action": "route", "outbound": tag}))

    # Unmatched devices are rejected BEFORE legacy bypass/routing/defaults,
    # including devices with no individual rule. The dynamic local rule-set
    # keeps this main config stable when subscriber membership alone changes;
    # apply owns atomic materialization/reload of its source file. The final
    # outbound remains for non-device traffic only. Use the route reject action,
    # not a legacy block outbound. Runtime fail-closed remains
    # agent.tproxy_apply's guards/readiness ordering and the existing
    # containment/kill-switch machinery; bind_interface is not a replacement
    # for those protections if a tunnel/engine goes down.
    rules.append({"rule_set": [SUBSCRIBER_PEERS_RULE_SET_TAG], "action": "reject"})
    return rules, list(bound_outbounds.values())


def generate_singbox(version: ConfigurationVersion,
                     secret_provider: Callable[[ProxyOutbound], dict] | None = None) -> dict:
    """Render sing-box policy. No provider means redacted preview; provider means apply only.

    A guarded-off TProxy configuration is still rendered for preview. Legacy
    proxy groups/defaults require ``proxies.enabled``; product rules explicitly
    select their own exits. No nftables, policy routing or service changes.
    """
    configuration = version.configuration
    # Recheck even for model_copy/model_construct callers that bypass validation.
    dns_detours = derive_dns_detours(configuration)
    proxies = configuration.proxies

    # Bypass (S3b): excluded traffic routed straight out. Emitted before every
    # other rule so a bypass row wins in the preview and matches the nftables
    # capture exclusion.
    bypass_rules = []
    for row in configuration.tproxy.bypass:
        matchers = []
        if row.source_ip_cidr:
            matchers.append({"source_ip_cidr": list(row.source_ip_cidr)})
        if row.ip_cidr:
            matchers.append({"ip_cidr": list(row.ip_cidr)})
        singles = [int(port) for port in row.ports if "-" not in port]
        if singles:
            matchers.append({"port": singles})
        ranges = [port.replace("-", ":") for port in row.ports if "-" in port]
        if ranges:
            matchers.append({"port_range": ranges})
        if row.protocol != "any":
            matchers.append({"network": [row.protocol]})
        match = {key: value for matcher in matchers for key, value in matcher.items()}
        match.update({"action": "route", "outbound": IMPLICIT_DIRECT_TAG})
        bypass_rules.append(match)

    rules = list(bypass_rules)
    product_has_domain = any(
        rule.domain_suffix or rule.domain_exact or rule.rule_sets
        for rule in configuration.routing_rules)
    if configuration.tproxy.sniff:
        rules.insert(0, {"action": "sniff"})
    elif any(any((part.domain_suffix, part.domain_exact, part.domain_keyword, part.domain_regex))
             for r in configuration.tproxy.rules for part in (r, *r.logical_rules)) \
            or product_has_domain:
        # Domain and rule-set matching need sniffed domains (ADR-0020); product
        # rules carry their own, so the system sniff covers them the same way.
        rules.append({"action": "sniff"})
    if configuration.tproxy.udp_timeout_seconds is not None:
        rules.insert(1 if configuration.tproxy.sniff else 0,
                     {"action": "route-options",
                      "udp_timeout": f"{configuration.tproxy.udp_timeout_seconds}s"})
    for rule in sorted(configuration.tproxy.rules, key=lambda r: r.order):
        match = _render_rule_match(rule)
        if rule.action == "block":
            match["action"] = "reject"
        elif rule.action == "route":
            match.update({"action": "route", "outbound": rule.outbound})
        else:
            match.update({"action": "route", "outbound": IMPLICIT_DIRECT_TAG})
        rules.append(match)

    product_rules, bound_outbounds = _render_product_routing(configuration)
    if product_rules:
        # Interception is the host's job. Nonterminal sniff/options prepare the
        # captured stream; product rules decide egress in configuration order.
        # Only traffic left after product policy and device rejection reaches
        # legacy bypass/TProxy rules. Keep their relative order unchanged.
        preparation = [r for r in rules if r.get("action") in ("sniff", "route-options")]
        legacy = [r for r in rules if r.get("action") not in ("sniff", "route-options")]
        rules = preparation + product_rules + legacy

    outbounds = [{"type": "direct", "tag": IMPLICIT_DIRECT_TAG}]
    final = IMPLICIT_DIRECT_TAG
    # Product exits render referenced outbounds/groups and their transitive
    # members even with legacy proxies off, without changing the legacy final.
    referenced = routing_referenced_tags(configuration)
    outbounds.extend(_render_outbound(o, secret_provider)
                     for o in sorted(proxies.outbounds, key=lambda o: o.tag)
                     if proxies.enabled or o.tag in referenced)
    outbounds.extend(_render_group(g) for g in sorted(proxies.groups, key=lambda g: g.tag)
                     if proxies.enabled or g.tag in referenced)
    outbounds.extend(bound_outbounds)
    # TProxy final action overrides the default outbound selection
    tproxy = configuration.tproxy
    if tproxy.final == "block":
        if not any(o.get("tag") == IMPLICIT_BLOCK_TAG and o.get("type") == "block" for o in outbounds):
            outbounds.append({"type": "block", "tag": IMPLICIT_BLOCK_TAG})
            outbounds.sort(key=lambda o: o["tag"])
        final = IMPLICIT_BLOCK_TAG
    elif tproxy.final == "route":
        final = tproxy.final_outbound or IMPLICIT_DIRECT_TAG
    else:
        # legacy direct behaviour
        if proxies.enabled:
            final = _default_outbound_tag(proxies.groups)

    dns_policy = tproxy.dns
    inbounds = [
        {"type": "tproxy", "tag": "tproxy-udp", "listen": "127.0.0.1", "listen_port": 51271,
         "network": "udp"},
        {"type": "tproxy", "tag": "tproxy-tcp", "listen": "127.0.0.1", "listen_port": 51272,
         "network": "tcp"},
    ]
    if dns_policy.servers:
        # The subscriber resolver forwards its unmatched queries to this loopback
        # stub (marks.DNS_STUB_PORT) and the engine answers them from the dns policy
        # below, so the split decision lives where the routing policy does. Both
        # 1.11-era mechanisms are gone from the pinned engine: an inbound `sniff`
        # field and the `dns` outbound are rejected outright (measured with `check`
        # on the panel), so sniffing is a rule action and DNS is answered by
        # hijack-dns. Both rules are scoped to this inbound, so nothing else starts
        # sniffing on the stub's account.
        inbounds.append({"type": "direct", "tag": DNS_STUB_TAG, "listen": marks.DNS_STUB_ADDR,
                         "listen_port": marks.DNS_STUB_PORT})
        rules.insert(0, {"inbound": [DNS_STUB_TAG], "action": "sniff"})
        rules.insert(1, {"inbound": [DNS_STUB_TAG], "protocol": "dns", "action": "hijack-dns"})
    result = {
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": final, "auto_detect_interface": True},
    }
    # ADR-0031: the engine learns the sets from the same contract. Every tag
    # referenced by a matcher (product rules, legacy rules and their logical
    # parts, DNS rules) must have a remote declaration here, or the pinned
    # engine rejects the config. Formats the engine cannot consume natively
    # (text lists, raw geosite/geoip) are a render-time failure, not a
    # silently dead matcher.
    referenced_sets = {name for rule in configuration.routing_rules for name in rule.rule_sets}
    referenced_sets |= {name for rule in configuration.tproxy.rules
                        for part in (rule, *rule.logical_rules) for name in part.rule_sets}
    referenced_sets |= {name for rule in configuration.tproxy.dns.rules for name in rule.rule_sets}
    declared = {source.name: source for source in configuration.rule_sets}
    if SUBSCRIBER_PEERS_RULE_SET_TAG in declared:
        # This tag identifies a generator-owned local file; accepting a user
        # declaration with the same tag would redirect fail-closed matching.
        raise ValueError("routing.ruleset_tag_reserved")
    rule_set_entries = []
    for name in sorted(referenced_sets):
        source = declared.get(name)
        if source is None:
            raise ValueError("routing.ruleset_unavailable")
        engine_format = {"srs": "binary", "json": "source"}.get(source.format)
        if engine_format is None:
            raise ValueError(f"routing.ruleset_format: {source.format}")
        rule_set_entries.append({"type": "remote", "tag": name,
                                 "format": engine_format, "url": source.url})
    if configuration.routing_rules:
        rule_set_entries.append({
            "type": "local",
            "tag": SUBSCRIBER_PEERS_RULE_SET_TAG,
            "format": "source",
            "path": SUBSCRIBER_PEERS_RULE_SET_PATH,
        })
    if rule_set_entries:
        result["route"]["rule_set"] = rule_set_entries
    if dns_policy.servers:
        dns_servers = []
        bootstrap_tag = None
        for server in dns_policy.servers:
            rendered: dict[str, object] = {"tag": server.tag, "type": server.type, "server": server.server}
            if server.server_port is not None:
                rendered["server_port"] = server.server_port
            if server.type == "https":
                rendered["path"] = server.path or "/dns-query"
            elif server.path:
                rendered["path"] = server.path
            if server.domain_resolver is not None:
                rendered["domain_resolver"] = server.domain_resolver
            detour = server.detour if server.detour is not None else dns_detours.get(server.tag)
            if detour is not None:
                rendered["detour"] = detour
            if server.type in ("tls", "https"):
                rendered["tls"] = {"server_name": server.tls_name} if server.tls_name else {}
            try:
                ip_address(server.server)
            except ValueError:
                pass
            else:
                if bootstrap_tag is None:
                    bootstrap_tag = server.tag
            dns_servers.append(rendered)
        result["route"]["default_domain_resolver"] = {
            "server": bootstrap_tag or dns_policy.servers[0].tag
        }
        dns = {"servers": dns_servers}
        if dns_policy.rules:
            dns_rules = []
            for rule in dns_policy.rules:
                matchers = []
                if rule.domain_suffix:
                    matchers.append({"domain_suffix": list(rule.domain_suffix)})
                if rule.rule_sets:
                    matchers.append({"rule_set": list(rule.rule_sets)})
                match = (matchers[0] if len(matchers) == 1 else
                         {"type": "logical", "mode": "or", "rules": matchers})
                dns_rules.append({**match, "server": rule.server})
            dns["rules"] = dns_rules
        dns["final"] = dns_policy.servers[0].tag
        result["dns"] = dns
    if tproxy.enabled or proxies.enabled:
        result["experimental"] = {"clash_api": {
            "external_controller": f"127.0.0.1:{tproxy.clash_api_port}"
        }}
    return result
