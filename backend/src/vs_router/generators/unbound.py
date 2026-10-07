import json
from ipaddress import ip_interface
from ..schema import ConfigurationVersion


def _render_unbound(c, dns, root_forward=None, username: str | None = "unbound") -> str:
    interfaces = {i.name: i for i in c.interfaces}
    addresses = [str(ip_interface(a).ip) for name in dns.interfaces for a in interfaces[name].addresses]
    lines = ["server:"]
    # ``username`` requests unbound to drop to a named user; its compiled-in
    # default is ``"unbound"`` and the drop is fatally rejected when the process
    # is not root. The TProxy split runs each resolver under a dedicated systemd
    # ``User=`` (ADR-0014), so it emits the documented empty value
    # (``username=""``) to disable the drop and lets systemd own the UID. The
    # ordinary product resolver keeps the historical ``username: "unbound"`` line.
    if username is not None:
        lines.append(f'    username: {json.dumps(username)}')
    lines += ['    interface-automatic: no',
              f'    log-queries: {"yes" if dns.log_queries else "no"}']
    if root_forward is not None:
        # Unbound's default refuses loopback upstreams even if checkconf exits 0.
        lines.append('    do-not-query-localhost: no')
        # No selected unmatched answer may outlive the DNS engine's readiness.
        # This sacrifices the selected instance's cache, including forwards;
        # local-data remains independent of the cache.
        lines += ['    cache-max-ttl: 0', '    cache-max-negative-ttl: 0',
                  '    serve-expired: no']
    # An unconfigured resolver is confined to loopback and refuses all clients.
    lines += [f"    interface: {a}" for a in dict.fromkeys(addresses or ["127.0.0.1"])]
    lines += ["    access-control: 0.0.0.0/0 refuse", "    access-control: ::/0 refuse"]
    lines += [f"    access-control: {n} allow" for n in dns.access_control]
    for r in dns.records:
        lines.append(f"    local-data: {json.dumps(f'{r.name} {r.ttl} IN {r.type} {r.value}')}")
    forwards = [(f.domain, f.upstreams) for f in dns.forwards]
    if root_forward is not None:
        forwards.append((".", (root_forward,)))
    if not dns.recursive and not any(d == "." for d, _ in forwards):
        if dns.upstreams:
            forwards.append((".", dns.upstreams))
        else:
            lines.append('    local-zone: "." refuse')
            lines += [f"    local-zone: {json.dumps(domain)} transparent" for domain, _ in forwards]
    for domain, upstreams in forwards:
        lines += ["forward-zone:", f"    name: {json.dumps(domain)}"]
        lines += [f"    forward-addr: {u}" for u in upstreams]
    return "\n".join(lines) + "\n"


def generate_unbound(version: ConfigurationVersion) -> str:
    c = version.configuration
    return _render_unbound(c, c.dns)


def tproxy_unbound_listener_addresses(version: ConfigurationVersion) -> dict[str, tuple[str, ...]]:
    """Validate offline-only split prerequisites and return disjoint IPv4 listeners."""
    c = version.configuration
    sources = c.tproxy.ingress_interfaces
    interfaces = {i.name: i for i in c.interfaces}
    if not c.tproxy.enabled or not sources or len(set(sources)) != len(sources):
        raise ValueError("tproxy.dns_split_invalid_sources")
    data = version.model_dump()
    data["configuration"]["tproxy"]["enabled"] = False
    ConfigurationVersion.model_validate(data)
    if any(name not in c.dns.interfaces for name in sources):
        raise ValueError("tproxy.dns_split_missing_listener")
    if c.dns.recursive or any(f.domain == "." for f in c.dns.forwards):
        raise ValueError("tproxy.dns_split_root_unsupported")
    addresses = [ip_interface(a).ip for name in c.dns.interfaces
                 for a in interfaces[name].addresses]
    all_addresses = [ip_interface(a).ip for i in c.interfaces for a in i.addresses]
    if (len(set(addresses)) != len(addresses) or
            len(set(all_addresses)) != len(all_addresses) or
            any(ip.version != 4 for ip in addresses)):
        raise ValueError("tproxy.dns_split_address_unsupported")
    selected = tuple(sorted(str(ip_interface(a).ip) for name in sources
                            for a in interfaces[name].addresses))
    ordinary = tuple(sorted(str(ip_interface(a).ip) for name in c.dns.interfaces
                            if name not in sources for a in interfaces[name].addresses))
    return {"selected": selected, "ordinary": ordinary or ("127.0.0.1",)}


def generate_tproxy_unbound_split(version: ConfigurationVersion) -> dict[str, str]:
    """OFFLINE-only split; requires separate processes and listener-bound INPUT rules.

    The selected instance forwards unmatched queries to a *nonexistent here*
    loopback DNS stub. This function never activates a service or changes routing.
    """
    tproxy_unbound_listener_addresses(version)
    c = version.configuration
    sources = c.tproxy.ingress_interfaces
    selected_dns = c.dns.model_copy(update={"interfaces": tuple(sorted(sources))})
    ordinary_dns = c.dns.model_copy(update={
        "interfaces": tuple(name for name in c.dns.interfaces if name not in sources)})
    return {
        "selected": _render_unbound(c, selected_dns, "127.0.0.1@15353",
                                    username=""),
        "ordinary": _render_unbound(c, ordinary_dns, username=""),
    }
