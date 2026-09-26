import json
from ipaddress import ip_interface
from ..schema import ConfigurationVersion


def generate_unbound(version: ConfigurationVersion) -> str:
    c = version.configuration
    dns = c.dns
    interfaces = {i.name: i for i in c.interfaces}
    addresses = [str(ip_interface(a).ip) for name in dns.interfaces for a in interfaces[name].addresses]
    lines = ["server:", '    username: "unbound"', '    interface-automatic: no',
             f'    log-queries: {"yes" if dns.log_queries else "no"}']
    # An unconfigured resolver is confined to loopback and refuses all clients.
    lines += [f"    interface: {a}" for a in dict.fromkeys(addresses or ["127.0.0.1"])]
    lines += ["    access-control: 0.0.0.0/0 refuse", "    access-control: ::/0 refuse"]
    lines += [f"    access-control: {n} allow" for n in dns.access_control]
    for r in dns.records:
        lines.append(f"    local-data: {json.dumps(f'{r.name} {r.ttl} IN {r.type} {r.value}')}")
    forwards = [(f.domain, f.upstreams) for f in dns.forwards]
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
