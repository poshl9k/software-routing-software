"""DoH client configuration for ``https`` upstreams (dnscrypt-proxy).

Deterministic, I/O-free generator (ADR-0015). DoH is not native to Unbound, so a
local ``dnscrypt-proxy`` listens on a loopback address and Unbound forwards the
``https`` upstreams to it. This module only renders the client config; the
service lifecycle (unit, activation) is a separate step.
"""
import json

from ..schema import ConfigurationVersion

#: Loopback endpoint the local dnscrypt-proxy listens on; Unbound forwards the
#: ``https`` upstreams here. Fixed so both generators agree.
DOH_LISTEN_ADDR = "127.0.0.1"
DOH_LISTEN_PORT = 5300


def doh_server_names(dns) -> tuple[str, ...]:
    """Built-in dnscrypt-proxy server names declared by ``https`` upstreams."""
    names = {u.doh_server for u in (*dns.upstreams,
                                    *(u for f in dns.forwards for u in f.upstreams))
             if u.mode == "https" and u.doh_server}
    return tuple(sorted(names))


def generate_dnscrypt(version: ConfigurationVersion) -> str:
    servers = doh_server_names(version.configuration.dns)
    return "\n".join([
        f"listen_addresses = ['{DOH_LISTEN_ADDR}:{DOH_LISTEN_PORT}']",
        "max_clients = 50",
        "doh_servers = true",
        "odoh_servers = false",
        "require_dnssec = false",
        "require_nolog = false",
        "require_nofilter = false",
        "cache = false",
        "server_names = [" + ", ".join(json.dumps(s) for s in servers) + "]",
    ]) + "\n"
