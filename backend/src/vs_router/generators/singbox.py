"""Deterministic sing-box configuration preview; never installs or activates interception.

The TProxy inbounds/route skeleton is always rendered for offline validation.
The disabled-by-default ``proxies`` section adds sing-box ``outbounds`` (local
direct/block plus contract proxy types) and ``outbounds`` groups (selector /
urltest) *only when* ``proxies.enabled`` is true; a disabled or empty section
produces the exact legacy output.

Secrets are never decrypted here: generators must stay deterministic and free of
I/O, and the contract stores every ``secret`` encrypted (``EncryptedSecret``).
Secret-bearing sing-box fields therefore carry a fixed, non-secret placeholder.
Real secret injection belongs to a future apply path (not implemented) and must
go through ``secrets.decrypt_secret``; nothing in this module reads a key.
"""
from vs_router.schema import ConfigurationVersion

# Fixed, non-secret stand-ins so a preview is structurally valid for
# ``sing-box check`` without ever exposing encrypted material. They are not
# credentials and are not derived from any secret.
PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"
PLACEHOLDER_PASSWORD = "redacted"
# Shadowsocks needs a cipher name; the contract does not model it yet.
PLACEHOLDER_SHADOWSOCKS_METHOD = "chacha20-ietf-poly1305"

# Tags owned by the generator itself; a contract object may not shadow them.
IMPLICIT_DIRECT_TAG = "direct"


def _tls_block(outbound):
    if not outbound.tls:
        return None
    tls = {"enabled": True}
    if outbound.tls_server_name:
        tls["server_name"] = outbound.tls_server_name
    if outbound.tls_insecure:
        tls["insecure"] = True
    return tls


def _render_outbound(outbound):
    """Map one contract :class:`ProxyOutbound` to a sing-box outbound dict.

    Deterministic and key-ordered by construction; carries no secret material.
    """
    rendered = {"type": outbound.type, "tag": outbound.tag}
    if outbound.type in ("direct", "block"):
        return rendered
    rendered["server"] = outbound.server
    rendered["server_port"] = outbound.port
    if outbound.type == "shadowsocks":
        rendered["method"] = PLACEHOLDER_SHADOWSOCKS_METHOD
        rendered["password"] = PLACEHOLDER_PASSWORD
    elif outbound.type == "vmess":
        rendered["uuid"] = PLACEHOLDER_UUID
        rendered["security"] = "auto"
        rendered["alter_id"] = 0
    elif outbound.type == "vless":
        rendered["uuid"] = PLACEHOLDER_UUID
    elif outbound.type == "trojan":
        rendered["password"] = PLACEHOLDER_PASSWORD
    elif outbound.type == "hysteria2":
        rendered["password"] = PLACEHOLDER_PASSWORD
    elif outbound.type == "tuic":
        rendered["uuid"] = PLACEHOLDER_UUID
        rendered["password"] = PLACEHOLDER_PASSWORD
    tls = _tls_block(outbound)
    if tls is not None:
        rendered["tls"] = tls
    return rendered


def _render_group(group):
    rendered = {"type": group.type, "tag": group.tag, "outbounds": list(group.outbounds)}
    if group.type == "urltest":
        if group.url:
            rendered["url"] = group.url
        if group.interval_minutes:
            rendered["interval"] = f"{group.interval_minutes}m"
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


def generate_singbox(version: ConfigurationVersion) -> dict:
    """Render the offline sing-box policy (inbounds, outbounds, route).

    A guarded-off TProxy configuration is still rendered for preview. The
    ``proxies`` section is only expanded while it is enabled; this function does
    not change nftables, policy routing or service state.
    """
    configuration = version.configuration
    proxies = configuration.proxies

    rules = ([{"action": "sniff"}] if any(r.domain_suffix for r in configuration.tproxy.rules)
             else [])
    for rule in sorted(configuration.tproxy.rules, key=lambda r: r.order):
        matchers = []
        if rule.domain_suffix:
            matchers.append({"domain_suffix": list(rule.domain_suffix)})
        if rule.ip_cidr:
            matchers.append({"ip_cidr": list(rule.ip_cidr)})
        match = (matchers[0] if len(matchers) == 1 else
                 {"type": "logical", "mode": "or", "rules": matchers})
        if rule.action == "block":
            match["action"] = "reject"
        elif rule.action == "route":
            match.update({"action": "route", "outbound": rule.outbound})
        else:
            match.update({"action": "route", "outbound": IMPLICIT_DIRECT_TAG})
        rules.append(match)

    outbounds = [{"type": "direct", "tag": IMPLICIT_DIRECT_TAG}]
    final = IMPLICIT_DIRECT_TAG
    if proxies.enabled:
        outbounds.extend(_render_outbound(o) for o in sorted(proxies.outbounds, key=lambda o: o.tag))
        outbounds.extend(_render_group(g) for g in sorted(proxies.groups, key=lambda g: g.tag))
        final = _default_outbound_tag(proxies.groups)

    return {
        "inbounds": [
            {"type": "tproxy", "tag": "tproxy-udp", "listen": "127.0.0.1", "listen_port": 51271,
             "network": "udp"},
            {"type": "tproxy", "tag": "tproxy-tcp", "listen": "127.0.0.1", "listen_port": 51272,
             "network": "tcp"},
        ],
        "outbounds": outbounds,
        "route": {"rules": rules, "final": final, "auto_detect_interface": True},
    }
