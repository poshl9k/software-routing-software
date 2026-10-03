"""Deterministic sing-box configuration preview; never installs or activates interception."""
from vs_router.schema import ConfigurationVersion


def generate_singbox(version: ConfigurationVersion) -> dict:
    """Render the initial IPv4 direct/block policy for offline validation only.

    A guarded-off TProxy configuration is still rendered for preview. This function
    does not change nftables, policy routing or service state.
    """
    rules = ([{"action": "sniff"}] if any(r.domain_suffix for r in version.configuration.tproxy.rules)
             else [])
    for rule in sorted(version.configuration.tproxy.rules, key=lambda r: r.order):
        matchers = []
        if rule.domain_suffix:
            matchers.append({"domain_suffix": list(rule.domain_suffix)})
        if rule.ip_cidr:
            matchers.append({"ip_cidr": list(rule.ip_cidr)})
        match = (matchers[0] if len(matchers) == 1 else
                 {"type": "logical", "mode": "or", "rules": matchers})
        match.update({"action": "reject"} if rule.action == "block" else
                     {"action": "route", "outbound": "direct"})
        rules.append(match)
    return {
        "inbounds": [
            {"type": "tproxy", "tag": "tproxy-udp", "listen": "127.0.0.1", "listen_port": 51271,
             "network": "udp"},
            {"type": "tproxy", "tag": "tproxy-tcp", "listen": "127.0.0.1", "listen_port": 51272,
             "network": "tcp"},
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct", "auto_detect_interface": True},
    }
