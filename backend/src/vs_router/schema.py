"""Versioned JSON contract. References use names, aliases use an explicit @ prefix."""
import re
from datetime import datetime
from ipaddress import ip_address
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_serializer, model_validator

Name = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_]{0,30}$")]
# Engine-owned tags (DNS servers/rules and references to them) follow sing-box
# convention and may contain hyphens, e.g. ``dns-direct`` / ``dns-tunnel``.
EngineTag = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]{0,30}$")]
InterfaceName = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Profile = Literal['router', 'panel']


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EncryptedSecret(Model):
    encrypted: Literal[True] = True
    ciphertext: str = Field(pattern=r"^gAAAA[A-Za-z0-9_=-]+$", repr=False)


class Interface(Model):
    name: InterfaceName
    type: Literal["physical", "bridge", "vlan"] = "physical"
    zone: Name | None = None
    # Free-form operator note / friendly label. UI-only metadata: generators
    # must never emit it into networkd/nftables/WireGuard output.
    description: str | None = Field(default=None, max_length=64)
    # static: addresses are configured; dhcp: the interface is a DHCPv4 client
    # (any type/zone). DHCP is explicit so "no address" never silently changes
    # meaning; the management LAN and Kea server interfaces forbid it.
    addressing: Literal["static", "dhcp", "pppoe"] = "static"
    pppoe_username: str | None = None
    pppoe_password: EncryptedSecret | None = None
    addresses: tuple[str, ...] = ()
    parent: InterfaceName | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    members: tuple[InterfaceName, ...] = ()

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        data = handler(self)
        # Preserve pre-PPPoE snapshot/API bytes for every ordinary interface.
        if self.addressing != "pppoe":
            data.pop("pppoe_username", None)
            data.pop("pppoe_password", None)
        return data


class StaticRoute(Model):
    destination: str
    interface: InterfaceName
    gateway: str | None = None
    metric: int = Field(default=0, ge=0)
    enabled: bool = True


class Alias(Model):
    name: Name
    type: Literal["address", "port"]
    elements: tuple[str, ...] = ()
    includes: tuple[Name, ...] = ()


class Pool(Model):
    start: str
    end: str


class Reservation(Model):
    hw_address: str = Field(pattern=r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    ip_address: str
    hostname: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9.-]+$")


class DHCPSubnet(Model):
    id: int = Field(ge=1, le=4294967294)
    interface: InterfaceName
    subnet: str
    pools: tuple[Pool, ...] = ()
    reservations: tuple[Reservation, ...] = ()
    routers: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    valid_lifetime: int = Field(default=3600, gt=0)


class Counters(Model):
    states: int = Field(default=0, ge=0)
    packets: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)


class FirewallRule(Model):
    name: Name
    ingress_zone: Name
    protocol: Literal["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp"] = "any"
    src: str = "any"
    dst: str = "any"
    destination_ports: str | None = None
    action: Literal["pass", "block", "reject"]
    order: int = Field(default=0, ge=0)
    enabled: bool = True
    log: bool = False
    counters: Counters = Field(default_factory=Counters)


class PortForward(Model):
    name: Name
    interface: InterfaceName
    protocol: Literal["tcp", "udp"]
    external_port: Port
    wan_address: str | None = None
    target: str
    target_port: Port
    enabled: bool = True


class OutboundNAT(Model):
    name: Name
    egress_zone: Name = "wan"
    src: str = "any"
    dst: str = "any"
    protocol: Literal["any", "tcp", "udp", "icmp"] = "any"
    translation: str = "primary"
    do_not_nat: bool = False
    order: int = Field(default=0, ge=0)


class DNSRecord(Model):
    name: str = Field(pattern=r"^[a-zA-Z0-9_.-]+$")
    type: Literal["A", "AAAA", "CNAME", "PTR", "TXT", "MX"] = "A"
    value: str
    ttl: int = Field(default=300, ge=0)


class DNSUpstream(Model):
    # An ``https`` (DoH) entry carries no forward-addr: it is realized by the
    # local dnscrypt-proxy (ADR-0015) and identified by a built-in server name.
    address: str = ""
    port: int = Field(default=53, ge=1, le=65535)
    mode: Literal["udp", "tls", "https"] = "udp"
    tls_name: str | None = None
    doh_server: str | None = None

    @model_validator(mode="before")
    def _coerce(cls, value):
        return {"address": value} if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check(self):
        if self.mode in ("udp", "tls") and not self.address:
            raise ValueError("dns.upstream_address_required")
        if self.mode == "tls" and not self.tls_name:
            raise ValueError("dns.upstream_tls_name_required")
        if self.mode == "https":
            if not self.doh_server:
                raise ValueError("dns.upstream_doh_server_required")
        elif self.doh_server is not None:
            raise ValueError("dns.upstream_doh_server_unexpected")
        return self


class DNSForward(Model):
    domain: str = Field(pattern=r"^(?:\.|[a-zA-Z0-9_.-]+)$")
    upstreams: tuple[DNSUpstream, ...] = Field(min_length=1)


class DNS(Model):
    interfaces: tuple[InterfaceName, ...] = ()
    access_control: tuple[str, ...] = ()
    records: tuple[DNSRecord, ...] = ()
    forwards: tuple[DNSForward, ...] = ()
    upstreams: tuple[DNSUpstream, ...] = ()
    recursive: bool = False
    log_queries: bool = False


class Subscriber(Model):
    name: Name
    label: str | None = None


class Peer(Model):
    name: Name
    public_key: str
    preshared_key: EncryptedSecret | None = None
    # Filled when the panel generated the peer keypair (client config export);
    # empty when the client brings its own key pair and shares only the public one.
    private_key: EncryptedSecret | None = None
    allowed_ips: tuple[str, ...] = ()
    #: The subscriber this peer belongs to as a device, or None for a service peer
    #: (CONTEXT.md allows a peer without a subscriber).
    subscriber: Name | None = None
    #: Panel resolvers allow domain rules; own resolvers allow address rules only
    #: for this device (ADR-0020).
    dns_mode: Literal['panel', 'own'] = 'panel'


# AmneziaWG obfuscation parameters. Classic values are integers; AWG 3+ adds the
# S3/S4 paddings, the I1-I5 signature packets and randomised ``min-max`` ranges
# for paddings and timings (see amneziawg-go's "AWG 3+" configuration section).
AWG_NUMERIC = frozenset({
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
    "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts"})
AWG_SIGNATURE = frozenset({"I1", "I2", "I3", "I4", "I5"})
# A single uint32 or an inclusive ``min-max`` range; ``(off)`` is a data-file
# spelling that the panel represents by simply omitting the key.
AWG_RANGE = re.compile(r"^[0-9]{1,10}(-[0-9]{1,10})?$")
# AWG 3+ keys that belong to the interface's obfuscation set: the mandatory core
# keys every client emits plus the optional AWG 3 additions.
AWG_CORE = frozenset({"Jc", "S1", "S2", "H1", "H2", "H3", "H4"})


def awg_parameter(key: str, value):
    """Validate one obfuscation entry, raising the schema error otherwise."""
    if key in AWG_NUMERIC:
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF:
            return value
        if isinstance(value, str) and AWG_RANGE.fullmatch(value):
            return value
    elif key in AWG_SIGNATURE:
        if isinstance(value, str) and value and "\n" not in value and "\r" not in value:
            return value
    raise ValueError("tunnel.awg_parameter")


class Tunnel(Model):
    name: Name
    interface: InterfaceName
    role: Literal["server", "client"]
    protocol: Literal["wg", "awg"]
    private_key: EncryptedSecret
    listen_port: Port | None = None
    peers: tuple[Peer, ...] = ()
    endpoint: str | None = None
    server_public_key: str | None = None
    allowed_ips: tuple[str, ...] = ()
    # Server only: client export resolvers. Empty selects the tunnel address.
    dns_servers: tuple[str, ...] = ()
    # Client only: opt in to installing 0.0.0.0/0 and ::/0 as host routes.
    # AllowedIPs remains the full peer contract even when host default routes are off.
    default_route: bool = False
    # A client's persistent keepalive: seconds, or an AWG 3+ ``min-max`` range.
    keepalive: int | str = 0
    # AmneziaWG interface parameters. Values are uint32s or ``min-max`` ranges;
    # I1-I5 are signature-packet expressions (strings).
    obfuscation: dict[str, int | str] = Field(default_factory=dict)
    # Client only: the peer's preshared secret, imported from a client config.
    preshared_key: EncryptedSecret | None = None
    # AmneziaWG 3+: low-entropy header protection key. Server-side in AWG terms
    # (it must match the remote end); stored for either role, emitted verbatim.
    header_protection_key: EncryptedSecret | None = None
    # AmneziaWG 3+ toggles.
    random_trailers: bool = False
    disable_cookies: bool = False
    # Server only: open udp/<listen_port> on the WAN zone so remote clients can
    # reach the server. The panel shows the generated rule on the Firewall page.
    open_port: bool = True

    @field_validator("dns_servers")
    @classmethod
    def check_dns_servers(cls, value):
        if len(value) > 2:
            raise ValueError("tunnel.dns_server_limit")
        for address in value:
            try:
                ip_address(address)
            except ValueError:
                raise ValueError("tunnel.dns_server_invalid") from None
        return value

    @field_validator("obfuscation")
    @classmethod
    def check_obfuscation(cls, value):
        for key, item in value.items():
            if key not in AWG_NUMERIC and key not in AWG_SIGNATURE:
                raise ValueError("tunnel.awg_key")
            awg_parameter(key, item)
        return value

    @field_validator("keepalive")
    @classmethod
    def check_keepalive(cls, value):
        if isinstance(value, int) and not isinstance(value, bool):
            if 0 <= value <= 65535:
                return value
        elif isinstance(value, str) and AWG_RANGE.fullmatch(value):
            return value
        raise ValueError("tunnel.keepalive")

    @model_validator(mode="after")
    def check_role(self):
        if self.role == "client" and self.dns_servers:
            raise ValueError("tunnel.dns_servers_server_only")
        # A server may carry an explicit public endpoint (IP or hostname) that is
        # advertised to its clients; without it the WAN address is used, else a
        # template. server_public_key belongs to a client only.
        if self.role == "server" and (self.server_public_key or self.listen_port is None):
            raise ValueError("tunnel.server_fields")
        if self.role == "client" and (self.peers or not self.endpoint or not self.server_public_key):
            raise ValueError("tunnel.client_fields")
        if self.protocol == "awg" and not AWG_CORE <= self.obfuscation.keys():
            raise ValueError("tunnel.awg_parameters")
        return self


class CaddySite(Model):
    name: Name
    hostname: str = Field(pattern=r"^[a-zA-Z0-9*.-]+$")
    upstream: str
    certificate_mode: Literal["http01", "dns01", "manual", "passthrough"]
    wan_address: str | None = None
    certificate: EncryptedSecret | None = None
    private_key: EncryptedSecret | None = None
    dns_api_token: EncryptedSecret | None = None

    @model_validator(mode="after")
    def check_certificate(self):
        if self.certificate_mode == "http01" and not self.wan_address:
            raise ValueError("caddy.wan_address_required")
        if self.certificate_mode == "manual" and not (self.certificate and self.private_key):
            raise ValueError("caddy.manual_certificate_required")
        return self


class DDNSUpdate(Model):
    name: Name
    provider: Literal["cloudflare", "rfc2136"]
    hostname: str = Field(pattern=r"^[a-zA-Z0-9.-]+$")
    zone: str | None = None
    server: str | None = None   # RFC2136 DNS-сервер
    key_name: str | None = None  # RFC2136 TSIG key name
    api_token: EncryptedSecret   # Cloudflare token / TSIG key
    wan_interface: InterfaceName = "enp1s0"

    @model_validator(mode="after")
    def check_provider(self):
        if self.provider == "cloudflare" and (not self.zone):
            raise ValueError("ddns.zone_required")
        if self.provider == "rfc2136" and not (self.server and self.key_name):
            raise ValueError("ddns.server_and_key_required")
        return self


class SSH(Model):
    interfaces: tuple[InterfaceName, ...] = ()
    wan_confirmed_interfaces: tuple[InterfaceName, ...] = ()


class TProxyUpdateSchedule(Model):
    mode: Literal["interval", "window"] = "interval"
    interval_hours: int = Field(default=6, ge=1, le=168)
    window_start: str = Field(default="00:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    window_end: str = Field(default="05:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")

    @model_validator(mode="after")
    def check_window(self):
        if self.mode == "window" and self.window_start >= self.window_end:
            raise ValueError("tproxy.invalid_window")
        return self


class TProxyRule(Model):
    name: Name
    domain_suffix: tuple[str, ...] = ()
    domain_exact: tuple[str, ...] = ()
    domain_keyword: tuple[str, ...] = ()
    domain_regex: tuple[str, ...] = ()
    ip_cidr: tuple[str, ...] = ()
    source_ip_cidr: tuple[str, ...] = ()
    source_mac: tuple[str, ...] = ()
    inbound: tuple[str, ...] = ()
    ip_is_private: StrictBool | None = None
    network: Literal["tcp", "udp"] | None = None
    rule_sets: tuple[EngineTag, ...] = ()
    protocol: Literal["any", "tcp", "udp"] = "any"
    ports: tuple[str, ...] = ()
    logical_mode: Literal["and", "or"] | None = None
    logical_rules: tuple["TProxyRule", ...] = ()
    # Destination of matched traffic (CONTEXT.md «Выход TProxy»): straight out
    # (direct), blocked, or routed to a named outbound (a proxy outbound/group
    # tag). ``outbound`` is only meaningful — and required — for ``route``.
    action: Literal["direct", "block", "route"] = "direct"
    outbound: Name | None = None
    order: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def check_matchers(self):
        from ipaddress import ip_network
        import re
        from vs_router.validators import port_range
        matchers = (self.domain_suffix, self.domain_exact, self.domain_keyword,
                    self.domain_regex, self.ip_cidr, self.source_ip_cidr,
                    self.source_mac, self.inbound, self.ip_is_private is not None,
                    self.network is not None, self.rule_sets, self.ports)
        if self.logical_mode is None and self.logical_rules:
            raise ValueError("tproxy.logical_mode_required")
        if self.logical_mode is not None:
            if len(self.logical_rules) < 2:
                raise ValueError("tproxy.logical_rules_required")
            if any(matchers) or self.protocol != "any":
                raise ValueError("tproxy.logical_matchers_unexpected")
            for child in self.logical_rules:
                if child.logical_mode is not None or child.logical_rules:
                    raise ValueError("tproxy.logical_nested")
                if child.action != "direct" or child.outbound is not None:
                    raise ValueError("tproxy.logical_child_action")
        elif not any(matchers):
            raise ValueError("tproxy.rule_matcher_required")
        if any(not re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+", domain)
               for domain in (*self.domain_suffix, *self.domain_exact)):
            raise ValueError("tproxy.domain_invalid")
        # sing-box ORs distinct domain keys inside a default rule. Refuse a
        # combination that would silently widen an AND policy; use logical AND
        # with one domain matcher per child instead.
        if sum(bool(values) for values in (self.domain_suffix, self.domain_exact,
                                           self.domain_keyword, self.domain_regex)) > 1:
            raise ValueError("tproxy.domain_matchers_conflict")
        if any(not value or not value.strip() for value in (*self.domain_keyword, *self.domain_regex,
                                                           *self.inbound)):
            raise ValueError("tproxy.matcher_empty")
        for pattern in self.domain_regex:
            try:
                re.compile(pattern)
            except re.error:
                raise ValueError("tproxy.domain_regex_invalid") from None
        if any(not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac)
               for mac in self.source_mac):
            raise ValueError("tproxy.source_mac_invalid")
        if self.protocol != "any" and self.network is not None and self.protocol != self.network:
            raise ValueError("tproxy.network_conflict")
        for cidr in self.ip_cidr:
            if ip_network(cidr).version != 4:
                raise ValueError("tproxy.ipv4_required")
        for cidr in self.source_ip_cidr:
            if ip_network(cidr).version != 4:
                raise ValueError("tproxy.source_ipv4_required")
        for port in self.ports:
            port_range(port)
        if self.action == "route" and self.outbound is None:
            raise ValueError("tproxy.outbound_required")
        if self.action != "route" and self.outbound is not None:
            raise ValueError("tproxy.outbound_unexpected")
        return self


class TProxyBypass(Model):
    name: Name
    source_ip_cidr: tuple[str, ...] = ()
    ip_cidr: tuple[str, ...] = ()
    ports: tuple[str, ...] = ()
    protocol: Literal["any", "tcp", "udp"] = "any"

    @model_validator(mode="after")
    def check_matchers(self):
        from ipaddress import ip_network
        from vs_router.validators import port_range
        if not any((self.source_ip_cidr, self.ip_cidr, self.ports)):
            raise ValueError("tproxy.bypass_matcher_required")
        for cidr in self.ip_cidr:
            if ip_network(cidr).version != 4:
                raise ValueError("tproxy.bypass_ipv4_required")
        for cidr in self.source_ip_cidr:
            if ip_network(cidr).version != 4:
                raise ValueError("tproxy.bypass_source_ipv4_required")
        for port in self.ports:
            port_range(port)
        return self


class TProxyDNSServer(Model):
    tag: EngineTag
    type: Literal["udp", "tls", "https"] = "udp"
    server: str
    server_port: int | None = Field(default=None, ge=1, le=65535)
    tls_name: str | None = None
    path: str | None = None
    domain_resolver: EngineTag | None = None
    detour: str | None = None

    @model_validator(mode="after")
    def check_address(self):
        if not self.server:
            raise ValueError("tproxy.dns_server_required")
        if self.type == "tls" and not self.tls_name:
            raise ValueError("tproxy.dns_tls_name_required")
        return self


class TProxyDNSRule(Model):
    name: EngineTag
    domain_suffix: tuple[str, ...] = ()
    rule_sets: tuple[EngineTag, ...] = ()
    server: EngineTag

    @model_validator(mode="after")
    def check_matchers(self):
        if not (self.domain_suffix or self.rule_sets):
            raise ValueError("tproxy.dns_rule_matcher_required")
        return self


class TProxyDNS(Model):
    servers: tuple[TProxyDNSServer, ...] = ()
    rules: tuple[TProxyDNSRule, ...] = ()

    @model_validator(mode="after")
    def check_refs(self):
        if not self.servers and self.rules:
            raise ValueError("tproxy.dns_servers_required")
        tags = [s.tag for s in self.servers]
        if len(tags) != len(set(tags)):
            raise ValueError("tproxy.dns_server_duplicate")
        names = [r.name for r in self.rules]
        if len(names) != len(set(names)):
            raise ValueError("tproxy.dns_rule_duplicate")
        for rule in self.rules:
            if rule.server not in tags:
                raise ValueError("tproxy.dns_rule_server_unavailable")
        has_hostname = False
        has_ip = False
        for server in self.servers:
            try:
                ip_address(server.server)
            except ValueError:
                has_hostname = True
            else:
                has_ip = True
        if has_hostname and not has_ip:
            raise ValueError("tproxy.dns_bootstrap_required")
        return self


class TProxy(Model):
    enabled: bool = False
    ingress_interfaces: tuple[InterfaceName, ...] = ()
    rules: tuple[TProxyRule, ...] = ()
    bypass: tuple[TProxyBypass, ...] = ()
    dns: TProxyDNS = Field(default_factory=TProxyDNS)
    final: Literal["direct", "block", "route"] = "direct"
    final_outbound: Name | None = None
    update_schedule: TProxyUpdateSchedule = Field(default_factory=TProxyUpdateSchedule)
    sniff: bool = False
    udp_timeout_seconds: int | None = Field(default=None, ge=1, le=86400)
    clash_api_port: int = Field(default=9099, strict=True, ge=1, le=65535)

    @model_validator(mode="after")
    def check_bypass_names(self):
        if not self.bypass:
            return self
        names = [row.name for row in self.bypass]
        if len(names) != len(set(names)):
            raise ValueError("tproxy.bypass_name_duplicate")
        return self


class ProxyOutbound(Model):
    """A future sing-box outbound. ``direct``/``block`` are local; every other
    type needs a server. A ``secret`` is stored encrypted (secrets.py) and
    returned redacted, never in plaintext — a raw string is rejected."""
    tag: Name
    type: Literal["direct", "block", "shadowsocks", "vmess", "vless",
                  "trojan", "hysteria2", "tuic", "naive", "mieru"]
    server: str | None = None
    port: Port | None = None
    secret: EncryptedSecret | None = None
    # Shadowsocks cipher name; the contract previously had no field for it, so
    # the generator substituted a placeholder. Imported links can carry it.
    method: str | None = None
    # VMess transport security and alter id; Shadowsocks plugin support.
    security: str | None = Field(default=None, pattern=r"^(auto|none|zero|aes-128-gcm|chacha20-poly1305)$")
    alter_id: int | None = Field(default=None, ge=0, le=65535)
    plugin: str | None = None
    plugin_opts: str | None = None
    tls: bool = False
    tls_server_name: str | None = None
    tls_insecure: bool = False
    transport: dict | None = None
    reality_public_key: str | None = None
    reality_short_id: str | None = None
    username: str | None = None
    flow: str | None = Field(default=None, pattern=r"^xtls-rprx-vision$")
    tls_utls_fingerprint: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    obfs_type: str | None = Field(default=None, pattern=r"^salamander$")
    obfs_password: EncryptedSecret | None = None
    # Optional local administrative endpoint. A non-loopback bind is an open
    # administrative inbound and is rejected by validators by default.
    admin_listen: str | None = None

    @model_validator(mode="after")
    def check_fields(self):
        if self.type in ("direct", "block"):
            if any((self.server, self.port, self.secret, self.tls, self.admin_listen)):
                raise ValueError("proxy.outbound_local_fields")
            return self
        if not self.server or self.port is None:
            raise ValueError("proxy.outbound_server_required")
        if self.flow is not None and self.type != "vless":
            raise ValueError("proxy.outbound_flow_invalid")
        if (self.reality_public_key or self.tls_utls_fingerprint) and not self.tls:
            raise ValueError("proxy.outbound_tls_required")
        if self.reality_short_id and not self.reality_public_key:
            raise ValueError("proxy.outbound_reality_key_required")
        if (self.obfs_type or self.obfs_password) and (
            self.type != "hysteria2" or not self.obfs_type or not self.obfs_password
        ):
            raise ValueError("proxy.outbound_obfs_invalid")
        return self


class ProxySubscription(Model):
    name: Name
    url: str
    format: Literal["auto", "sing-box", "clash", "v2ray", "base64"] = "auto"
    interval_hours: int = Field(default=24, ge=1, le=168)
    enabled: bool = False
    mode: Literal["selector", "urltest"] = "selector"
    url_test: str | None = None
    test_interval_minutes: int | None = Field(default=None, ge=1, le=1440)
    test_tolerance_ms: int | None = Field(default=None, ge=0, le=5000)
    headers: tuple[str, ...] = ()
    filter_include: str | None = None
    filter_exclude: str | None = None
    active_member: str | None = None
    excluded_members: tuple[str, ...] = ()
    inline: bool = False
    inline_content: str | None = None

    @model_validator(mode="after")
    def check_source(self):
        import re
        if self.inline and not self.inline_content:
            raise ValueError("proxy.subscription_inline_content_required")
        if not self.inline and self.inline_content is not None:
            raise ValueError("proxy.subscription_inline_content_unexpected")
        for header in self.headers:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\r\n]*[^\s\r\n]", header):
                raise ValueError("proxy.subscription_header_invalid")
        for pattern in (self.filter_include, self.filter_exclude):
            if pattern is not None:
                try:
                    re.compile(pattern)
                except re.error:
                    raise ValueError("proxy.subscription_filter_invalid") from None
        return self


class ProxyGroup(Model):
    tag: Name
    type: Literal["selector", "urltest"]
    outbounds: tuple[Name, ...] = ()
    url: str | None = None
    interval_minutes: int | None = Field(default=None, ge=1, le=1440)
    tolerance_ms: int | None = Field(default=None, ge=0, le=5000)


class ProxySettings(Model):
    """Outbounds, subscriptions and groups for the future sing-box engine.
    Off and empty by default; nothing here is fetched or applied yet, and
    enabling it does not open TProxy."""
    enabled: bool = False
    outbounds: tuple[ProxyOutbound, ...] = ()
    subscriptions: tuple[ProxySubscription, ...] = ()
    groups: tuple[ProxyGroup, ...] = ()


class RuleSetSource(Model):
    """A *declared* rule-set source profile — a read-only web contract.

    Off and empty by default; it carries no secret (a source is a name, a
    format, an https URL and caps) and nothing here is fetched or applied by
    this contract. The agent downloader owns fetching, SSRF policy, format
    validation and status; this model only lets the panel/contract describe
    which sources exist, with strict validation at the boundary so a malformed
    declaration is rejected before any fetch is considered.
    """
    name: EngineTag
    format: Literal["text-domain", "text-cidr", "json", "geosite", "geoip", "srs"]
    url: str
    max_records: int = Field(default=200_000, ge=1, le=5_000_000)
    max_bytes: int = Field(default=5_000_000, ge=1024, le=50_000_000)

    @model_validator(mode="after")
    def check_url(self):
        if not self.url.lower().startswith("https://"):
            raise ValueError("ruleset.https_required")
        return self


class Exit(Model):
    """Product egress: direct internet, bound interface, outbound, group, tunnel or block.

    Outbound/group require exactly one tag, tunnel exactly one name, and
    interface exactly one interface field. Direct/block carry no target fields;
    fields belonging to another kind are forbidden.
    """
    kind: Literal['direct', 'interface', 'outbound', 'group', 'tunnel', 'block'] = 'direct'
    #: ProxyOutbound or ProxyGroup tag, required for outbound/group only.
    tag: Name | None = None
    #: Client Tunnel name, required for tunnel only.
    name: Name | None = None
    #: Host interface name, required for interface only.
    interface: InterfaceName | None = None

    @model_validator(mode="after")
    def check_fields(self):
        if ((self.kind not in ('outbound', 'group') and self.tag is not None)
                or (self.kind != 'tunnel' and self.name is not None)
                or (self.kind != 'interface' and self.interface is not None)):
            raise ValueError('routing.exit_fields_unexpected')
        if self.kind == 'outbound' and self.tag is None:
            raise ValueError('routing.outbound_tag_required')
        if self.kind == 'tunnel' and self.name is None:
            raise ValueError('routing.tunnel_name_required')
        if ((self.kind == 'group' and self.tag is None)
                or (self.kind == 'interface' and self.interface is None)):
            raise ValueError('routing.exit_field_required')
        return self


class RoutingSubject(Model):
    """Traffic from the server, a subscriber device, or an interface's sources.

    Server has no reference fields; device requires subscriber and peer only;
    interface requires exactly one interface field and no device fields.
    """
    kind: Literal['server', 'device', 'interface'] = 'server'
    subscriber: Name | None = None
    peer: Name | None = None
    interface: InterfaceName | None = None

    @model_validator(mode="after")
    def check_fields(self):
        if ((self.kind != 'device' and (self.subscriber is not None or self.peer is not None))
                or (self.kind != 'interface' and self.interface is not None)):
            raise ValueError('routing.subject_fields_unexpected')
        if self.kind == 'device' and (self.subscriber is None or self.peer is None):
            raise ValueError('routing.device_required')
        if self.kind == 'interface' and self.interface is None:
            raise ValueError('routing.exit_field_required')
        return self


class RoutingRule(Model):
    name: Name
    subject: RoutingSubject = Field(default_factory=RoutingSubject)
    ip_cidr: tuple[str, ...] = ()
    domain_suffix: tuple[str, ...] = ()
    domain_exact: tuple[str, ...] = ()
    exit: Exit = Field(default_factory=Exit)

    @model_validator(mode="after")
    def check_destination(self):
        from ipaddress import ip_network
        if not (self.ip_cidr or self.domain_suffix or self.domain_exact):
            raise ValueError('routing.destination_required')
        for cidr in self.ip_cidr:
            try:
                ip_network(cidr)
            except ValueError:
                raise ValueError('routing.ip_cidr_invalid') from None
        if any(not re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+", domain)
               for domain in (*self.domain_suffix, *self.domain_exact)):
            raise ValueError('routing.domain_invalid')
        return self


class Configuration(Model):
    schema_version: Literal[1] = 1
    interfaces: tuple[Interface, ...] = ()
    static_routes: tuple[StaticRoute, ...] = ()
    aliases: tuple[Alias, ...] = ()
    dhcp_subnets: tuple[DHCPSubnet, ...] = ()
    firewall_rules: tuple[FirewallRule, ...] = ()
    port_forwards: tuple[PortForward, ...] = ()
    outbound_nat_mode: Literal["automatic", "hybrid", "manual", "disabled"] = "hybrid"
    outbound_nat: tuple[OutboundNAT, ...] = ()
    dns: DNS = Field(default_factory=DNS)
    tunnels: tuple[Tunnel, ...] = ()
    sites: tuple[CaddySite, ...] = ()
    ddns: tuple[DDNSUpdate, ...] = ()
    ssh: SSH = Field(default_factory=SSH)
    tproxy: TProxy = Field(default_factory=TProxy)
    proxies: ProxySettings = Field(default_factory=ProxySettings)
    rule_sets: tuple[RuleSetSource, ...] = ()
    anti_lockout: bool = True
    panel_port: Port = 443
    subscribers: tuple[Subscriber, ...] = ()
    routing_rules: tuple[RoutingRule, ...] = ()

    @model_validator(mode="after")
    def validate_domain(self):
        from .validators import validate_configuration
        validate_configuration(self)
        return self


class ConfigurationVersion(Model):
    id: int = Field(default=1, ge=1)
    profile: Profile = 'router'
    status: Literal["draft", "confirmed"] = "draft"
    configuration: Configuration = Field(default_factory=Configuration)
    created_at: datetime | None = None
