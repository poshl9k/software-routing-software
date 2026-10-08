"""Versioned JSON contract. References use names, aliases use an explicit @ prefix."""
from datetime import datetime
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

Name = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_]{0,30}$")]
InterfaceName = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$")]
Port = Annotated[int, Field(ge=1, le=65535)]


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
    addressing: Literal["static", "dhcp"] = "static"
    addresses: tuple[str, ...] = ()
    parent: InterfaceName | None = None
    vlan_id: int | None = Field(default=None, ge=1, le=4094)
    members: tuple[InterfaceName, ...] = ()


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
    protocol: Literal["any", "tcp", "udp", "icmp", "ipv6-icmp"] = "any"
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


class Peer(Model):
    name: Name
    public_key: str
    preshared_key: EncryptedSecret | None = None
    # Filled when the panel generated the peer keypair (client config export);
    # empty when the client brings its own key pair and shares only the public one.
    private_key: EncryptedSecret | None = None
    allowed_ips: tuple[str, ...] = ()


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
    keepalive: int = Field(default=0, ge=0, le=65535)
    obfuscation: dict[str, int] = Field(default_factory=dict)
    # Server only: open udp/<listen_port> on the WAN zone so remote clients can
    # reach the server. The panel shows the generated rule on the Firewall page.
    open_port: bool = True

    @model_validator(mode="after")
    def check_role(self):
        # A server may carry an explicit public endpoint (IP or hostname) that is
        # advertised to its clients; without it the WAN address is used, else a
        # template. server_public_key belongs to a client only.
        if self.role == "server" and (self.server_public_key or self.listen_port is None):
            raise ValueError("tunnel.server_fields")
        if self.role == "client" and (self.peers or not self.endpoint or not self.server_public_key):
            raise ValueError("tunnel.client_fields")
        if self.protocol == "awg" and not {"Jc", "S1", "S2", "H1", "H2", "H3", "H4"} <= self.obfuscation.keys():
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
    ip_cidr: tuple[str, ...] = ()
    source_ip_cidr: tuple[str, ...] = ()
    rule_sets: tuple[Name, ...] = ()
    protocol: Literal["any", "tcp", "udp"] = "any"
    ports: tuple[str, ...] = ()
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
        if not any((self.domain_suffix, self.ip_cidr, self.source_ip_cidr,
                    self.rule_sets, self.ports)):
            raise ValueError("tproxy.rule_matcher_required")
        if any(not re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+", domain)
               for domain in self.domain_suffix):
            raise ValueError("tproxy.domain_invalid")
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


class TProxy(Model):
    enabled: bool = False
    ingress_interfaces: tuple[InterfaceName, ...] = ()
    rules: tuple[TProxyRule, ...] = ()
    bypass: tuple[TProxyBypass, ...] = ()
    final: Literal["direct", "block", "route"] = "direct"
    final_outbound: Name | None = None
    update_schedule: TProxyUpdateSchedule = Field(default_factory=TProxyUpdateSchedule)

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
                  "trojan", "hysteria2", "tuic"]
    server: str | None = None
    port: Port | None = None
    secret: EncryptedSecret | None = None
    tls: bool = False
    tls_server_name: str | None = None
    tls_insecure: bool = False
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
        return self


class ProxySubscription(Model):
    name: Name
    url: str
    format: Literal["auto", "sing-box", "clash", "v2ray", "base64"] = "auto"
    interval_hours: int = Field(default=24, ge=1, le=168)
    enabled: bool = False


class ProxyGroup(Model):
    tag: Name
    type: Literal["selector", "urltest"]
    outbounds: tuple[Name, ...] = ()
    url: str | None = None
    interval_minutes: int | None = Field(default=None, ge=1, le=1440)


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
    name: str = Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_]{0,30}$")
    format: Literal["text-domain", "text-cidr", "json", "geosite", "geoip", "srs"]
    url: str
    max_records: int = Field(default=200_000, ge=1, le=5_000_000)
    max_bytes: int = Field(default=5_000_000, ge=1024, le=50_000_000)

    @model_validator(mode="after")
    def check_url(self):
        if not self.url.lower().startswith("https://"):
            raise ValueError("ruleset.https_required")
        return self


class Configuration(Model):
    schema_version: Literal[1] = 1
    interfaces: tuple[Interface, ...] = ()
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

    @model_validator(mode="after")
    def validate_domain(self):
        from .validators import validate_configuration
        validate_configuration(self)
        return self


class ConfigurationVersion(Model):
    id: int = Field(default=1, ge=1)
    status: Literal["draft", "confirmed"] = "draft"
    configuration: Configuration = Field(default_factory=Configuration)
    created_at: datetime | None = None
