/** Hand-maintained mirror of backend/src/vs_router/schema.py. Secrets stay opaque. */
export type Secret =
  { redacted: true } | { encrypted: true; ciphertext: string }
  | { plaintext: string }; // Write-only API input; encrypted by the server.
export interface Interface {
  name: string;
  type: "physical" | "bridge" | "vlan";
  zone: string | null;
  /** Free-form operator note / friendly label; UI-only, never generated. */
  description: string | null;
  /** static: addresses are configured; dhcp: this interface is a DHCPv4 client. */
  addressing: "static" | "dhcp" | "pppoe";
  pppoe_username?: string | null;
  pppoe_password?: Secret | null;
  addresses: string[];
  parent: string | null;
  vlan_id: number | null;
  members: string[];
}
export interface StaticRoute {
  destination: string;
  interface: string;
  gateway: string | null;
  metric: number;
  enabled: boolean;
}
export interface Alias {
  name: string;
  type: "address" | "port";
  elements: string[];
  includes: string[];
}
export interface Reservation {
  hw_address: string;
  ip_address: string;
  hostname: string | null;
}
export interface DHCPSubnet {
  id: number;
  interface: string;
  subnet: string;
  pools: { start: string; end: string }[];
  reservations: Reservation[];
  routers: string[];
  dns_servers: string[];
  valid_lifetime: number;
}
export interface FirewallRule {
  name: string;
  ingress_zone: string;
  protocol: "any" | "tcp" | "udp" | "tcp_udp" | "icmp" | "ipv6-icmp";
  src: string;
  dst: string;
  destination_ports: string | null;
  action: "pass" | "block" | "reject";
  order: number;
  enabled: boolean;
  log: boolean;
  counters: { states: number; packets: number; bytes: number };
}
export interface PortForward {
  name: string;
  interface: string;
  protocol: "tcp" | "udp";
  external_port: number;
  wan_address: string | null;
  target: string;
  target_port: number;
  enabled: boolean;
}
export interface OutboundNAT {
  name: string;
  egress_zone: string;
  src: string;
  dst: string;
  protocol: "any" | "tcp" | "udp" | "icmp";
  translation: string;
  do_not_nat: boolean;
  order: number;
}
export interface DNSUpstream {
  address: string;
  port: number;
  mode: "udp" | "tls" | "https";
  tls_name: string | null;
  doh_server: string | null;
}
export interface DNS {
  interfaces: string[];
  access_control: string[];
  records: {
    name: string;
    type: "A" | "AAAA" | "CNAME" | "PTR" | "TXT" | "MX";
    value: string;
    ttl: number;
  }[];
  forwards: { domain: string; upstreams: DNSUpstream[] }[];
  upstreams: DNSUpstream[];
  recursive: boolean;
  log_queries: boolean;
}
export interface Peer {
  name: string;
  public_key: string;
  preshared_key: Secret | null;
  private_key?: Secret | null;
  allowed_ips: string[];
}
export interface Tunnel {
  name: string;
  interface: string;
  role: "server" | "client";
  protocol: "wg" | "awg";
  private_key: Secret;
  listen_port: number | null;
  peers: Peer[];
  endpoint: string | null;
  server_public_key: string | null;
  allowed_ips: string[];
  /** Seconds, or an AWG 3+ "min-max" range. */
  keepalive: number | string;
  /** AmneziaWG parameters: uint32s / "min-max" ranges, or I1-I5 signature strings. */
  obfuscation: Record<string, number | string>;
  /** Client only: the remote peer's preshared secret. */
  preshared_key: Secret | null;
  /** AmneziaWG 3+ header protection key (must match the remote end). */
  header_protection_key: Secret | null;
  random_trailers: boolean;
  disable_cookies: boolean;
  /** Server only: open udp/<listen_port> on the WAN zone (generated firewall rule). */
  open_port: boolean;
}
export interface CaddySite {
  name: string;
  hostname: string;
  upstream: string;
  certificate_mode: "http01" | "dns01" | "manual" | "passthrough";
  wan_address: string | null;
  certificate: Secret | null;
  private_key: Secret | null;
  dns_api_token: Secret | null;
}
export interface DDNSUpdate {
  name: string;
  provider: "cloudflare" | "rfc2136";
  hostname: string;
  zone: string | null;
  server: string | null;
  key_name: string | null;
  api_token: Secret;
  wan_interface: string;
}
export interface TProxyUpdateSchedule {
  mode: "interval" | "window";
  interval_hours: number;
  window_start: string;
  window_end: string;
}
export interface TProxyRule {
  name: string;
  domain_suffix: string[];
  domain_exact?: string[];
  domain_keyword?: string[];
  domain_regex?: string[];
  ip_cidr: string[];
  source_ip_cidr: string[];
  source_mac?: string[];
  inbound?: string[];
  ip_is_private?: boolean | null;
  network?: "tcp" | "udp" | null;
  rule_sets: string[];
  protocol: "any" | "tcp" | "udp";
  ports: string[];
  logical_mode?: "and" | "or" | null;
  logical_rules?: TProxyRule[];
  action: "direct" | "block" | "route";
  outbound: string | null;
  order: number;
}
export interface TProxyBypass {
  name: string;
  source_ip_cidr: string[];
  ip_cidr: string[];
  ports: string[];
  protocol: "any" | "tcp" | "udp";
}
export interface TProxyDNSServer {
  tag: string;
  type: "udp" | "tls" | "https";
  server: string;
  server_port: number | null;
  tls_name: string | null;
  path: string | null;
  domain_resolver: string | null;
  detour: string | null;
}
export interface TProxyDNSRule {
  name: string;
  domain_suffix: string[];
  rule_sets: string[];
  server: string;
}
export interface TProxyDNS {
  servers: TProxyDNSServer[];
  rules: TProxyDNSRule[];
}
export interface TProxy {
  enabled: boolean;
  ingress_interfaces: string[];
  rules: TProxyRule[];
  bypass: TProxyBypass[];
  dns: TProxyDNS;
  final: "direct" | "block" | "route";
  final_outbound: string | null;
  update_schedule: TProxyUpdateSchedule;
  sniff?: boolean;
  udp_timeout_seconds?: number | null;
}
export interface ProxyOutbound {
  tag: string;
  type:
    | "direct"
    | "block"
    | "shadowsocks"
    | "vmess"
    | "vless"
    | "trojan"
    | "hysteria2"
    | "tuic"
    | "naive"
    | "mieru";
  server: string | null;
  port: number | null;
  secret: Secret | null;
  method: string | null;
  tls: boolean;
  tls_server_name: string | null;
  tls_insecure: boolean;
  transport?: { type: "http" | "ws" | "grpc" | "httpupgrade"; path?: string; host?: string | string[]; service_name?: string } | null;
  reality_public_key?: string | null;
  reality_short_id?: string | null;
  username?: string | null;
  flow?: string | null;
  tls_utls_fingerprint?: string | null;
  security?: string | null;
  alter_id?: number | null;
  password?: Secret | null;
  uuid?: Secret | null;
  plugin?: string | null;
  plugin_opts?: string | null;
  obfs_type?: string | null;
  obfs_password?: Secret | null;
  admin_listen: string | null;
}
// Subscription runtime (agent proposals; no implicit draft write).
export interface SubscriptionMember {
  tag: string;
  label: string;
  protocol: string;
  server: string;
  port: number;
  sni?: string | null;
  transport?: string | null;
  security?: string | null;
  excluded?: boolean;
}
export interface SubscriptionPreview {
  members: SubscriptionMember[];
  skipped: { line: number; reason: string }[];
  outbounds: ProxyOutbound[];
  groups: ProxyGroup[];
}
export interface SubscriptionRefresh {
  added: SubscriptionMember[];
  updated: SubscriptionMember[];
  unchanged: SubscriptionMember[];
  orphans: SubscriptionMember[];
  skipped: { line: number; reason: string }[];
  outbounds: ProxyOutbound[];
  groups: ProxyGroup[];
}

export interface ProxySubscription {
  name: string;
  url: string;
  format: "auto" | "sing-box" | "clash" | "v2ray" | "base64";
  interval_hours: number;
  enabled: boolean;
  mode?: "selector" | "urltest";
  url_test?: string | null;
  test_interval_minutes?: number | null;
  test_tolerance_ms?: number | null;
  headers?: string[];
  filter_include?: string | null;
  filter_exclude?: string | null;
  active_member?: string | null;
  excluded_members?: string[];
  inline?: boolean;
  inline_content?: string | null;
}
export interface ProxyGroup {
  tag: string;
  type: "selector" | "urltest";
  outbounds: string[];
  url: string | null;
  interval_minutes: number | null;
  tolerance_ms?: number | null;
}
export interface ProxySettings {
  enabled: boolean;
  outbounds: ProxyOutbound[];
  subscriptions: ProxySubscription[];
  groups: ProxyGroup[];
}
/** Declared rule-set source profile; read-only, secret-free (mirrors schema.py). */
export interface RuleSetSource {
  name: string;
  format: "text-domain" | "text-cidr" | "json" | "geosite" | "geoip" | "srs";
  url: string;
  max_records: number;
  max_bytes: number;
}
/** A rule-set source joined with its agent-owned update status (read-only). */
export interface RuleSetStatus {
  name: string;
  format: string | null;
  url: string | null;
  kind: string;
  status: "never" | "ok" | "failed" | "not_modified";
  stale: boolean;
  last_attempt: number | null;
  last_success: number | null;
  sha256: string | null;
  declared: boolean;
}
export interface RuleSetUpdate {
  name: string;
  url: string;
  kind?: "rule_set" | "subscription";
  format?: "auto" | "sing-box" | "clash" | "v2ray" | "base64" | "json" | "rule-set" | "text" | "srs";
  authorized?: boolean;
  max_bytes?: number;
  timeout?: number;
}
/** Read-only service catalog returned by the panel; URLs are declarations, not browser downloads. */
export interface CatalogService {
  id: string;
  name: string;
  category: string;
  icon_slug: string;
  notice: string | null;
  covers: string[];
  dns_domains: string[];
  rule_sets: { tag: string; url: string; format: RuleSetSource["format"] }[];
  action: string;
  declared: boolean;
}
export interface CatalogResponse {
  categories: { key: string; title: string; count: number }[];
  services: CatalogService[];
}

export interface TProxyPreview {
  version_id: number;
  singbox: Record<string, unknown>;
}
export interface Configuration {
  schema_version: 1;
  interfaces: Interface[];
  /** Optional in legacy snapshots; backend defaults to an empty tuple. */
  static_routes?: StaticRoute[];
  aliases: Alias[];
  dhcp_subnets: DHCPSubnet[];
  firewall_rules: FirewallRule[];
  port_forwards: PortForward[];
  outbound_nat_mode: "automatic" | "hybrid" | "manual" | "disabled";
  outbound_nat: OutboundNAT[];
  dns: DNS;
  tunnels: Tunnel[];
  sites: CaddySite[];
  ddns: DDNSUpdate[];
  ssh: { interfaces: string[]; wan_confirmed_interfaces: string[] };
  tproxy: TProxy;
  proxies: ProxySettings;
  rule_sets: RuleSetSource[];
  anti_lockout: boolean;
  panel_port: number;
}
export interface ConfigurationVersion {
  id: number;
  status: "draft" | "confirmed";
  configuration: Configuration;
  created_at?: string | null;
}
export interface DiffChange {
  op: "add" | "remove" | "replace";
  path: string;
  before?: unknown;
  after?: unknown;
}
export interface DiffSummary {
  area: string;
  title: string;
  added: number;
  removed: number;
  changed: number;
  consequences: string[];
}
export interface DiffResponse {
  changes: DiffChange[];
  summary: DiffSummary[];
}
export interface ErrorBody {
  code: string;
  message: string;
  details: unknown[];
}
export interface DHCPLease {
  ip: string; mac: string; hostname: string | null; subnet: string;
  cltt: number; valid_lft: number; expires_in: number;
}
export interface ImportPreview { ok: boolean; errors: { line: number; message: string }[]; aliases: Alias[] }
export interface PingResult { sent: number; received: number; loss_pct: number; min_avg_max_ms: number[] }
export interface ApplyResult {
  version_id: number;
  status:
    | "applying"
    | "pending"
    | "confirmed"
    | "rolling_back"
    | "rolled_back"
    | "failed"
    | "rollback_failed";
  phases?: Record<string, string>;
  error?: ErrorBody | null;
  /** Why a rolled_back result happened (agent marker) and which service broke. */
  reason?: string | null;
  reason_service?: string | null;
}
/** Host-owned agent marker returned by GET /api/apply/status. */
export interface ApplyMarker extends ApplyResult {
  applied_at: number;
  deadline: number | null;
}
/** Read-only runtime state from the agent; not a configuration or apply status. */
export interface ServiceStatus {
  name: string;
  state: "running" | "stopped" | "unknown";
  detail: string | null;
}
export interface ServiceStatusResponse {
  generated_at: string;
  services: ServiceStatus[];
}
export interface ApplyRequest {
  version_id: number;
  safe_mode: boolean;
  confirmation_timeout: number;
}
export interface User {
  id: number;
  username: string;
  role: "admin" | "operator";
}
export interface Credentials {
  username: string;
  password: string;
}

export interface HostInterface {
  name: string;
  kind: "physical" | "vlan" | "bridge" | "bond";
  parent: string | null;
  operstate: string;
  mac: string | null;
}

/** First-run management endpoint; `single-uplink` means the one port is also the uplink. */
export interface HostManagement {
  interface: string;
  mac: string;
  address: string;
  mode: "separate-lan" | "single-uplink";
  hostname: string | null;
  path_prefix: string | null;
}

export interface ReleaseInfo {
  commit: string | null;
  semver: string | null;
  installed_at: string | null;
  source: "iso" | "online" | "unknown";
}
export interface UpdateRun {
  status: "running" | "success" | "failed";
  release: string | null;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
}
export interface UpdateStatus {
  configured: boolean;
  manifest_url: string | null;
  current: ReleaseInfo;
  available: { commit: string; semver: string } | null;
  update_available: boolean;
  running: boolean;
  last: UpdateRun | null;
  error: string | null;
}
export interface UpdateStart {
  started: boolean;
  release: string;
}

// Runtime agent DTOs (backend agent/engine.py and agent/clash.py; separate from configuration).
export interface RuntimeEngine {
  installed: boolean;
  version: string | null;
  running: boolean;
  pid: number | null;
  clash_api: boolean;
  ip_forward: boolean | null;
  nft_tproxy_tables: boolean;
}
export interface RuntimeConnection {
  id: string;
  metadata?: {
    network?: string;
    type?: string;
    sourceIP?: string;
    sourcePort?: string | number;
    destinationIP?: string;
    destinationPort?: string | number;
    host?: string;
  };
  upload?: number;
  download?: number;
  start?: string;
  chains?: string[];
  rule?: string;
  rulePayload?: string;
}
export interface RuntimeConnections {
  download: number;
  upload: number;
  connections: RuntimeConnection[] | null;
}
export interface RuntimeLogEntry {
  type?: string;
  payload?: string;
  source?: string;
  time?: string;
}
export interface RuntimeProxies {
  proxies: Record<string, {
    name?: string;
    type?: string;
    now?: string;
    all?: string[];
    history?: { time?: string; delay?: number }[];
  }>;
}
export interface RuntimeProxyDelay { delay: number }
