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
  addressing: "static" | "dhcp";
  addresses: string[];
  parent: string | null;
  vlan_id: number | null;
  members: string[];
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
  protocol: "any" | "tcp" | "udp" | "icmp" | "ipv6-icmp";
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
export interface DNS {
  interfaces: string[];
  access_control: string[];
  records: {
    name: string;
    type: "A" | "AAAA" | "CNAME" | "PTR" | "TXT" | "MX";
    value: string;
    ttl: number;
  }[];
  forwards: { domain: string; upstreams: string[] }[];
  upstreams: string[];
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
  keepalive: number;
  obfuscation: Record<string, number>;
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
  ip_cidr: string[];
  action: "direct" | "block";
  order: number;
}
export interface TProxy {
  enabled: boolean;
  ingress_interfaces: string[];
  rules: TProxyRule[];
  final: "direct";
  update_schedule: TProxyUpdateSchedule;
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
    | "tuic";
  server: string | null;
  port: number | null;
  secret: Secret | null;
  tls: boolean;
  tls_server_name: string | null;
  tls_insecure: boolean;
  admin_listen: string | null;
}
export interface ProxySubscription {
  name: string;
  url: string;
  format: "auto" | "sing-box" | "clash" | "v2ray" | "base64";
  interval_hours: number;
  enabled: boolean;
}
export interface ProxyGroup {
  tag: string;
  type: "selector" | "urltest";
  outbounds: string[];
  url: string | null;
  interval_minutes: number | null;
}
export interface ProxySettings {
  enabled: boolean;
  outbounds: ProxyOutbound[];
  subscriptions: ProxySubscription[];
  groups: ProxyGroup[];
}
export interface TProxyPreview {
  version_id: number;
  singbox: Record<string, unknown>;
}
export interface Configuration {
  schema_version: 1;
  interfaces: Interface[];
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
  anti_lockout: boolean;
  panel_port: number;
}
export interface ConfigurationVersion {
  id: number;
  status: "draft" | "confirmed";
  configuration: Configuration;
  created_at?: string | null;
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
