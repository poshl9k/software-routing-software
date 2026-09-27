/** Hand-maintained mirror of backend/src/vs_router/schema.py. Secrets stay opaque. */
export type Secret =
  { redacted: true } | { encrypted: true; ciphertext: string }
  | { plaintext: string }; // Write-only API input; encrypted by the server.
export interface Interface {
  name: string;
  type: "physical" | "bridge" | "vlan";
  zone: string | null;
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
  anti_lockout: boolean;
  panel_port: number;
}
export interface ConfigurationVersion {
  id: number;
  status: "draft" | "confirmed";
  configuration: Configuration;
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
}
/** Agent RPC status shape; currently not exposed over HTTP. */
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
