import type { Configuration } from "./types";
export const emptyConfiguration: Configuration = {
  schema_version: 1,
  interfaces: [],
  aliases: [],
  dhcp_subnets: [],
  firewall_rules: [],
  port_forwards: [],
  outbound_nat_mode: "hybrid",
  outbound_nat: [],
  dns: {
    interfaces: [],
    access_control: [],
    records: [],
    forwards: [],
    upstreams: [],
    recursive: false,
    log_queries: false,
  },
  tunnels: [],
  sites: [],
  ddns: [],
  ssh: { interfaces: [], wan_confirmed_interfaces: [] },
  anti_lockout: true,
  panel_port: 443,
};
/** Minimal WireGuard configuration used only by tests. */
export const sampleConfiguration: Configuration = {
  ...emptyConfiguration,
  tunnels: [{
    name: "wg-office",
    interface: "wg-office",
    role: "server",
    protocol: "wg",
    private_key: { redacted: true },
    listen_port: 51820,
    endpoint: null,
    server_public_key: null,
    allowed_ips: ["10.8.0.0/24"],
    keepalive: 0,
    obfuscation: {},
    peers: [{
      name: "alina-laptop",
      public_key: "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
      preshared_key: null,
      allowed_ips: ["10.8.0.2/32"],
    }],
  }],
};
export interface Lease {
  ip: string;
  mac: string;
  hostname: string;
  subnet: string;
  expires: string;
}
export interface RouterEvent {
  time: string;
  type: "green" | "purple" | "blue" | "red";
  label: string;
  message: string;
}
