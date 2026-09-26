import type { Configuration, Interface, Tunnel } from "./types";
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
  anti_lockout: true,
  panel_port: 443,
};
const iface = (
  name: string,
  zone: string | null,
  addresses: string[],
  type: Interface["type"] = "physical",
): Interface => ({
  name,
  zone,
  addresses,
  type,
  parent: null,
  vlan_id: null,
  members: [],
});
const tunnel = (
  name: string,
  role: Tunnel["role"],
  protocol: Tunnel["protocol"],
): Tunnel => ({
  name,
  interface: name,
  role,
  protocol,
  private_key: { redacted: true },
  listen_port: role === "server" ? 51820 : null,
  endpoint: role === "client" ? "vpn.example.net:51820" : null,
  server_public_key: null,
  allowed_ips: ["10.8.0.0/24"],
  keepalive: role === "client" ? 25 : 0,
  obfuscation:
    protocol === "awg"
      ? { Jc: 4, S1: 88, S2: 1152, H1: 1, H2: 2, H3: 3, H4: 4 }
      : {},
  peers:
    role === "server"
      ? ["alina-laptop", "phone-max", "printer-vpn"].map((name) => ({
          name,
          public_key: "Демонстрационный ключ",
          preshared_key: null,
          allowed_ips: [],
        }))
      : [],
});
/** TODO-API: display-only examples from mockups; never submitted to the router. */
export const demoConfiguration: Configuration = {
  ...emptyConfiguration,
  interfaces: [
    iface("eth0", "wan", [
      "185.23.10.14/24",
      "185.23.10.20/32",
      "185.23.10.21/32",
    ]),
    iface("eth1", "wan", ["203.0.113.10/24"]),
    {
      ...iface("br0", "lan", ["192.168.10.1/24"], "bridge"),
      members: ["eth2", "eth3"],
    },
    {
      ...iface("vlan20", "iot", ["192.168.20.1/24"], "vlan"),
      parent: "br0",
      vlan_id: 20,
    },
    {
      ...iface("vlan30", "guest", ["192.168.30.1/24"], "vlan"),
      parent: "br0",
      vlan_id: 30,
    },
    iface("eth4", null, []),
  ],
  dhcp_subnets: [10, 20, 30].map((n, i) => ({
    id: i + 1,
    interface: i === 0 ? "br0" : `vlan${n}`,
    subnet: `192.168.${n}.0/24`,
    pools: [
      {
        start: `192.168.${n}.${i === 0 ? 100 : i === 1 ? 50 : 20}`,
        end: `192.168.${n}.${i === 0 ? 200 : 250}`,
      },
    ],
    routers: [`192.168.${n}.1`],
    dns_servers: [`192.168.${n}.1`],
    valid_lifetime: 3600,
    reservations:
      i === 0
        ? [
            {
              hostname: "printer",
              hw_address: "AA:BB:CC:10:20:30",
              ip_address: "192.168.10.120",
            },
            {
              hostname: "nas",
              hw_address: "AA:BB:CC:10:20:31",
              ip_address: "192.168.10.10",
            },
          ]
        : [],
  })),
  aliases: [
    {
      name: "rfc1918",
      type: "address",
      elements: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      includes: [],
    },
    {
      name: "web_ports",
      type: "port",
      elements: ["tcp/80", "tcp/443"],
      includes: [],
    },
  ],
  firewall_rules: [
    {
      name: "block_private",
      ingress_zone: "wan",
      protocol: "tcp",
      src: "@rfc1918",
      dst: "router",
      destination_ports: null,
      action: "block",
      order: 0,
      enabled: true,
      log: true,
      counters: { states: 0, packets: 41208, bytes: 0 },
    },
    {
      name: "allow_vpn",
      ingress_zone: "wan",
      protocol: "udp",
      src: "any",
      dst: "router",
      destination_ports: "51820",
      action: "pass",
      order: 1,
      enabled: true,
      log: false,
      counters: { states: 12, packets: 88451, bytes: 0 },
    },
    {
      name: "lan_allow",
      ingress_zone: "lan",
      protocol: "any",
      src: "any",
      dst: "any",
      destination_ports: null,
      action: "pass",
      order: 0,
      enabled: true,
      log: false,
      counters: { states: 0, packets: 0, bytes: 0 },
    },
  ],
  port_forwards: [
    {
      name: "mail",
      interface: "eth0",
      protocol: "tcp",
      external_port: 25,
      wan_address: "185.23.10.20",
      target: "192.168.10.9",
      target_port: 25,
      enabled: true,
    },
  ],
  outbound_nat: [
    {
      name: "mail_snat",
      egress_zone: "wan",
      src: "192.168.10.9",
      dst: "any",
      protocol: "any",
      translation: "185.23.10.20",
      do_not_nat: false,
      order: 0,
    },
  ],
  dns: {
    interfaces: ["br0", "vlan20", "vlan30"],
    access_control: ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"],
    records: [
      { name: "router.home.lan", type: "A", value: "192.168.10.1", ttl: 300 },
      { name: "nas.home.lan", type: "A", value: "192.168.10.10", ttl: 300 },
      { name: "git.home.lan", type: "A", value: "192.168.10.30", ttl: 300 },
      {
        name: "nastya.home.lan",
        type: "CNAME",
        value: "nas.home.lan",
        ttl: 300,
      },
    ],
    forwards: [
      { domain: "alfapi.ru", upstreams: ["192.168.6.253"] },
      { domain: "company.local", upstreams: ["192.168.107.201"] },
    ],
    upstreams: ["1.1.1.1", "8.8.8.8"],
    recursive: false,
    log_queries: true,
  },
  tunnels: [
    tunnel("wg-office", "server", "wg"),
    tunnel("awg-home", "server", "awg"),
    tunnel("wg-to-vps", "client", "wg"),
    tunnel("awg-rvs", "client", "awg"),
  ],
  sites: [
    ["home", "http://192.168.10.10:8123", "http01"],
    ["git", "http://192.168.10.30:3000", "http01"],
    ["nas", "https://192.168.10.50:5001", "manual"],
    ["mail", "192.168.10.9:443", "passthrough"],
    ["wiki", "http://192.168.20.10:8080", "dns01"],
  ].map(([name, upstream, mode]) => ({
    name,
    hostname: `${name}.example.ru`,
    upstream,
    certificate_mode:
      mode as Configuration["sites"][number]["certificate_mode"],
    wan_address: name === "mail" ? "185.23.10.20" : "185.23.10.14",
    certificate: null,
    private_key: null,
    dns_api_token: null,
  })),
};
export interface Lease {
  ip: string;
  mac: string;
  hostname: string;
  subnet: string;
  expires: string;
}
export const demoLeases: Lease[] = [
  {
    ip: "192.168.10.45",
    mac: "AA:BB:CC:09:11:45",
    hostname: "laptop-alina",
    subnet: "LAN",
    expires: "через 3 ч 12 мин",
  },
  {
    ip: "192.168.10.120",
    mac: "AA:BB:CC:10:20:30",
    hostname: "printer",
    subnet: "LAN",
    expires: "резервация",
  },
  {
    ip: "192.168.20.51",
    mac: "AA:BB:CC:20:01:51",
    hostname: "esp-thermo-2",
    subnet: "IoT",
    expires: "через 11 ч",
  },
];
export interface RouterEvent {
  time: string;
  type: "green" | "purple" | "blue" | "red";
  label: string;
  message: string;
}
export const demoEvents: RouterEvent[] = [
  {
    time: "14:22:31",
    type: "purple",
    label: "Профиль",
    message: "Клиент 192.168.10.45 получил адрес по DHCP",
  },
  {
    time: "14:21:58",
    type: "green",
    label: "Успех",
    message: "Резервация для принтера применена",
  },
  {
    time: "14:16:41",
    type: "blue",
    label: "Перезапуск",
    message: "Конфигурация Kea перезагружена без простоя",
  },
  {
    time: "13:57:03",
    type: "red",
    label: "Ошибка",
    message: "Не удалось получить IP от WAN2",
  },
];
