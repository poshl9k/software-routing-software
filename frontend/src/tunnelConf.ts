import type { Tunnel } from "./types";

export type ImportedTunnel = { tunnel: Partial<Tunnel>; error?: never };
export type ImportFailure = { tunnel?: never; error: string };

const wgKey = /^[A-Za-z0-9+/]{43}=$/;
const awgKeys = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"] as const;

function ipv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
}

function ipv6(value: string): boolean {
  if (!value.includes(":")) return false;
  try {
    // URL's host parser validates IPv6 (including compressed and IPv4-mapped forms).
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function address(value: string): boolean {
  return ipv4(value) || ipv6(value);
}

function allowedIP(value: string): boolean {
  const parts = value.split("/");
  if (parts.length > 2 || !address(parts[0])) return false;
  if (parts.length === 1) return true;
  const max = ipv4(parts[0]) ? 32 : 128;
  return /^(0|[1-9][0-9]{0,2})$/.test(parts[1]) && Number(parts[1]) <= max;
}

function endpoint(value: string): boolean {
  const match = value.match(/^(\[[^\]]+\]|[^:\s\[\]]+):([0-9]+)$/);
  if (!match) return false;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  const host = match[1];
  if (host.startsWith("[")) return ipv6(host.slice(1, -1));
  if (/^[0-9.]+$/.test(host)) return ipv4(host);
  return host.length <= 253 && host.split(".").every((label) =>
    label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
}

function list(value: string): string[] {
  return value.split(",").map((part) => part.trim());
}

/** Parse a single client configuration locally; no I/O or secret logging. */
export function parseWireGuardConf(text: string): ImportedTunnel | ImportFailure {
  if (typeof text !== "string") return { error: "Некорректный конфиг" };
  const sections: Record<string, string>[] = [];
  const peers: Record<string, string>[] = [];
  let current: Record<string, string> | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split(/[;#]/, 1)[0].trim();
    if (!line) continue;
    const section = line.match(/^\[([^\]]+)\]$/);
    if (section) {
      const name = section[1].trim().toLowerCase();
      current = name === "interface" || name === "peer" ? {} : undefined;
      if (current && name === "interface") sections.push(current);
      if (current && name === "peer") peers.push(current);
      continue;
    }
    if (!current) continue;
    const delimiter = line.indexOf("=");
    if (delimiter < 0) continue;
    current[line.slice(0, delimiter).trim().toLowerCase()] = line.slice(delimiter + 1).trim();
  }

  if (sections.length !== 1) return { error: "Нужна секция [Interface]" };
  if (peers.length !== 1) return { error: "Нужна одна секция [Peer]" };
  const iface = sections[0];
  const peer = peers[0];
  if (!wgKey.test(iface.privatekey ?? "")) return { error: "Некорректный PrivateKey" };
  if (!wgKey.test(peer.publickey ?? "")) return { error: "Некорректный PublicKey" };
  if (!peer.endpoint || !endpoint(peer.endpoint)) return { error: "Некорректный Endpoint" };
  const ips = list(peer.allowedips ?? "");
  if (ips.some((ip) => !allowedIP(ip))) return { error: "Некорректный AllowedIPs" };
  if (peer.presharedkey !== undefined) {
    return { error: "PresharedKey не поддерживается для клиентского туннеля; импорт невозможен без потери секрета" };
  }
  const keepalive = peer.persistentkeepalive ?? "0";
  if (!/^(0|[1-9][0-9]*)$/.test(keepalive) || !Number.isSafeInteger(Number(keepalive)) || Number(keepalive) > 65535) {
    return { error: "Некорректный PersistentKeepalive" };
  }

  const obfuscation: Record<string, number> = {};
  for (const key of awgKeys) {
    const value = iface[key.toLowerCase()];
    if (value === undefined) continue;
    if (!/^-?(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) {
      return { error: `Некорректный ${key}` };
    }
    obfuscation[key] = Number(value);
  }

  return {
    tunnel: {
      role: "client",
      protocol: Object.keys(obfuscation).length ? "awg" : "wg",
      private_key: { plaintext: iface.privatekey },
      server_public_key: peer.publickey,
      endpoint: peer.endpoint,
      allowed_ips: ips,
      keepalive: Number(keepalive),
      peers: [],
      listen_port: null,
      obfuscation,
    },
  };
}
