import type { Tunnel } from "./types";

export type ImportedTunnel = { tunnel: Partial<Tunnel>; error?: never };
export type ImportFailure = { tunnel?: never; error: string };

const wgKey = /^[A-Za-z0-9+/]{43}=$/;
// AmneziaWG interface parameters: a uint32 or an inclusive "min-max" range.
const awgNumeric: Record<string, string> = {
  jc: "Jc", jmin: "Jmin", jmax: "Jmax", s1: "S1", s2: "S2", s3: "S3", s4: "S4",
  h1: "H1", h2: "H2", h3: "H3", h4: "H4",
  contentpaddingaddition: "ContentPaddingAddition",
  rekeyaftertime: "RekeyAfterTime", rekeytimeout: "RekeyTimeout",
  rejectaftertime: "RejectAfterTime", keepalivetimeout: "KeepaliveTimeout",
  maxhandshakeattempts: "MaxHandshakeAttempts",
};
// AWG 3+ signature-packet expressions (`I1 = <r 2><b 0x...>`); arbitrary strings.
const awgSignature: Record<string, string> = { i1: "I1", i2: "I2", i3: "I3", i4: "I4", i5: "I5" };
const range = /^[0-9]{1,10}(-[0-9]{1,10})?$/;
const truthy = new Set(["on", "true", "yes", "1"]);
const falsy = new Set(["off", "false", "no", "0"]);

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
  const match = value.match(/^(\[[^\]]+\]|[^:\s[\]]+):([0-9]+)$/);
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

/** An integer stays a number, a "min-max" range becomes a string; null = invalid. */
function numberOrRange(value: string): number | string | null {
  if (!range.test(value)) return null;
  return value.includes("-") ? value : Number(value);
}

function flag(value: string | undefined): boolean {
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  if (truthy.has(normalized)) return true;
  if (falsy.has(normalized)) return false;
  throw new Error("invalid flag");
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
  if (peer.presharedkey !== undefined && !wgKey.test(peer.presharedkey)) {
    return { error: "Некорректный PresharedKey" };
  }
  const keepalive = numberOrRange(peer.persistentkeepalive ?? "0");
  if (keepalive === null) return { error: "Некорректный PersistentKeepalive" };
  const mtu = iface.mtu === undefined ? null : Number(iface.mtu);
  if (iface.mtu !== undefined && (!/^[0-9]+$/.test(iface.mtu) || mtu! < 576 || mtu! > 65535)) {
    return { error: "Некорректный MTU" };
  }

  const obfuscation: Record<string, number | string> = {};
  for (const [key, name] of Object.entries(awgNumeric)) {
    const value = iface[key];
    if (value === undefined) continue;
    const parsed = numberOrRange(value);
    if (parsed === null) return { error: `Некорректный ${name}` };
    obfuscation[name] = parsed;
  }
  for (const [key, name] of Object.entries(awgSignature)) {
    const value = iface[key];
    if (value === undefined) continue;
    if (!value) return { error: `Некорректный ${name}` };
    obfuscation[name] = value;
  }
  const headerProtectionKey = iface.headerprotectionkey;
  if (headerProtectionKey !== undefined && !wgKey.test(headerProtectionKey)) {
    return { error: "Некорректный HeaderProtectionKey" };
  }
  let randomTrailers = false;
  let disableCookies = false;
  try {
    randomTrailers = flag(iface.randomtrailers);
    disableCookies = flag(iface.disablecookies);
  } catch {
    return { error: "Некорректный RandomTrailers/DisableCookies" };
  }
  const isAwg = Object.keys(obfuscation).length > 0
    || headerProtectionKey !== undefined || randomTrailers || disableCookies;

  return {
    tunnel: {
      role: "client",
      protocol: isAwg ? "awg" : "wg",
      private_key: { plaintext: iface.privatekey },
      server_public_key: peer.publickey,
      endpoint: peer.endpoint,
      allowed_ips: ips,
      keepalive,
      mtu,
      preshared_key: peer.presharedkey ? { plaintext: peer.presharedkey } : null,
      header_protection_key: headerProtectionKey ? { plaintext: headerProtectionKey } : null,
      random_trailers: randomTrailers,
      disable_cookies: disableCookies,
      peers: [],
      listen_port: null,
      obfuscation,
    },
  };
}
