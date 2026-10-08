import type { ProxyOutbound } from "./types";
import { hostValid, portValid } from "./components/validators";

export interface ParsedLink {
  /** Safe diagnostic label; never the original credential-bearing URL. */
  link: string;
  outbound?: ProxyOutbound;
  error?: string;
}

type RemoteType = Extract<ProxyOutbound["type"], "shadowsocks" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic">;

function decodeBase64(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.replace(/=+$/, "").length % 4 === 1) {
    throw new Error("invalid base64");
  }
  const bytes = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes, (c) => c.charCodeAt(0)));
}

function required(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new Error("missing field");
  return value;
}

function port(value: unknown): number {
  const text = String(value ?? "");
  if (!/^\d{1,5}$/.test(text) || !portValid(Number(text))) throw new Error("invalid port");
  return Number(text);
}

function makeOutbound(type: RemoteType, tag: string, server: string, serverPort: unknown, password: string, method: string | null, tls: boolean, sni: string | null, insecure: boolean): ProxyOutbound {
  if (!hostValid(server) || !server.trim()) throw new Error("invalid host");
  if (sni && !hostValid(sni)) throw new Error("invalid sni");
  return {
    tag, type, server, port: port(serverPort), secret: { plaintext: required(password) },
    method, tls, tls_server_name: sni, tls_insecure: insecure, admin_listen: null,
  };
}

function boolParam(value: string | null): boolean {
  return value === "1" || value?.toLowerCase() === "true";
}

function uriOutbound(url: URL, tag: string, type: RemoteType): ProxyOutbound {
  const q = url.searchParams;
  const security = (q.get("security") ?? "").toLowerCase();
  if (security && security !== "tls" && security !== "none") throw new Error("unsupported security");
  if (q.has("type") && q.get("type") !== "tcp") throw new Error("unsupported transport");
  if (q.has("plugin") || q.has("flow") || q.has("obfs")) throw new Error("unsupported options");
  const tls = type === "trojan" || type === "hysteria2" || type === "tuic" || security === "tls" || boolParam(q.get("tls"));
  const sni = q.get("sni") || q.get("peer") || q.get("servername") || null;
  const password = decodeURIComponent(url.username);
  if (type === "tuic" && !url.password) throw new Error("missing field");
  return makeOutbound(type, tag, url.hostname, url.port, password, null, tls, sni, boolParam(q.get("allowInsecure")) || boolParam(q.get("insecure")));
}

function ssOutbound(raw: string, tag: string): ProxyOutbound {
  const withoutFragment = raw.split("#", 1)[0];
  const body = withoutFragment.slice(5).split("?", 1)[0];
  if (withoutFragment.includes("?")) throw new Error("unsupported plugin");
  // SIP002: base64(method:password)@host:port, or base64(method:password@host:port).
  const at = body.lastIndexOf("@");
  let credentials: string;
  let authority: string;
  if (at < 0) {
    const decoded = decodeBase64(body);
    const split = decoded.lastIndexOf("@");
    if (split < 0) throw new Error("invalid ss");
    credentials = decoded.slice(0, split);
    authority = decoded.slice(split + 1);
  } else {
    credentials = body.slice(0, at);
    authority = body.slice(at + 1);
    if (!credentials.includes(":")) credentials = decodeBase64(credentials);
  }
  const colon = credentials.indexOf(":");
  if (colon <= 0) throw new Error("invalid ss");
  const method = required(credentials.slice(0, colon));
  const password = required(credentials.slice(colon + 1));
  const url = new URL(`ss://${authority}`);
  return makeOutbound("shadowsocks", tag, url.hostname, url.port, password, method, false, null, false);
}

function vmessOutbound(raw: string, tag: string): ProxyOutbound {
  const payload = raw.slice(8).split("#", 1)[0].split("?", 1)[0];
  const value: unknown = JSON.parse(decodeBase64(payload));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid vmess");
  const data = value as Record<string, unknown>;
  if ((data.net && data.net !== "tcp") || (data.type && data.type !== "none") || data.path || data.host) throw new Error("unsupported transport");
  const tlsValue = String(data.tls ?? "").toLowerCase();
  if (tlsValue && !["tls", "none", "0", "1", "true", "false"].includes(tlsValue)) throw new Error("unsupported security");
  return makeOutbound("vmess", tag, required(data.add), data.port, required(data.id), null,
    tlsValue === "tls" || tlsValue === "1" || tlsValue === "true", typeof data.sni === "string" ? data.sni || null : null,
    data.allowInsecure === true || data.allowInsecure === 1 || data.allowInsecure === "1" || data.allowInsecure === "true");
}

function fragmentTag(raw: string): string | null {
  const hash = raw.indexOf("#");
  if (hash < 0 || !raw.slice(hash + 1)) return null;
  return decodeURIComponent(raw.slice(hash + 1));
}

/** Coerce any display name to the contract's `Name` (^[A-Za-z][A-Za-z0-9_]{0,30}$). */
function safeTag(name: string): string {
  const cleaned = name.trim().replace(/[^a-zA-Z0-9_]/g, "_");
  const prefixed = /^[a-zA-Z]/.test(cleaned) ? cleaned : `t_${cleaned}`;
  return (prefixed.replace(/_+$/, "") || "imported").slice(0, 31);
}

/** Parse one share URL. Both the display label and errors are credential-free. */
export function parseShareLink(link: string, tag: string): ParsedLink {
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(link)?.[1]?.toLowerCase();
  const safeLink = `${scheme && /^[a-z][a-z0-9+.-]*$/.test(scheme) ? scheme : "unknown"}://[скрыто]`;
  try {
    if (!scheme || !["ss", "vmess", "vless", "trojan", "hysteria2", "hy2", "tuic"].includes(scheme)) {
      throw new Error("unsupported scheme");
    }
    const name = safeTag(fragmentTag(link) || tag);
    if (!name) throw new Error("missing tag");
    let outbound: ProxyOutbound;
    if (scheme === "ss") outbound = ssOutbound(link, name);
    else if (scheme === "vmess") outbound = vmessOutbound(link, name);
    else outbound = uriOutbound(new URL(link), name, scheme === "hy2" ? "hysteria2" : scheme as RemoteType);
    return { link: safeLink, outbound };
  } catch {
    return { link: safeLink, error: "Некорректная или неподдерживаемая ссылка" };
  }
}

/** Parse newline-separated URLs; suffix duplicate tags within the batch. */
export function parseShareLinks(text: string): ParsedLink[] {
  const used = new Set<string>();
  let unnamed = 0;
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((raw) => {
    let tag: string;
    try {
      tag = fragmentTag(raw) || `imported_${++unnamed}`;
    } catch {
      tag = `imported_${++unnamed}`;
    }
    const item = parseShareLink(raw, tag);
    if (item.outbound) {
      const base = item.outbound.tag;
      let unique = base;
      for (let n = 1; used.has(unique);) {
        const suffix = `_${++n}`;
        unique = `${base.slice(0, 31 - suffix.length)}${suffix}`;
      }
      item.outbound.tag = unique;
      used.add(unique);
    }
    return item;
  });
}
