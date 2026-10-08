import { describe, expect, it } from "vitest";
import { parseShareLink, parseShareLinks } from "../shareLinks";

const b64 = (text: string) => btoa(Array.from(new TextEncoder().encode(text), (byte) => String.fromCharCode(byte)).join(""));
const urlSafe = (text: string) => b64(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function ok(link: string, type: string) {
  const result = parseShareLink(link, "fallback");
  expect(result.error).toBeUndefined();
  expect(result.outbound?.type).toBe(type);
  expect(result.outbound).toMatchObject({ admin_listen: null });
  expect(result.link).not.toBe(link);
  return result.outbound!;
}

describe("share links", () => {
  it("parses both Shadowsocks base64 forms, URL-safe unpadded UTF-8", () => {
    const first = ok(`ss://${urlSafe("aes-256-gcm:пароль")}@example.org:8388#My%20Node`, "shadowsocks");
    expect(first).toMatchObject({ tag: "My_Node", server: "example.org", port: 8388, secret: { plaintext: "пароль" }, method: "aes-256-gcm", tls: false, tls_server_name: null, tls_insecure: false });
    const second = ok(`ss://${b64("chacha20-ietf-poly1305:another@example.net:443")}`, "shadowsocks");
    expect(second).toMatchObject({ method: "chacha20-ietf-poly1305", secret: { plaintext: "another" }, server: "example.net", port: 443 });
  });

  it("parses vmess JSON base64 and fragment override", () => {
    const outbound = ok(`vmess://${urlSafe(JSON.stringify({ add: "vm.example", port: "443", id: "uuid-secret", ps: "old", tls: "tls", sni: "front.example", allowInsecure: 1 }))}#New%20Name`, "vmess");
    expect(outbound).toMatchObject({ tag: "New_Name", server: "vm.example", port: 443, secret: { plaintext: "uuid-secret" }, method: null, tls: true, tls_server_name: "front.example", tls_insecure: true });
  });

  it.each([
    ["vless://uuid@vless.example:443?security=tls&sni=front.example&allowInsecure=1#V", "vless", "uuid", true, "front.example", true],
    ["trojan://pass%40word@trojan.example:443?sni=t.example#T", "trojan", "pass@word", true, "t.example", false],
    ["hysteria2://hy-secret@hy.example:8443?insecure=true#H", "hysteria2", "hy-secret", true, null, true],
    ["tuic://user:pwd@tuic.example:443?security=tls&servername=s.example#U", "tuic", "user", true, "s.example", false],
  ])("parses URI scheme case %#", (link, type, secret, tls, sni, insecure) => {
    expect(ok(link, type)).toMatchObject({ secret: { plaintext: secret }, tls, tls_server_name: sni, tls_insecure: insecure, method: null });
  });

  it("uses fallback tag for a single URL; generates and deduplicates batch tags", () => {
    expect(ok("vless://abc@host.test:80", "vless").tag).toBe("fallback");
    const parsed = parseShareLinks("vless://a@one.test:80#Same\n trojan://b@two.test:443#Same\n vless://c@three.test:80\n vless://d@four.test:80");
    expect(parsed.map((item) => item.outbound?.tag)).toEqual(["Same", "Same_2", "imported_1", "imported_2"]);
  });

  it("sanitizes fragment names to a contract-valid Name", () => {
    // Spaces/hyphens/leading digit/non-ASCII all coerce to [A-Za-z][A-Za-z0-9_]*
    expect(ok("vless://a@h.test:80#my-server", "vless").tag).toBe("my_server");
    expect(ok("vless://a@h.test:80#1%20сервер", "vless").tag).toBe("t_1");
    expect(parseShareLink("vless://a@h.test:80", "1 bad").outbound?.tag).toBe("t_1_bad");
    // Dedup must keep the tag within the 31-char limit.
    const long = "a".repeat(40);
    const parsed = parseShareLinks(`vless://a@h.test:80#${long}\nvless://b@h.test:80#${long}`);
    expect(parsed[0].outbound?.tag).toHaveLength(31);
    expect(parsed[1].outbound?.tag).toHaveLength(31);
    expect(parsed[1].outbound?.tag.endsWith("_2")).toBe(true);
  });

  it.each([
    "ss://broken", "ss://bm90LWJhc2U2NA@host:123", "vmess://not-valid*", "vmess://e30=",
    "vless://@host:443", "trojan://pass@host:0", "hysteria2://pass@bad_host:443",
    "tuic://user@host:443", "vless://pass@host:65536", "unknown://pass@host:443",
    "vless://pass@host:443#%ZZ",
    "vless://pass@host:443?security=reality",
    "vless://pass@host:443?type=ws",
    `ss://${urlSafe("aes-256-gcm:pass")}@host:443?plugin=obfs-local`,
    `vmess://${b64(JSON.stringify({ add: "host", port: 443, id: "pass", net: "ws" }))}`,
  ])("returns safe error for invalid case %#", (link) => {
    const result = parseShareLink(link, "tag");
    expect(result.outbound).toBeUndefined();
    expect(result.error).toBeTruthy();
    expect(result.link).toMatch(/^[a-z0-9]+:\/\/\[скрыто\]$/);
    expect(JSON.stringify(result)).not.toContain("pass@host");
  });

  it("never exposes URI or credentials outside outbound even on failure", () => {
    const good = parseShareLink("trojan://topsecret@host.test:443#safe", "fallback");
    const bad = parseShareLink("trojan://topsecret@host.test:0#safe", "fallback");
    for (const item of [good, bad]) {
      expect(item.link).toBe("trojan://[скрыто]");
      expect(item.error ?? "").not.toContain("topsecret");
      expect(JSON.stringify({ link: item.link, error: item.error })).not.toContain("topsecret");
    }
    expect(good.outbound?.secret).toEqual({ plaintext: "topsecret" });
  });
});
