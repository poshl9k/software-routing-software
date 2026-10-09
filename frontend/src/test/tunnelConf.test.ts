import { describe, expect, it } from "vitest";
import { parseWireGuardConf } from "../tunnelConf";

const privateKey = `${"A".repeat(43)}=`;
const publicKey = `${"B".repeat(43)}=`;
const presharedKey = `${"C".repeat(43)}=`;
const basic = `[Interface]
PrivateKey = ${privateKey}
Address = 10.1.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1420
ListenPort = 51820

[Peer]
PublicKey = ${publicKey}
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;

function failure(text: string, field: string) {
  const result = parseWireGuardConf(text);
  expect(result).toEqual({ error: expect.stringContaining(field) });
  expect(result.tunnel).toBeUndefined();
}

describe("parseWireGuardConf", () => {
  it("maps a WG client without inventing Address/DNS/MTU/ListenPort fields or peer rows", () => {
    const result = parseWireGuardConf(`# example\r\n; comment\r\n${basic.replaceAll("\n", "\r\n")}`);
    expect(result).toEqual({ tunnel: {
      role: "client", protocol: "wg", private_key: { plaintext: privateKey },
      server_public_key: publicKey, endpoint: "vpn.example.com:51820",
      allowed_ips: ["0.0.0.0/0", "::/0"], keepalive: 25,
      peers: [], listen_port: null, obfuscation: {},
    } });
    expect(Object.keys(result.tunnel ?? {}).sort()).toEqual([
      "allowed_ips", "endpoint", "keepalive", "listen_port", "obfuscation", "peers",
      "private_key", "protocol", "role", "server_public_key",
    ]);
  });

  it("maps AWG obfuscation with integer values; ignores unknown keys and comments", () => {
    const text = basic.replace("ListenPort = 51820", `Jc = 4
Jmin = 35
Jmax = 90
S1 = 0
S2 = 95
H1 = 11
H2 = 12
H3 = 13
H4 = 14
Unknown = ignored`)
      .replace("Endpoint = vpn.example.com:51820", "Endpoint = [2001:db8::1]:443 # server")
      .replace("PersistentKeepalive = 25", "PersistentKeepalive = 0 ; keepalive disabled");
    const result = parseWireGuardConf(text);
    expect(result.tunnel).toMatchObject({
      protocol: "awg", endpoint: "[2001:db8::1]:443", keepalive: 0,
      private_key: { plaintext: privateKey }, peers: [],
      obfuscation: { Jc: 4, Jmin: 35, Jmax: 90, S1: 0, S2: 95, H1: 11, H2: 12, H3: 13, H4: 14 },
    });
    expect(JSON.stringify(result)).not.toContain(presharedKey);
  });

  it("rejects a preshared secret rather than silently dropping it", () => {
    const result = parseWireGuardConf(basic.replace("[Peer]", `[Peer]\nPresharedKey = ${presharedKey}`));
    expect(result).toEqual({ error: expect.stringContaining("PresharedKey") });
    expect(JSON.stringify(result)).not.toContain(presharedKey);
  });

  it("rejects missing sections, required values and invalid keys", () => {
    failure(basic.replace(/\[Peer\][\s\S]*/, ""), "Peer");
    failure(basic.replace(`PublicKey = ${publicKey}`, ""), "PublicKey");
    failure(basic.replace("Endpoint = vpn.example.com:51820", ""), "Endpoint");
    failure(basic.replace(privateKey, "short"), "PrivateKey");
    failure(basic.replace(publicKey, "short"), "PublicKey");
    failure(basic.replace("AllowedIPs =", "PresharedKey = invalid\nAllowedIPs ="), "PresharedKey");
  });

  it.each(["vpn.example.com", "vpn.example.com:0", "vpn.example.com:65536", "[bad::ip]:443", "2001:db8::1:443", "999.1.2.3:123", "-bad.example:443"])(
    "rejects malformed endpoint %s", (value) => {
      failure(basic.replace("vpn.example.com:51820", value), "Endpoint");
    },
  );

  it.each(["", "10.0.0.999/24", "10.0.0.0/33", "192.168.1.1/", "::/129", "not-an-ip/24", "10.0.0.1/24, ", "1.2.3.4/24/20"])(
    "rejects malformed AllowedIPs %s", (value) => {
      failure(basic.replace("0.0.0.0/0, ::/0", value), "AllowedIPs");
    },
  );

  it("rejects invalid AWG integers and keepalive without throwing", () => {
    failure(basic.replace("ListenPort = 51820", "Jc = 1.5"), "Jc");
    failure(basic.replace("ListenPort = 51820", "H4 = nope"), "H4");
    failure(basic.replace("PersistentKeepalive = 25", "PersistentKeepalive = -1"), "PersistentKeepalive");
    failure(basic.replace("PersistentKeepalive = 25", "PersistentKeepalive = 65536"), "PersistentKeepalive");
    failure(basic + `\n[Peer]\nPublicKey = ${publicKey}`, "Peer");
  });
});
