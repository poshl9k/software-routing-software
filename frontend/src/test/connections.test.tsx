import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import { Tunnels, Sites, DDNS } from "../pages/ConnectionEditors";
import { emptyConfiguration } from "../fixtures";
import type { Configuration, Tunnel } from "../types";
const server: Tunnel = {
  name: "vpn",
  interface: "awg0",
  role: "server",
  protocol: "awg",
  private_key: { redacted: true },
  listen_port: 51820,
  peers: [
    {
      name: "phone",
      public_key: "pub",
      allowed_ips: ["10.0.0.2/32"],
      preshared_key: { redacted: true },
    },
  ],
  endpoint: null,
  server_public_key: null,
  allowed_ips: [],
  keepalive: 25,
  obfuscation: { Jc: 4, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4 },
};
const wan: Configuration = {
  ...emptyConfiguration,
  interfaces: [
    {
      name: "eth0",
      type: "physical",
      zone: "wan",
      description: null,
      addressing: "static",
      addresses: ["203.0.113.1/24"],
      parent: null,
      vlan_id: null,
      members: [],
    },
  ],
};
async function open(
  page: React.ReactNode,
  config = emptyConfiguration,
  fail = false,
) {
  const fetch = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === "/api/versions")
      return new Response(
        JSON.stringify([{ id: 1, status: "confirmed", configuration: config }]),
      );
    if (fail)
      return new Response(
        JSON.stringify({ code: "save.failed", message: "Ошибка API" }),
        { status: 500 },
      );
    return new Response(
      JSON.stringify({
        id: 2,
        status: "draft",
        configuration: JSON.parse(String(init?.body)),
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(<RouterProvider>{page}</RouterProvider>);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Редактировать" })).toBeEnabled(),
  );
  await userEvent.click(screen.getByRole("button", { name: "Редактировать" }));
  return fetch;
}
const fill = (label: string, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
const save = () => screen.getByRole("button", { name: "Сохранить" });
it("renders AWG server, locks role, preserves secrets and hides obfuscation for WG", async () => {
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    tunnels: [server],
  });
  expect(screen.getByLabelText("Роль")).toHaveAttribute("readonly");
  expect(screen.getByLabelText("Jc")).toHaveValue(4);
  expect(screen.getByLabelText("Приватный ключ")).toHaveValue("");
  expect(screen.getByText(/сохранён/)).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Экспорт пира" }),
  ).toBeDisabled();
  fill("Протокол", "wg");
  expect(screen.queryByLabelText("Jc")).not.toBeInTheDocument();
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.tunnels[0].private_key).toEqual({ redacted: true });
  expect(body.tunnels[0].peers).toEqual(server.peers);
});
it("creates a complete draft with a client and write-only new secret", async () => {
  const wg0 = {
    name: "wg0",
    type: "physical" as const,
    zone: "lan",
    description: null,
    addressing: "static" as const,
    addresses: [],
    parent: null,
    vlan_id: null,
    members: [],
  };
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    interfaces: [wg0],
  });
  await userEvent.click(
    screen.getByRole("button", { name: "+ Добавить туннель" }),
  );
  fill("Имя туннеля", "bad-name");
  expect(save()).toBeDisabled();
  fill("Имя туннеля", "client");
  fill("Интерфейс", "wg0");
  fill("Роль", "client");
  fill("Endpoint", "vpn.example.org:51820");
  fill("Публичный ключ сервера", "public");
  fill("AllowedIPs", "0.0.0.0/0");
  fill("Приватный ключ", "new-key");
  await userEvent.click(save());
  const call = fetch.mock.calls.find(([p]) => p === "/api/draft")!;
  expect(call[1]!.method).toBe("POST");
  expect(JSON.parse(call[1]!.body as string)).toEqual({
    ...emptyConfiguration,
    interfaces: [{ ...wg0, description: "client", addresses: ["10.66.66.2/24"] }],
    tunnels: [
      expect.objectContaining({
        name: "client",
        role: "client",
        peers: [],
        listen_port: null,
        allowed_ips: ["0.0.0.0/0"],
        private_key: { plaintext: "new-key" },
      }),
    ],
  });
});
it("saves a passthrough site without certificate secrets", async () => {
  const fetch = await open(<Sites />, wan);
  await userEvent.click(
    screen.getByRole("button", { name: "+ Добавить сайт" }),
  );
  fill("Имя сайта", "web");
  fill("Hostname сайта", "home.example.org");
  fill("Upstream", "10.0.0.2:443");
  fill("Режим сертификата", "manual");
  expect(save()).toBeDisabled();
  fill("Режим сертификата", "passthrough");
  expect(screen.queryByLabelText("Сертификат")).not.toBeInTheDocument();
  await userEvent.click(save());
  expect(
    JSON.parse(
      fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
    ).sites[0],
  ).toMatchObject({
    certificate_mode: "passthrough",
    wan_address: "203.0.113.1",
    certificate: null,
  });
});
it.each(["cloudflare", "rfc2136"])(
  "saves %s DDNS with provider fields",
  async (provider) => {
    const fetch = await open(<DDNS />, wan);
    await userEvent.click(
      screen.getByRole("button", { name: "+ Добавить DDNS" }),
    );
    fill("Имя DDNS", "home");
    fill("Hostname DDNS", "home.example.org");
    fill("Провайдер", provider);
    expect(save()).toBeDisabled();
    if (provider === "cloudflare") fill("Zone", "example.org");
    else {
      fill("Сервер DNS", "192.0.2.53");
      fill("Key name", "home_key");
    }
    fill("API token / TSIG key", "token");
    await userEvent.click(save());
    expect(
      JSON.parse(
        fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
      ).ddns[0],
    ).toMatchObject({
      provider,
      api_token: { plaintext: "token" },
      wan_interface: "eth0",
    });
  },
);
it("auto-creates a LAN-zone interface for a new tunnel", async () => {
  const fetch = await open(<Tunnels />, emptyConfiguration);
  await userEvent.click(
    screen.getByRole("button", { name: "+ Добавить туннель" }),
  );
  // The tunnel device name is generated; the operator does not pick a NIC.
  expect(screen.getByLabelText("Интерфейс")).toHaveValue("tun0");
  fill("Имя туннеля", "vpn");
  fill("Приватный ключ", "key");
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.tunnels[0].interface).toBe("tun0");
  expect(body.interfaces).toContainEqual(
    expect.objectContaining({
      name: "tun0",
      type: "physical",
      zone: "lan",
      addressing: "static",
      description: "vpn",
    }),
  );
});
it("offers to create a new interface for a tunnel bound to a physical NIC", async () => {
  const nic = {
    name: "eth0",
    type: "physical" as const,
    zone: "wan",
    description: null,
    addressing: "static" as const,
    addresses: ["203.0.113.1/24"],
    parent: null,
    vlan_id: null,
    members: [],
  };
  await open(<Tunnels />, {
    ...emptyConfiguration,
    interfaces: [nic],
    tunnels: [{ ...server, interface: "eth0" }],
  });
  const select = screen.getByLabelText("Интерфейс") as HTMLSelectElement;
  const option = Array.from(select.options).find((o) =>
    o.textContent?.includes("создать новый интерфейс"),
  );
  // A fresh device name, so an existing tunnel can be moved off a NIC name.
  expect(option?.value).toBe("tun0");
});
it("fills an empty interface description with the owning tunnel name", async () => {
  const tun = {
    name: "tun0",
    type: "physical" as const,
    zone: "lan",
    description: null,
    addressing: "static" as const,
    addresses: [],
    parent: null,
    vlan_id: null,
    members: [],
  };
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    interfaces: [tun],
    tunnels: [{ ...server, interface: "tun0" }],
  });
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.interfaces[0].description).toBe("vpn");
});
it("removes an auto-created tunnel interface when its tunnel is deleted", async () => {
  const tun = {
    name: "tun0",
    type: "physical" as const,
    zone: "lan",
    description: "vpn",
    addressing: "static" as const,
    addresses: [],
    parent: null,
    vlan_id: null,
    members: [],
  };
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    interfaces: [tun],
    tunnels: [{ ...server, interface: "tun0" }],
  });
  await userEvent.click(screen.getByRole("button", { name: "Удалить vpn" }));
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.tunnels).toEqual([]);
  expect(body.interfaces).toEqual([]);
});
it("keeps a tunnel device that is still referenced elsewhere", async () => {
  const tun = {
    name: "tun0",
    type: "physical" as const,
    zone: "lan",
    description: "vpn",
    addressing: "static" as const,
    addresses: [],
    parent: null,
    vlan_id: null,
    members: [],
  };
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    interfaces: [tun],
    tunnels: [{ ...server, interface: "tun0" }],
    ssh: { interfaces: ["tun0"], wan_confirmed_interfaces: [] },
  });
  await userEvent.click(screen.getByRole("button", { name: "Удалить vpn" }));
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.tunnels).toEqual([]);
  expect(body.interfaces.map((i: { name: string }) => i.name)).toEqual(["tun0"]);
});
it("materializes the tunnel address and the peer /32 into the saved draft", async () => {
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    tunnels: [
      { ...server, allowed_ips: [], peers: [{ ...server.peers[0], allowed_ips: [] }] },
    ],
  });
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.interfaces).toContainEqual(
    expect.objectContaining({ name: "awg0", addresses: ["10.66.66.1/24"] }),
  );
  expect(body.tunnels[0].peers[0].allowed_ips).toEqual(["10.66.66.2/32"]);
});
it("saves a server's public endpoint for the client config", async () => {
  const fetch = await open(<Tunnels />, {
    ...emptyConfiguration,
    tunnels: [{ ...server, endpoint: null }],
  });
  fill("Публичный адрес (endpoint)", "vpn.example.org");
  await userEvent.click(save());
  const body = JSON.parse(
    fetch.mock.calls.find(([p]) => p === "/api/draft")![1]!.body as string,
  );
  expect(body.tunnels[0].endpoint).toBe("vpn.example.org");
});
it("retains edits after API failure", async () => {
  await open(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, true);
  fill("Порт", "51821");
  await userEvent.click(save());
  expect(await screen.findByRole("alert")).toHaveTextContent("Ошибка API");
  expect(screen.getByLabelText("Порт")).toHaveValue(51821);
  expect(save()).toBeEnabled();
});
