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
const save = () => screen.getByRole("button", { name: "Сохранить черновик" });
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
    screen.getByRole("button", { name: /TODO-API-EXPORT/ }),
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
  const fetch = await open(<Tunnels />);
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
it("retains edits after API failure", async () => {
  await open(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, true);
  fill("Порт", "51821");
  await userEvent.click(save());
  expect(await screen.findByRole("alert")).toHaveTextContent("Ошибка API");
  expect(screen.getByLabelText("Порт")).toHaveValue(51821);
  expect(save()).toBeEnabled();
});
