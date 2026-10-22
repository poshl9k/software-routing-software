import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import { Tunnels, Sites, DDNS } from "../pages/ConnectionEditors";
import { emptyConfiguration } from "../fixtures";
import type { Configuration, Tunnel } from "../types";

const server: Tunnel = {
  name: "vpn", interface: "tun0", role: "server", protocol: "awg",
  private_key: { redacted: true }, listen_port: 51820,
  peers: [{ name: "phone", public_key: "pub", allowed_ips: ["10.0.0.2/32"], preshared_key: { redacted: true } }],
  endpoint: null, server_public_key: null, allowed_ips: [], keepalive: 25,
  obfuscation: { Jc: 4, S1: 0, S2: 0, H1: 1, H2: 2, H3: 3, H4: 4 }, open_port: true,
  preshared_key: null, header_protection_key: null, random_trailers: false, disable_cookies: false,
};
const generated = { private_key: "generated-private-key", public_key: "generated-public-key",
  obfuscation: { Jc: 4, Jmin: 35, Jmax: 90, S1: 12, S2: 95, H1: 11, H2: 12, H3: 13, H4: 14 } };
const wan: Configuration = { ...emptyConfiguration, interfaces: [{ name: "eth0", type: "physical", zone: "wan", description: null,
  addressing: "static", addresses: ["203.0.113.1/24"], parent: null, vlan_id: null, members: [] }] };
async function mount(page: React.ReactNode, config: Configuration = emptyConfiguration, fail = false,
  keygen: (protocol: "wg" | "awg") => Promise<Response> = async (protocol) => new Response(JSON.stringify(protocol === "awg" ? generated : { private_key: generated.private_key, public_key: generated.public_key })),
  status: Response = new Response(JSON.stringify({ generated_at: "2026-01-01T00:00:00Z", services: [] }))) {
  const fetch = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === "/api/status/services") return status.clone();
    if (path === "/api/keygen/tunnel") return keygen(JSON.parse(String(init?.body)).protocol);
    if (path === "/api/versions") return new Response(JSON.stringify([{ id: 1, status: "confirmed", configuration: config }]));
    if (fail) return new Response(JSON.stringify({ code: "save.failed", message: "Ошибка API" }), { status: 500 });
    return new Response(JSON.stringify({ id: 2, status: "draft", configuration: JSON.parse(String(init?.body)) }));
  });
  vi.stubGlobal("fetch", fetch);
  render(<RouterProvider>{page}</RouterProvider>);
  if ((page as { type?: unknown }).type === Tunnels) await screen.findByRole("button", { name: /Добавить туннель/ });
  else { await userEvent.click(await screen.findByRole("button", { name: "Редактировать" })); }
  return fetch;
}
const fill = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const save = () => screen.getByRole("button", { name: "Сохранить" });
const draft = (fetch: ReturnType<typeof vi.fn>) => JSON.parse(String(fetch.mock.calls.find(([path]) => path === "/api/draft")?.[1]?.body));
async function openTunnel() {
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  await userEvent.click(within(screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" }))
    .getByRole("button", { name: "Изменить" }));
}
async function choose(role: "client" | "server", protocol: "wg" | "awg" = "wg") {
  await userEvent.click(screen.getByRole("button", { name: /Добавить туннель/ }));
  if (role === "server") await userEvent.click(screen.getByRole("button", { name: "Поднять сервер" }));
  if (protocol === "awg") fill("Протокол нового туннеля", "awg");
  await userEvent.click(screen.getByRole("button", { name: "Продолжить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Новый туннель" })).not.toBeInTheDocument());
}
it("client/server split filters cards and preserves hidden tunnels when saving either tab", async () => {
  const client: Tunnel = { ...server, name: "remote", interface: "tun1", role: "client",
    peers: [], endpoint: "remote.example:51820", server_public_key: "remote-public" };
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server, client] });
  expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Клиенты", "Серверы"]);
  expect(screen.getByRole("tab", { name: "Клиенты" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("remote · AmneziaWG · Клиент")).toBeVisible();
  expect(screen.queryByText("vpn · AmneziaWG · Сервер")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  fill("Endpoint", "updated.example:51820");
  await userEvent.click(save());
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(draft(fetch).tunnels).toEqual([
    { ...server, default_route: false, dns_servers: [] },
    { ...client, endpoint: "updated.example:51820", default_route: false, dns_servers: [] },
  ]);
  await userEvent.click(screen.getByRole("tab", { name: "Серверы" }));
  expect(screen.getByRole("tab", { name: "Серверы" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("vpn · AmneziaWG · Сервер")).toBeVisible();
  expect(screen.queryByText("remote · AmneziaWG · Клиент")).not.toBeInTheDocument();
  await openTunnel();
  fill("Порт", "51821");
  await userEvent.click(save());
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  const writes = fetch.mock.calls.filter(([path]) => path === "/api/draft");
  expect(writes).toHaveLength(2);
  expect(JSON.parse(String(writes[1][1]?.body)).tunnels).toEqual([
    { ...server, listen_port: 51821, default_route: false, dns_servers: [] },
    { ...client, endpoint: "updated.example:51820", default_route: false, dns_servers: [] },
  ]);
  await userEvent.click(screen.getByRole("tab", { name: "Клиенты" }));
  expect(screen.getByText("remote · AmneziaWG · Клиент")).toBeVisible();
  expect(screen.queryByText("vpn · AmneziaWG · Сервер")).not.toBeInTheDocument();
});
it.each(["client", "server"] as const)("view mode for %s has only facts until Изменить and resets after cancel", async (role) => {
  const tunnel: Tunnel = { ...server, role, ...(role === "client"
    ? { peers: [], endpoint: "remote.example:51820", server_public_key: "remote-public" } : {}) };
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [tunnel] });
  if (role === "server") await userEvent.click(screen.getByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  let dialog = screen.getByRole("dialog", { name: /Туннель: vpn/ });
  const facts = dialog.querySelector("dl.kv")!;
  expect(Array.from(facts.querySelectorAll("dt"), (item) => item.textContent))
    .toEqual(["Имя", "Роль", "Протокол", "Интерфейс"]);
  expect(Array.from(facts.querySelectorAll("dd"), (item) => item.textContent))
    .toEqual(["vpn", role === "server" ? "сервер" : "клиент", "AmneziaWG", "tun0"]);
  expect(dialog.querySelector("input, select, textarea")).toBeNull();
  expect(within(dialog).queryByRole("button", { name: "Сохранить" })).not.toBeInTheDocument();
  expect(within(dialog).queryByRole("button", { name: "Удалить vpn" })).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Изменить" }));
  expect(within(dialog).getByLabelText("Имя туннеля")).toBeVisible();
  const label = role === "server" ? "Порт" : "Endpoint";
  fill(label, role === "server" ? "51821" : "discarded.example:51820");
  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(fetch.mock.calls.filter(([path]) => path === "/api/draft")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  dialog = screen.getByRole("dialog", { name: /Туннель: vpn/ });
  expect(dialog.querySelector("input, select, textarea")).toBeNull();
  await userEvent.click(within(dialog).getByRole("button", { name: "Изменить" }));
  expect(within(dialog).getByLabelText(label)).toHaveValue(role === "server" ? 51820 : "remote.example:51820");
});
it("cancels a read-only view without a write and creates the next tunnel directly in edit mode", async () => {
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  await userEvent.click(screen.getByRole("tab", { name: "Серверы" }));
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  await userEvent.click(screen.getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(fetch.mock.calls.filter(([path]) => path === "/api/draft")).toHaveLength(0);
  await choose("server");
  expect(screen.getByLabelText("Имя туннеля")).toHaveValue("");
  expect(screen.getByLabelText("Имя туннеля")).not.toHaveAttribute("readonly");
  expect(screen.queryByRole("button", { name: "Изменить" })).not.toBeInTheDocument();
});
it("shows one tunnel card with honest status; opens one dialog with role locked and secret hidden", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  expect(screen.getByText("vpn · AmneziaWG · Сервер")).toBeVisible();
  expect(within(screen.getByText("Пиров").closest("dl")!).getByText("1")).toBeVisible();
  expect(await screen.findByText("Статус недоступен")).toBeVisible();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  await openTunnel();
  const dialog = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" });
  expect(within(dialog).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Туннель", "Пиры"]);
  expect(within(dialog).getByLabelText("Роль")).toHaveAttribute("readonly");
  expect(within(dialog).getByLabelText("Приватный ключ")).toHaveValue("");
  expect(within(dialog).getByText(/Повторная генерация ключей разорвёт/)).toBeVisible();
  expect(within(dialog).queryByLabelText("Preshared key")).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByText("Показать дополнительные настройки"));
  expect(within(dialog).getByLabelText("Jc")).toHaveValue("4");
  await userEvent.click(within(dialog).getByRole("tab", { name: "Пиры" }));
  expect(within(dialog).getByText("phone")).toBeVisible();
  await userEvent.click(within(dialog).getByRole("button", { name: "Изменить" }));
  expect(within(screen.getByRole("dialog", { name: "Пир: phone" })).getByLabelText("Preshared key")).toHaveValue("");
});
it("keeps the entire server tunnel form on its own tab and peers on the other", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  await openTunnel();
  const dialog = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" });
  for (const section of ["Идентификация", "Подключение", "Ключи", "Дополнительно"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Порт")).toBeVisible();
  expect(within(dialog).getByLabelText("Приватный ключ")).toBeVisible();
  expect(within(dialog).queryByLabelText("Preshared key")).not.toBeInTheDocument();
  expect(within(dialog).getByRole("button", { name: "Отмена" })).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeVisible();
  await userEvent.click(within(dialog).getByRole("tab", { name: "Пиры" }));
  expect(within(dialog).getByLabelText("Порт")).not.toBeVisible();
  expect(within(dialog).getByRole("table")).toBeVisible();
});
it("keeps peer and key fields off the page until the editor dialog opens", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Preshared key")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Приватный ключ")).not.toBeInTheDocument();
  await openTunnel();
  expect(screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" })).toBeVisible();
  expect(screen.queryByLabelText("Preshared key")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Приватный ключ")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Пиры" }));
  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  expect(within(screen.getByRole("dialog", { name: "Пир: phone" })).getByLabelText("Preshared key")).toBeInTheDocument();
});
it("shows two server clients as a number in the read-only facts", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [{ ...server, peers: [...server.peers, { ...server.peers[0], name: "laptop" }] }] });
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  const facts = screen.getByText("Пиров").closest("dl")!;
  expect(within(facts).getByText("Интерфейс")).toBeVisible();
  expect(within(facts).getByText("tun0")).toBeVisible();
  expect(within(facts).getByText("2")).toBeVisible();
});
it("says no clients instead of zero on an empty server card", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [{ ...server, peers: [] }] });
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  const facts = screen.getByText("Пиров").closest("dl")!;
  expect(within(facts).getByText("нет пиров")).toBeVisible();
  expect(within(facts).queryByText("0")).not.toBeInTheDocument();
});
it("shows one empty state in the server peers section without duplicating the add action", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [{ ...server, peers: [] }] });
  await openTunnel();
  const dialog = screen.getByRole("dialog", { name: "Туннель: vpn · AmneziaWG · Сервер" });
  await userEvent.click(within(dialog).getByRole("tab", { name: "Пиры" }));
  expect(within(dialog).getAllByText("Пиров нет.")).toHaveLength(1);
  expect(within(dialog).getAllByRole("button", { name: "+ Добавить пира" })).toHaveLength(1);
});
it("shows client endpoint in read-only facts", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [{ ...server, role: "client", peers: [], endpoint: "vpn.example.net:51820" }] });
  const facts = screen.getByText("Endpoint").closest("dl")!;
  expect(within(facts).getByText("vpn.example.net:51820")).toBeVisible();
  expect(within(facts).queryByText("Пиров")).not.toBeInTheDocument();
});
it.each([
  ["running", "Работает"], ["stopped", "Остановлена"], ["unknown", "Состояние неизвестно"],
])("shows %s tunnel state and timestamp from matching interface only", async (state, label) => {
  const status = new Response(JSON.stringify({ generated_at: "2026-01-01T00:00:00Z", services: [
    { name: "tunnel:tun1", state: "running", detail: null },
    { name: "tunnel:tun0", state, detail: null },
  ] }));
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, false, undefined, status);
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  expect(await screen.findByText(label)).toBeVisible();
  expect(screen.getByText("2026-01-01T00:00:00Z")).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => path === "/api/status/services")).toBe(true);
  expect(screen.queryByText("Черновик")).not.toBeInTheDocument();
});
it("keeps failed telemetry unknown, never green", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, false, undefined,
    new Response(JSON.stringify({ code: "unavailable", message: "Нет статуса" }), { status: 503 }));
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  expect(await screen.findByText("Статус недоступен")).toBeVisible();
  expect(screen.queryByText("Работает")).not.toBeInTheDocument();
});
it("selects client and protocol before keygen; saves one draft without opening WAN port", async () => {
  const fetch = await mount(<Tunnels />);
  await userEvent.click(screen.getByRole("button", { name: /Добавить туннель/ }));
  expect(fetch.mock.calls.filter(([p]) => p === "/api/keygen/tunnel")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Новый туннель" })).not.toBeInTheDocument());
  await choose("client", "awg");
  expect(fetch.mock.calls.filter(([p]) => p === "/api/keygen/tunnel")).toHaveLength(1);
  fill("Имя туннеля", "client");
  expect(screen.getByLabelText("Роль")).toHaveValue("клиент");
  fill("Endpoint", "vpn.example.org:51820");
  fill("AllowedIPs", "0.0.0.0/0");
  fill("Публичный ключ сервера", "public");
  expect(within(screen.getByRole("dialog", { name: /Туннель:/ })).getByText(/Сохранение создаёт только черновик/)).toBeVisible();
  await userEvent.click(save());
  await waitFor(() => expect(fetch.mock.calls.some(([p]) => p === "/api/draft")).toBe(true));
  expect(draft(fetch).tunnels[0]).toMatchObject({ name: "client", role: "client", protocol: "awg", open_port: false,
    default_route: false,
    endpoint: "vpn.example.org:51820", allowed_ips: ["0.0.0.0/0"], private_key: { plaintext: generated.private_key } });
  expect(draft(fetch).interfaces[0].addresses).toEqual(["10.66.66.2/24"]);
  expect(fetch.mock.calls.filter(([p]) => p === "/api/draft")).toHaveLength(1);
});
it("creates server with WAN port closed and previews save effects", async () => {
  const fetch = await mount(<Tunnels />);
  await choose("server");
  fill("Имя туннеля", "vpn");
  expect(screen.getByText(/WAN UDP-порт не открывается/)).toBeVisible();
  expect(screen.getByRole("switch", { name: "Открыть порт на WAN" })).not.toBeChecked();
  await userEvent.click(save());
  expect(draft(fetch).tunnels[0]).toMatchObject({ name: "vpn", role: "server", listen_port: 51820, open_port: false });
});
it("imports client conf with recognized fields, preserves Address and the preshared secret", async () => {
  const fetch = await mount(<Tunnels />);
  const privateKey = `${"A".repeat(43)}=`;
  const publicKey = `${"B".repeat(43)}=`;
  const presharedKey = `${"C".repeat(43)}=`;
  await userEvent.click(screen.getByRole("button", { name: "Импорт .conf" }));
  const conf = `[Interface]\nAddress = 10.9.8.7/24\nPrivateKey = ${privateKey}\n[Peer]\nPublicKey = ${publicKey}\nPresharedKey = ${presharedKey}\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25`;
  fill("Содержимое .conf", conf);
  await userEvent.click(screen.getByRole("button", { name: "Показать распознанные поля" }));
  expect(screen.getByText(/Address 10.9.8.7\/24/)).toBeVisible();
  expect(screen.getByText(/endpoint vpn.example.org:51820/)).toBeVisible();
  expect(screen.getByText(/PSK распознан/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Импорт .conf" })).not.toBeInTheDocument());
  expect(screen.getByLabelText("Имя туннеля")).toHaveValue("tunnel1");
  expect(fetch.mock.calls.filter(([p]) => p === "/api/keygen/tunnel")).toHaveLength(0);
  await userEvent.click(save());
  expect(draft(fetch).interfaces[0].addresses).toEqual(["10.9.8.7/24"]);
  expect(draft(fetch).tunnels[0].private_key).toEqual({ plaintext: privateKey });
  expect(draft(fetch).tunnels[0].preshared_key).toEqual({ plaintext: presharedKey });
  expect(draft(fetch).tunnels[0].default_route).toBe(false);
});
it("retains secret and only edits selected tunnel; delete requires confirmation", async () => {
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  await openTunnel();
  fill("Порт", "51821");
  await userEvent.click(save());
  expect(draft(fetch).tunnels[0].private_key).toEqual({ redacted: true });
  expect(draft(fetch).tunnels[0].listen_port).toBe(51821);
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  await userEvent.click(screen.getByRole("button", { name: "Открыть" }));
  const dialog = screen.getByRole("dialog", { name: /Туннель: vpn/ });
  expect(dialog.querySelector("input, select, textarea")).toBeNull();
  await userEvent.click(within(dialog).getByRole("button", { name: "Изменить" }));
  expect(within(dialog).getByLabelText("Порт")).toHaveValue(51821);
});
it("confirmation removes tunnel and auto interface only from draft", async () => {
  const config: Configuration = { ...emptyConfiguration, tunnels: [server], interfaces: [{ name: "tun0", type: "physical", zone: "lan", addressing: "static", addresses: [], description: "vpn", parent: null, vlan_id: null, members: [] }] };
  const fetch = await mount(<Tunnels />, config);
  await openTunnel();
  await userEvent.click(screen.getByRole("button", { name: "Удалить vpn" }));
  const dialog = screen.getByRole("dialog", { name: "Удалить туннель?" });
  expect(within(dialog).getByText(/ссылки на него/i)).toBeVisible();
  expect(fetch.mock.calls.filter(([p]) => p === "/api/draft")).toHaveLength(0);
  await userEvent.click(within(dialog).getByRole("button", { name: "Удалить из черновика" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить туннель?" })).not.toBeInTheDocument());
  // Removing the last tunnel may close the editor dialog; save only if its footer is still mounted.
  if (screen.queryByRole("button", { name: "Сохранить" })) await userEvent.click(save());
  await waitFor(() => expect(fetch.mock.calls.some(([p]) => p === "/api/draft")).toBe(true));
  expect(draft(fetch).tunnels).toEqual([]);
  expect(draft(fetch).interfaces).toEqual([]);
});
it("removes a deleted tunnel's device and every reference that named it", async () => {
  const backup: Tunnel = { ...server, name: "backup", interface: "tun1", peers: [] };
  const tun = (name: string, description: string, address: string) => ({
    name, type: "physical" as const, zone: "lan" as const, addressing: "static" as const,
    addresses: [address], description, parent: null, vlan_id: null, members: [],
  });
  const config: Configuration = {
    ...emptyConfiguration,
    tunnels: [server, backup],
    interfaces: [tun("tun0", "vpn", "10.66.66.1/24"), tun("tun1", "backup", "10.66.67.1/24")],
    // A surviving tunnel keeps its device; the deleted one takes its references.
    tproxy: { ...emptyConfiguration.tproxy, ingress_interfaces: ["tun0", "tun1"] },
    static_routes: [{ destination: "192.0.2.0/24", gateway: null, interface: "tun0", metric: 100, enabled: true }],
  };
  const fetch = await mount(<Tunnels />, config);
  await userEvent.click(await screen.findByRole("tab", { name: "Серверы" }));
  await userEvent.click((await screen.findAllByRole("button", { name: "Открыть" }))[0]);
  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  await userEvent.click(screen.getByRole("button", { name: "Удалить vpn" }));
  await userEvent.click(within(screen.getByRole("dialog", { name: "Удалить туннель?" }))
    .getByRole("button", { name: "Удалить из черновика" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить туннель?" })).not.toBeInTheDocument());
  if (screen.queryByRole("button", { name: "Сохранить" })) await userEvent.click(save());
  await waitFor(() => expect(fetch.mock.calls.some(([p]) => p === "/api/draft")).toBe(true));
  expect(draft(fetch).interfaces.map((i: { name: string }) => i.name)).toEqual(["tun1"]);
  expect(draft(fetch).tproxy.ingress_interfaces).toEqual(["tun1"]);
  expect(draft(fetch).static_routes).toEqual([]);
});
it("surfaces keygen failure and keeps save error in editor", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, true, async () => new Response(JSON.stringify({ message: "Генерация не удалась" }), { status: 500 }));
  await openTunnel();
  await userEvent.click(screen.getByRole("button", { name: "Сгенерировать ключи" }));
  expect((await screen.findAllByRole("alert")).some((alert) => alert.textContent?.includes("Генерация не удалась"))).toBe(true);
  fill("Порт", "51821");
  await userEvent.click(save());
  await waitFor(() => expect(screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("Ошибка API"))).toBe(true));
  expect(screen.getByLabelText("Порт")).toHaveValue(51821);
});
it("saves passthrough site without certificate secrets", async () => {
  const fetch = await mount(<Sites />, wan);
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить сайт" }));
  fill("Имя сайта", "web"); fill("Hostname сайта", "home.example.org"); fill("Upstream", "10.0.0.2:443");
  fill("Режим сертификата", "passthrough");
  await userEvent.click(save());
  expect(draft(fetch).sites[0]).toMatchObject({ certificate_mode: "passthrough", wan_address: "203.0.113.1", certificate: null });
});
it.each(["cloudflare", "rfc2136"])("saves %s DDNS", async (provider) => {
  const fetch = await mount(<DDNS />, wan);
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить домен" }));
  fill("Имя DDNS", "home"); fill("Hostname DDNS", "home.example.org"); fill("Провайдер", provider);
  if (provider === "cloudflare") fill("Zone", "example.org");
  else { fill("Сервер DNS", "192.0.2.53"); fill("Key name", "home_key"); }
  fill("API token / TSIG key", "token");
  await userEvent.click(save());
  expect(draft(fetch).ddns[0]).toMatchObject({ provider, api_token: { plaintext: "token" }, wan_interface: "eth0" });
});
