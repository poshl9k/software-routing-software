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
};
const generated = { private_key: "generated-private-key", public_key: "generated-public-key",
  obfuscation: { Jc: 4, Jmin: 35, Jmax: 90, S1: 12, S2: 95, H1: 11, H2: 12, H3: 13, H4: 14 } };
const wan: Configuration = { ...emptyConfiguration, interfaces: [{ name: "eth0", type: "physical", zone: "wan", description: null,
  addressing: "static", addresses: ["203.0.113.1/24"], parent: null, vlan_id: null, members: [] }] };
async function mount(page: React.ReactNode, config: Configuration = emptyConfiguration, fail = false,
  keygen: (protocol: "wg" | "awg") => Promise<Response> = async (protocol) => new Response(JSON.stringify(protocol === "awg" ? generated : { private_key: generated.private_key, public_key: generated.public_key }))) {
  const fetch = vi.fn(async (path: string, init?: RequestInit) => {
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
async function openTunnel() { await userEvent.click(screen.getByRole("button", { name: "Открыть" })); }
async function choose(role: "client" | "server", protocol: "wg" | "awg" = "wg") {
  await userEvent.click(screen.getByRole("button", { name: /Добавить туннель/ }));
  if (role === "server") await userEvent.click(screen.getByRole("button", { name: "Поднять сервер" }));
  if (protocol === "awg") fill("Протокол нового туннеля", "awg");
  await userEvent.click(screen.getByRole("button", { name: "Продолжить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Новый туннель" })).not.toBeInTheDocument());
}
it("shows one tunnel card with honest status; opens one editor with role locked and secret hidden", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  expect(screen.getByText("vpn · AmneziaWG · Сервер")).toBeVisible();
  expect(screen.getByText("Клиентов: 1")).toBeVisible();
  expect(screen.getByText("Состояние недоступно")).toBeVisible();
  expect(screen.queryByRole("table")).not.toBeInTheDocument();
  await openTunnel();
  expect(screen.getByLabelText("Роль")).toHaveAttribute("readonly");
  await userEvent.click(screen.getByRole("tab", { name: "Ключи" }));
  expect(screen.getByLabelText("Приватный ключ")).toHaveValue("");
  expect(screen.getByText(/Повторная генерация ключей разорвёт/)).toBeVisible();
  await userEvent.click(screen.getByRole("tab", { name: "Клиенты" }));
  expect(screen.getByLabelText("Preshared key")).toHaveValue("");
  expect(screen.getByText("phone")).toBeVisible();
  await userEvent.click(screen.getByRole("tab", { name: "Дополнительно" }));
  expect(screen.getByLabelText("Jc")).toHaveValue(4);
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
  await userEvent.click(screen.getByRole("tab", { name: "Подключение" }));
  fill("Endpoint", "vpn.example.org:51820");
  fill("AllowedIPs", "0.0.0.0/0");
  await userEvent.click(screen.getByRole("tab", { name: "Ключи" }));
  fill("Публичный ключ сервера", "public");
  expect(screen.getByText(/Сохранение создаёт только черновик/)).toBeVisible();
  await userEvent.click(save());
  await waitFor(() => expect(fetch.mock.calls.some(([p]) => p === "/api/draft")).toBe(true));
  expect(draft(fetch).tunnels[0]).toMatchObject({ name: "client", role: "client", protocol: "awg", open_port: false,
    endpoint: "vpn.example.org:51820", allowed_ips: ["0.0.0.0/0"], private_key: { plaintext: generated.private_key } });
  expect(draft(fetch).interfaces[0].addresses).toEqual(["10.66.66.2/24"]);
  expect(fetch.mock.calls.filter(([p]) => p === "/api/draft")).toHaveLength(1);
});
it("creates server with WAN port closed and previews save effects", async () => {
  const fetch = await mount(<Tunnels />);
  await choose("server");
  fill("Имя туннеля", "vpn");
  expect(screen.getByText(/WAN UDP-порт не открывается/)).toBeVisible();
  await userEvent.click(screen.getByRole("tab", { name: "Подключение" }));
  expect(screen.getByRole("switch", { name: "Открыть порт на WAN" })).not.toBeChecked();
  await userEvent.click(save());
  expect(draft(fetch).tunnels[0]).toMatchObject({ name: "vpn", role: "server", listen_port: 51820, open_port: false });
});
it("imports client conf with recognized fields and preserves Address; rejects PSK", async () => {
  const fetch = await mount(<Tunnels />);
  const privateKey = `${"A".repeat(43)}=`;
  const publicKey = `${"B".repeat(43)}=`;
  await userEvent.click(screen.getByRole("button", { name: "Импорт .conf" }));
  const conf = `[Interface]\nAddress = 10.9.8.7/24\nPrivateKey = ${privateKey}\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = vpn.example.org:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25`;
  fill("Содержимое .conf", conf + `\nPresharedKey = ${publicKey}`);
  await userEvent.click(screen.getByRole("button", { name: "Показать распознанные поля" }));
  expect(screen.getByText(/PresharedKey не поддерживается/)).toBeVisible();
  fill("Содержимое .conf", conf);
  await userEvent.click(screen.getByRole("button", { name: "Показать распознанные поля" }));
  expect(screen.getByText(/Address 10.9.8.7\/24/)).toBeVisible();
  expect(screen.getByText(/endpoint vpn.example.org:51820/)).toBeVisible();
  await userEvent.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Импорт .conf" })).not.toBeInTheDocument());
  expect(screen.getByLabelText("Имя туннеля")).toHaveValue("tunnel1");
  expect(fetch.mock.calls.filter(([p]) => p === "/api/keygen/tunnel")).toHaveLength(0);
  await userEvent.click(save());
  expect(draft(fetch).interfaces[0].addresses).toEqual(["10.9.8.7/24"]);
  expect(draft(fetch).tunnels[0].private_key).toEqual({ plaintext: privateKey });
});
it("retains secret and only edits selected tunnel; delete requires confirmation", async () => {
  const fetch = await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] });
  await openTunnel();
  await userEvent.click(screen.getByRole("tab", { name: "Подключение" }));
  fill("Порт", "51821");
  await userEvent.click(save());
  expect(draft(fetch).tunnels[0].private_key).toEqual({ redacted: true });
  expect(draft(fetch).tunnels[0].listen_port).toBe(51821);
});
it("confirmation removes tunnel and auto interface only from draft", async () => {
  const config: Configuration = { ...emptyConfiguration, tunnels: [server], interfaces: [{ name: "tun0", type: "physical", zone: "lan", addressing: "static", addresses: [], description: "vpn", parent: null, vlan_id: null, members: [] }] };
  const fetch = await mount(<Tunnels />, config);
  await openTunnel();
  await userEvent.click(screen.getByRole("button", { name: "Удалить vpn" }));
  const dialog = screen.getByRole("dialog", { name: "Удалить туннель?" });
  expect(within(dialog).getByText(/проверьте зависимости/i)).toBeVisible();
  expect(fetch.mock.calls.filter(([p]) => p === "/api/draft")).toHaveLength(0);
  await userEvent.click(within(dialog).getByRole("button", { name: "Удалить из черновика" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить туннель?" })).not.toBeInTheDocument());
  await userEvent.click(save());
  expect(draft(fetch).tunnels).toEqual([]);
  expect(draft(fetch).interfaces).toEqual([]);
});
it("surfaces keygen failure and keeps save error in editor", async () => {
  await mount(<Tunnels />, { ...emptyConfiguration, tunnels: [server] }, true, async () => new Response(JSON.stringify({ message: "Генерация не удалась" }), { status: 500 }));
  await openTunnel();
  await userEvent.click(screen.getByRole("tab", { name: "Ключи" }));
  await userEvent.click(screen.getByRole("button", { name: "Сгенерировать ключи" }));
  expect((await screen.findAllByRole("alert")).some((alert) => alert.textContent?.includes("Генерация не удалась"))).toBe(true);
  await userEvent.click(screen.getByRole("tab", { name: "Подключение" }));
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
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить DDNS" }));
  fill("Имя DDNS", "home"); fill("Hostname DDNS", "home.example.org"); fill("Провайдер", provider);
  if (provider === "cloudflare") fill("Zone", "example.org");
  else { fill("Сервер DNS", "192.0.2.53"); fill("Key name", "home_key"); }
  fill("API token / TSIG key", "token");
  await userEvent.click(save());
  expect(draft(fetch).ddns[0]).toMatchObject({ provider, api_token: { plaintext: "token" }, wan_interface: "eth0" });
});
