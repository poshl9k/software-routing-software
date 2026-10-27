import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { ProxiesEditor } from "../pages/RoutingProxy";
import { Tunnels } from "../pages/ConnectionEditors";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { Configuration, ProxyGroup, Tunnel } from "../types";

const client: Tunnel = {
  name: "remote", interface: "tun1", role: "client", protocol: "wg",
  private_key: { redacted: true }, listen_port: null, peers: [],
  endpoint: "remote.example:51820", server_public_key: "server-public", allowed_ips: ["0.0.0.0/0"],
  keepalive: 25, obfuscation: {}, preshared_key: null, header_protection_key: null,
  random_trailers: false, disable_cookies: false, open_port: false,
};
const configuration = (groups: ProxyGroup[] = []): Configuration => ({
  ...emptyConfiguration,
  interfaces: ["eth0", "tun0", "tun1"].map((name) => ({
    name, type: "physical", zone: name === "eth0" ? "wan" : "lan", description: null,
    addressing: "static", addresses: [], parent: null, vlan_id: null, members: [],
  })),
  tunnels: [client, { ...client, name: "server", interface: "tun0", role: "server", listen_port: 51820 }],
  proxies: { ...emptyConfiguration.proxies, groups, outbounds: [{
    tag: "proxy", type: "vless", server: "proxy.example", port: 443,
    secret: { redacted: true }, method: null, tls: true, tls_server_name: null,
    tls_insecure: false, admin_listen: null,
  }] },
});
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
type Telemetry = () => Response | Promise<Response>;
async function mount(page: React.ReactNode, config = configuration(), telemetry: Telemetry = () => json({}), runtime: Telemetry = () => json({})) {
  const fetch = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === "/api/versions") return json([{ id: 1, status: "confirmed", configuration: config }]);
    if (path === "/api/status/services") return json({ generated_at: "2026-01-01T00:00:00Z", services: [] });
    if (path === "/api/tunnels/availability") return telemetry();
    if (path === "/api/runtime/proxies") return runtime();
    if (path === "/api/draft") return json({ id: 2, status: "draft", configuration: JSON.parse(String(init?.body)) });
    return json({});
  });
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider>{page}</RouterProvider></MemoryRouter>);
  await waitFor(() => expect(screen.getByRole("button", { name: page && (page as { type: unknown }).type === Tunnels
    ? "+ Добавить туннель" : "Редактировать" })).toBeEnabled());
  return fetch;
}
const writes = (fetch: ReturnType<typeof vi.fn>) => fetch.mock.calls.filter(([path]) => path === "/api/draft");
const saved = (fetch: ReturnType<typeof vi.fn>) => JSON.parse(String(writes(fetch).at(-1)?.[1]?.body)) as Configuration;
const composite: ProxyGroup = { tag: "mixed", type: "urltest", outbounds: [],
  exits: [{ kind: "tunnel", name: "remote" }, { kind: "interface", interface: "eth0" }, { kind: "outbound", tag: "proxy" }],
  url: "https://probe.example/check", interval_minutes: 3, tolerance_ms: 25 };
async function editGroup() {
  await userEvent.click(screen.getByRole("button", { name: "Редактировать" }));
  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  return screen.getByRole("dialog", { name: /Группа выходов:/ });
}

it("creates ordered mixed exits with exact payload, no server devices, duplicates or implicit WAN", async () => {
  const fetch = await mount(<ProxiesEditor />);
  await userEvent.click(screen.getByRole("button", { name: "Редактировать" }));
  await userEvent.click(screen.getByRole("button", { name: "+ Добавить группу" }));
  const dialog = screen.getByRole("dialog", { name: /Группа выходов:/ });
  fireEvent.change(within(dialog).getByLabelText("Тег группы"), { target: { value: "mixed" } });
  await userEvent.selectOptions(within(dialog).getByLabelText("Тип группы"), "urltest");
  await userEvent.selectOptions(within(dialog).getByLabelText("Состав группы"), "exits");
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeDisabled();
  const picker = within(dialog).getByLabelText("Добавить участника");
  expect(within(picker).getAllByRole("option").map((o) => o.textContent)).toEqual([
    "Выберите выход", "через туннель remote", "через интерфейс eth0", "через прокси-выход proxy",
  ]);
  await userEvent.selectOptions(picker, "через туннель remote");
  expect(within(picker).getByRole("option", { name: "через туннель remote" })).toBeDisabled();
  expect(within(dialog).queryByText(/Включён WAN:/)).not.toBeInTheDocument();
  expect(within(dialog).getByText(/WAN не добавляется автоматически/)).toBeVisible();
  await userEvent.selectOptions(picker, "через интерфейс eth0");
  expect(within(dialog).getByText(/Включён WAN:/)).toBeVisible();
  await userEvent.selectOptions(picker, "через прокси-выход proxy");
  await userEvent.click(within(dialog).getByRole("button", { name: "Вверх: через прокси-выход proxy" }));
  expect(within(dialog).getByRole("button", { name: "Вверх: через туннель remote" })).toBeDisabled();
  expect(within(dialog).getByRole("button", { name: "Вниз: через интерфейс eth0" })).toBeDisabled();
  expect(within(dialog).getByText(/а не по фиксированному приоритету списка/)).toBeVisible();
  await userEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes(fetch)).toHaveLength(1));
  expect(saved(fetch).proxies.groups[0]).toEqual({ tag: "mixed", type: "urltest", outbounds: [],
    exits: [{ kind: "tunnel", name: "remote" }, { kind: "outbound", tag: "proxy" }, { kind: "interface", interface: "eth0" }],
    url: null, interval_minutes: null, tolerance_ms: null });
  expect(saved(fetch).tunnels).toEqual(configuration().tunnels);
  expect(saved(fetch).interfaces).toEqual(configuration().interfaces);
});

it("edits existing composite order/removal while preserving probe settings and blocking lossy mode changes", async () => {
  const fetch = await mount(<ProxiesEditor />, configuration([composite]));
  expect(screen.getByText(/через туннель remote, через интерфейс eth0, через прокси-выход proxy/)).toBeVisible();
  const dialog = await editGroup();
  expect(within(within(dialog).getByLabelText("Тип группы")).getByRole("option", { name: "selector" })).toBeDisabled();
  expect(within(within(dialog).getByLabelText("Состав группы")).getByRole("option", { name: /прежний формат/ })).toBeDisabled();
  await userEvent.click(within(dialog).getByRole("button", { name: "Удалить участника: через интерфейс eth0" }));
  await userEvent.click(within(dialog).getByRole("button", { name: "Вниз: через туннель remote" }));
  expect(within(dialog).queryByText(/Включён WAN:/)).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes(fetch)).toHaveLength(1));
  expect(saved(fetch).proxies.groups).toEqual([{ ...composite,
    exits: [{ kind: "outbound", tag: "proxy" }, { kind: "tunnel", name: "remote" }] }]);
});

it.each(["selector", "urltest"] as const)("keeps legacy %s groups unchanged when opened and saved", async (type) => {
  const legacy: ProxyGroup = { tag: "old", type, outbounds: ["proxy"], url: null, interval_minutes: null, tolerance_ms: 50 };
  const fetch = await mount(<ProxiesEditor />, configuration([legacy]));
  const dialog = await editGroup();
  expect(within(dialog).getByRole("checkbox", { name: "proxy" })).toBeChecked();
  expect(within(dialog).queryByLabelText("Добавить участника")).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes(fetch)).toHaveLength(1));
  expect(saved(fetch).proxies.groups).toEqual([legacy]);
});

it("explicit legacy conversion retains proxy members and clears the other representation", async () => {
  const legacy: ProxyGroup = { ...composite, exits: [], outbounds: ["proxy"] };
  const fetch = await mount(<ProxiesEditor />, configuration([legacy]));
  const dialog = await editGroup();
  await userEvent.selectOptions(within(dialog).getByLabelText("Состав группы"), "exits");
  await userEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes(fetch)).toHaveLength(1));
  expect(saved(fetch).proxies.groups).toEqual([{ ...legacy, outbounds: [], exits: [{ kind: "outbound", tag: "proxy" }] }]);
});

it.each([
  { ...composite, exits: [{ kind: "tunnel" as const, name: "server" }] },
  { ...composite, exits: [{ kind: "tunnel" as const, name: "missing" }] },
  { ...composite, outbounds: ["proxy"] },
  { ...composite, exits: [composite.exits![0], composite.exits![0]] },
])("blocks invalid composite members without silently changing the document: %j", async (group) => {
  const fetch = await mount(<ProxiesEditor />, configuration([group]));
  const dialog = await editGroup();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeDisabled();
  expect(writes(fetch)).toHaveLength(0);
});

it("shows all handshake states by tunnel name, missing/malformed data stay unknown, no availability claim", async () => {
  const names = ["recent", "stale", "never", "unknown", "missing", "malformed"];
  const config = { ...configuration(), tunnels: names.map((name, i) => ({ ...client, name, interface: `tun${i}` })) };
  const fetch = await mount(<Tunnels />, config, () => json({
    recent: { state: "recent_handshake", last_handshake: 1_700_000_000 },
    stale: { state: "stale_handshake", last_handshake: 1_600_000_000 },
    never: { state: "never_handshaked", last_handshake: 0 },
    unknown: { state: "unknown", last_handshake: null },
    malformed: { state: "recent_handshake", last_handshake: null },
  }));
  expect(await screen.findByText(/^Недавний handshake:/)).toBeVisible();
  expect(screen.getByText(/^Устаревший handshake:/)).toBeVisible();
  expect(screen.getByText("Handshake ещё не было")).toBeVisible();
  expect(screen.getAllByText("Handshake: состояние неизвестно")).toHaveLength(3);
  expect(screen.getByText(/а не сквозную доступность интернета/)).toBeVisible();
  expect(screen.queryByText("Доступен")).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledWith("/api/tunnels/availability", expect.objectContaining({ credentials: "include", signal: expect.any(AbortSignal) }));
  expect(writes(fetch)).toHaveLength(0);
});

it("shows unknown during loading and surfaces an availability HTTP error", async () => {
  let resolve!: (value: Response) => void;
  const pending = new Promise<Response>((done) => { resolve = done; });
  await mount(<Tunnels />, configuration(), () => pending);
  expect(screen.getByText("Handshake: состояние неизвестно")).toBeVisible();
  expect(screen.queryByText(/^Недавний handshake:/)).not.toBeInTheDocument();
  await act(async () => { resolve(json({ code: "availability.failed", message: "Нет данных handshake" }, 503)); });
  expect(await screen.findByText(/Нет данных handshake/)).toBeVisible();
  expect(screen.getByText("Handshake: состояние неизвестно")).toBeVisible();
});

it("polls handshake, hides cached success after failure, stops on server tab and never changes peer activity", async () => {
  let attempt = 0;
  const fetch = await mount(<Tunnels />, configuration(), () => ++attempt === 1
    ? json({ remote: { state: "recent_handshake", last_handshake: 1_700_000_000 } })
    : json({ code: "availability.failed", message: "Ошибка опроса handshake" }, 503));
  expect(await screen.findByText(/^Недавний handshake:/)).toBeVisible();
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  try {
    // Remount the interval by toggling the role tab.
    await userEvent.click(screen.getByRole("tab", { name: "Серверы" }));
    await userEvent.click(screen.getByRole("tab", { name: "Клиенты" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_000); });
    expect(await screen.findByText(/Ошибка опроса handshake/)).toBeVisible();
    expect(screen.queryByText(/^Недавний handshake:/)).not.toBeInTheDocument();
    expect(screen.getByText("Handshake: состояние неизвестно")).toBeVisible();
    const count = fetch.mock.calls.filter(([path]) => path === "/api/tunnels/availability").length;
    expect(count).toBe(2);
    await userEvent.click(screen.getByRole("tab", { name: "Серверы" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(fetch.mock.calls.filter(([path]) => path === "/api/tunnels/availability")).toHaveLength(count);
    expect(fetch.mock.calls.filter(([path]) => path === "/api/tunnels/activity")).toHaveLength(0);
    expect(screen.queryByText(/Handshake:/)).not.toBeInTheDocument();
  } finally { vi.useRealTimers(); }
});

it("does not request availability for server-only configuration", async () => {
  const fetch = await mount(<Tunnels />, { ...configuration(), tunnels: [configuration().tunnels[1]] });
  expect(fetch.mock.calls.filter(([path]) => path === "/api/tunnels/availability")).toHaveLength(0);
});

it("malformed map is a visible error, never healthy", async () => {
  await mount(<Tunnels />, configuration(), () => json(null));
  expect(await screen.findByText("Некорректные данные handshake туннелей")).toBeVisible();
  expect(screen.getByText("Handshake: состояние неизвестно")).toBeVisible();
});

it("shows live URL-test status per channel separately from handshake and draft", async () => {
  const now = new Date().toISOString();
  const fetch = await mount(<ProxiesEditor />, configuration([composite]), () => json({}), () => json({ proxies: {
    mixed: { type: "URLTest", now: "routing-tunnel:remote", all: ["routing-tunnel:remote", "exit_eth0", "proxy"] },
    "routing-tunnel:remote": { history: [{ time: now, delay: 48 }] },
    exit_eth0: { history: [{ time: now, delay: 0 }] },
    proxy: { history: [{ time: "2020-01-01T00:00:00Z", delay: 15 }] },
  } }));
  expect(await screen.findByText("Сейчас выбран выход: routing-tunnel:remote")).toBeVisible();
  expect(screen.getByText("routing-tunnel:remote: URL доступен (48 мс)")).toBeVisible();
  expect(screen.getByText("exit_eth0: URL недоступен")).toBeVisible();
  expect(screen.getByText("proxy: нет свежей проверки")).toBeVisible();
  expect(screen.getByText(/от работающего sing-box, не от черновика/)).toBeVisible();
  expect(fetch).toHaveBeenCalledWith("/api/runtime/proxies", expect.objectContaining({ credentials: "include" }));
});

it("does not claim URL availability if runtime API fails", async () => {
  await mount(<ProxiesEditor />, configuration([composite]), () => json({}),
    () => json({ code: "clash.unavailable", message: "Движок недоступен" }, 503));
  expect(await screen.findByText(/Движок недоступен/)).toBeVisible();
  expect(screen.getByText("Активный выход неизвестен")).toBeVisible();
  expect(screen.queryByText(/URL доступен \(/)).not.toBeInTheDocument();
});
