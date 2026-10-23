import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import App from "../App";
import { emptyConfiguration, sampleConfiguration } from "../fixtures";
import type { Configuration, HostProfile } from "../types";

const panel: HostProfile = { profile: "panel", declared: true, dhcp: true };
const router: HostProfile = { profile: "router", declared: true, dhcp: true };
const legacy: HostProfile = { profile: null, declared: false, dhcp: true };
const configuration: Configuration = {
  ...emptyConfiguration,
  subscribers: [{ name: "alice", label: "Алиса" }, { name: "bob", label: null }],
  tunnels: [{ ...sampleConfiguration.tunnels[0], name: "wg_home", peers: [
    { ...sampleConfiguration.tunnels[0].peers[0], name: "phone", subscriber: "alice" },
    { ...sampleConfiguration.tunnels[0].peers[0], name: "laptop", subscriber: "alice" },
    { ...sampleConfiguration.tunnels[0].peers[0], name: "service", subscriber: null },
  ] }, { ...sampleConfiguration.tunnels[0], name: "wg_work", peers: [
    { ...sampleConfiguration.tunnels[0].peers[0], name: "tablet", subscriber: "bob" },
  ] }],
};

function setup(path: string, config: Configuration = configuration, host: HostProfile = panel,
  role: "admin" | "operator" = "admin") {
  const tariffs = [{ id: 7, name: "Базовый", device_limit: 3, term_days: 30, price_amount: null }];
  const fetch = vi.fn((url: string, init?: RequestInit) => {
    if (url === "/api/portal-admin/tariffs" && init?.method === "POST") {
      return Promise.resolve(new Response(JSON.stringify({ id: 8, ...JSON.parse(String(init.body)) }), { status: 201 }));
    }
    if (url === "/api/portal-admin/subscribers/alice/invite") {
      return Promise.resolve(new Response(JSON.stringify({
        token: "tok123", subscriber_name: "alice", expires_at: "2026-10-30T00:00:00Z",
        invite_path: "/invite/tok123", ...(JSON.parse(String(init?.body)).activate ? { password: "s3cret-password" } : {}),
      }), { status: 201 }));
    }
    if (url === "/api/portal-admin/subscribers/alice/subscription") {
      return Promise.resolve(new Response(JSON.stringify({
        subscriber_name: "alice", tariff_id: 7, expires_at: "2099-01-01T00:00:00Z", status: "active",
      })));
    }
    if (/^\/api\/portal-admin\/subscribers\/[^/]+\/subscription$/.test(url)) {
      return Promise.resolve(new Response(JSON.stringify({ error: { code: "portal.subscription_not_found" } }), { status: 404 }));
    }
    return Promise.resolve(new Response(JSON.stringify(
      url === "/api/versions" ? [{ id: 1, status: "draft", configuration: config }] :
      url === "/api/auth/me" ? { id: 1, username: role, role } :
      url === "/api/host/profile" ? host :
      url === "/api/apply/status" ? null :
      url === "/api/status/services" ? { generated_at: "2026-01-01", services: [] } :
      url === "/api/tunnels/activity" ? {} :
      url === "/api/draft" ? { id: 1, status: "draft", configuration: JSON.parse(String(init?.body)) } :
      url === "/api/portal-admin/tariffs" ? tariffs :
      {},
    )));
  });
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
  return fetch;
}

function saved(fetch: ReturnType<typeof vi.fn>) {
  const call = fetch.mock.calls.find(([url, init]) => url === "/api/draft" && init?.method === "PUT");
  expect(call).toBeTruthy();
  return JSON.parse(String(call![1].body)) as Configuration;
}

it("criterion_1_lists_subscribers_and_counts_devices_across_tunnels", async () => {
  setup("/subscribers");
  const table = within((await screen.findAllByRole("table"))[0]!);
  const alice = table.getByRole("row", { name: /alice — Алиса/ });
  expect(within(alice).getByRole("cell", { name: "2" })).toBeVisible();
  expect(within(alice).getByText("wg_home / phone, wg_home / laptop")).toBeVisible();
  const bob = table.getByRole("row", { name: /bob/ });
  expect(within(bob).getByRole("cell", { name: "1" })).toBeVisible();
  expect(within(bob).getByText("wg_work / tablet")).toBeVisible();
  expect(table.queryByText("wg_home / service")).not.toBeInTheDocument();
});

it("criterion_2_creates_subscriber_in_exact_saved_array_and_refuses_duplicate", async () => {
  const fetch = setup("/subscribers");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "+ Абонент" }));
  const dialog = screen.getByRole("dialog", { name: "Абонент: Новый абонент" });
  await user.type(within(dialog).getByLabelText(/Имя абонента/), "alice");
  expect(within(dialog).getByText(/subscriber.duplicate_name/)).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeDisabled();
  await user.clear(within(dialog).getByLabelText(/Имя абонента/));
  await user.type(within(dialog).getByLabelText(/Имя абонента/), "carol");
  await user.type(within(dialog).getByLabelText("Описание"), "Кэрол");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === "/api/draft")).toBe(true));
  expect(saved(fetch).subscribers).toEqual([
    { name: "alice", label: "Алиса" }, { name: "bob", label: null },
    { name: "carol", label: "Кэрол" },
  ]);
});

it("criterion_3_blocks_referenced_subscriber_deletion_and_names_every_device", async () => {
  const fetch = setup("/subscribers");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Удалить абонента alice" }));
  const dialog = screen.getByRole("dialog", { name: "Удалить абонента?" });
  expect(within(dialog).getByText(/wg_home \/ phone, wg_home \/ laptop/)).toBeVisible();
  await user.click(within(dialog).getByRole("button", { name: "Понятно" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить абонента?" })).not.toBeInTheDocument());
  expect(fetch.mock.calls.filter(([url]) => url === "/api/draft")).toHaveLength(0);
  expect(screen.getByRole("button", { name: "Удалить абонента alice" })).toBeVisible();
});

it("criterion_4_peer_editor_saves_subscriber_and_null_for_service_peer", async () => {
  const fetch = setup("/tunnels");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("tab", { name: "Серверы" }));
  await user.click((await screen.findAllByRole("button", { name: "Открыть" }))[0]);
  expect(screen.getByRole("dialog", { name: /Туннель: / }).querySelector("input, select, textarea")).toBeNull();
  await user.click(within(screen.getByRole("dialog", { name: /Туннель: / })).getByRole("button", { name: "Изменить" }));
  await user.click(screen.getByRole("tab", { name: "Пиры" }));
  const peerRow = within(screen.getByRole("row", { name: /phone/ }));
  await user.click(peerRow.getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: "Пир: phone" });
  await user.selectOptions(within(dialog).getByLabelText("Абонент"), "bob");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === "/api/draft")).toBe(true));
  expect(saved(fetch).tunnels[0].peers.find((peer) => peer.name === "phone")?.subscriber).toBe("bob");
  await user.click(await screen.findByRole("tab", { name: "Серверы" }));
  await user.click((await screen.findAllByRole("button", { name: "Открыть" }))[0]);
  expect(screen.getByRole("dialog", { name: /Туннель: / }).querySelector("input, select, textarea")).toBeNull();
  await user.click(within(screen.getByRole("dialog", { name: /Туннель: / })).getByRole("button", { name: "Изменить" }));
  await user.click(screen.getByRole("tab", { name: "Пиры" }));
  await user.click(within(screen.getByRole("row", { name: /laptop/ })).getByRole("button", { name: "Изменить" }));
  const second = screen.getByRole("dialog", { name: "Пир: laptop" });
  await user.selectOptions(within(second).getByLabelText("Абонент"), "");
  await user.click(within(second).getByRole("button", { name: "Сохранить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.filter(([url]) => url === "/api/draft")).toHaveLength(2));
  const payload = JSON.parse(String(fetch.mock.calls.filter(([url]) => url === "/api/draft")[1]?.[1]?.body)) as Configuration;
  expect(payload.tunnels[0].peers.find((peer) => peer.name === "laptop")?.subscriber).toBeNull();
});

it.each([
  ["router", router, false],
  ["legacy", legacy, true],
] as const)("criterion_5_%s_profile_gates_nav_and_direct_route", async (_, host, available) => {
  setup("/subscribers", configuration, host);
  await screen.findByText(host.profile === "router" ? "vs-router" : /Продукт не заявлен/);
  const nav = screen.getByRole("navigation", { name: "Разделы панели" });
  await waitFor(() => expect(within(nav).queryByRole("link", { name: "Абоненты" }) !== null).toBe(available));
  await waitFor(() => expect(screen.queryByRole("heading", { name: "Абоненты", level: 1 }) !== null).toBe(available));
});

it("unreferenced subscriber is removed from the saved draft", async () => {
  const config = { ...configuration, subscribers: [...configuration.subscribers!, { name: "carol", label: null }] };
  const fetch = setup("/subscribers", config);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Удалить абонента carol" }));
  const dialog = screen.getByRole("dialog", { name: "Удалить абонента?" });
  await user.click(within(dialog).getByRole("button", { name: "Удалить из черновика" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === "/api/draft")).toBe(true));
  expect(saved(fetch).subscribers).toEqual(configuration.subscribers);
});

it("operator_can_read_but_cannot_edit_subscribers", async () => {
  setup("/subscribers", configuration, panel, "operator");
  expect(await screen.findByRole("cell", { name: "alice — Алиса" })).toBeVisible();
  expect(screen.queryByRole("button", { name: "+ Абонент" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Удалить абонента alice" })).not.toBeInTheDocument();
});

it("criterion_6_creates_tariff_and_lists_it", async () => {
  const fetch = setup("/subscribers");
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "+ Тариф" }));
  const dialog = screen.getByRole("dialog", { name: "Тариф: новый" });
  await user.type(within(dialog).getByLabelText(/^Название/), "Премиум");
  await user.type(within(dialog).getByLabelText(/Лимит устройств/), "5");
  await user.type(within(dialog).getByLabelText(/Срок подписки/), "90");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url, init]) =>
    url === "/api/portal-admin/tariffs" && init?.method === "POST")).toBe(true));
  const body = JSON.parse(String(fetch.mock.calls.find(([url, init]) =>
    url === "/api/portal-admin/tariffs" && init?.method === "POST")![1]!.body));
  expect(body).toEqual({ name: "Премиум", device_limit: 5, term_days: 90 });
});

it("criterion_7_invite_needs_tariff_and_ready_password_is_warned", async () => {
  const fetch = setup("/subscribers");
  const user = userEvent.setup();
  const table = within((await screen.findAllByRole("table"))[0]!);
  await user.click(await within(table.getByRole("row", { name: /alice — Алиса/ }))
    .findByRole("button", { name: "Пригласить" }));
  const dialog = screen.getByRole("dialog", { name: "Приглашение: alice" });
  await user.click(within(dialog).getByRole("checkbox"));
  expect(within(dialog).getByText(/перехватывается вместе со ссылкой/i)).toBeVisible();
  await user.click(within(dialog).getByRole("button", { name: "Выслать приглашение" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url]) =>
    url === "/api/portal-admin/subscribers/alice/invite")).toBe(true));
  const body = JSON.parse(String(fetch.mock.calls.find(([url]) =>
    url === "/api/portal-admin/subscribers/alice/invite")![1]!.body));
  expect(body).toEqual({ tariff_id: 7, activate: true });
  expect(await within(dialog).findByLabelText(/Ссылка-приглашение/)).toHaveValue("/invite/tok123");
  expect(await within(dialog).findByLabelText("Пароль")).toHaveValue("s3cret-password");
  expect(within(dialog).getByRole("button", { name: "Отозвать" })).toBeEnabled();
});

it("criterion_8_subscription_dialog_shows_badge_and_renews", async () => {
  const fetch = setup("/subscribers");
  const user = userEvent.setup();
  const table = within((await screen.findAllByRole("table"))[0]!);
  await waitFor(() => expect(within(table.getByRole("row", { name: /alice — Алиса/ }))
    .getByText("Активна")).toBeVisible());
  await user.click(within(table.getByRole("row", { name: /alice — Алиса/ }))
    .getByRole("button", { name: "Подписка" }));
  const dialog = await screen.findByRole("dialog", { name: "Подписка: alice" });
  await user.click(within(dialog).getByRole("button", { name: "Продлить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([url, init]) =>
    url === "/api/portal-admin/subscribers/alice/subscription" && init?.method === "PATCH"
      && JSON.parse(String(init.body)).renew === true)).toBe(true));
});
