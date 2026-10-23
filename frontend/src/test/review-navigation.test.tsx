import { render, renderHook, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import App, { navigation } from "../App";
import { emptyConfiguration } from "../fixtures";
import { useHostProfile } from "../hooks/useHostProfile";
import { queryKeys } from "../query";
import type { HostProfile } from "../types";

const versions = [
  { id: 3, status: "draft", configuration: emptyConfiguration },
  { id: 2, status: "draft", configuration: emptyConfiguration },
  { id: 1, status: "confirmed", configuration: emptyConfiguration },
];

function open(path: string, rows = versions) {
  const fetch = vi.fn((url: string) => Promise.resolve(new Response(JSON.stringify(
    url === "/api/versions" ? rows :
    url === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
    url === "/api/apply/status" ? null :
    url === "/api/host/interfaces" ? [] :
    url.startsWith("/api/diff") ? { changes: [], summary: [] } :
    url === "/api/apply" ? { version_id: 2, status: "confirmed", phases: {} } : {},
  ))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
  return fetch;
}

it("opens review from the topbar without applying a draft", async () => {
  const fetch = open("/");
  const review = await screen.findByRole("link", { name: "Проверить изменения" });
  await userEvent.click(review);
  expect(await screen.findByRole("heading", { name: "Применение изменений", level: 1 })).toBeVisible();
  expect(fetch.mock.calls.some(([url]) => url === "/api/apply")).toBe(false);
});

it("applies from the action strip only after dialog confirmation, without navigating", async () => {
  localStorage.setItem("vs-router.preferences", JSON.stringify({ safe: true, timeout: 180 }));
  const fetch = open("/");
  const apply = await screen.findByRole("button", { name: "Применить" });
  const strip = document.querySelector(".page-actions")!;
  const rail = document.querySelector(".sidebar .configuration-rail")!;
  await waitFor(() => expect(apply).toBeEnabled());
  expect(within(strip as HTMLElement).getByRole("link", { name: "Проверить изменения" })).toHaveAttribute("href", "/apply");
  expect(within(rail as HTMLElement).getByText("Есть изменения, ожидающие применения")).toBeVisible();
  expect(within(rail as HTMLElement).queryByRole("button")).not.toBeInTheDocument();
  expect(within(rail as HTMLElement).queryByRole("link")).not.toBeInTheDocument();
  await userEvent.click(apply);
  let dialog = screen.getByRole("dialog", { name: "Применить изменения?" });
  expect(within(dialog).getByText(/Через 180 с потребуется подтверждение/)).toBeVisible();
  expect(fetch.mock.calls.some(([url]) => url === "/api/apply")).toBe(false);
  expect(screen.queryByRole("heading", { name: "Применение изменений" })).not.toBeInTheDocument();
  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  expect(fetch.mock.calls.some(([url]) => url === "/api/apply")).toBe(false);
  await userEvent.click(apply);
  dialog = screen.getByRole("dialog", { name: "Применить изменения?" });
  await userEvent.click(within(dialog).getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(fetch).toHaveBeenCalledWith("/api/apply", expect.objectContaining({
    method: "POST", body: expect.stringContaining('"version_id":3'),
  })));
  expect(screen.queryByRole("heading", { name: "Применение изменений" })).not.toBeInTheDocument();
});

it("warns that the first apply has no rollback target", async () => {
  localStorage.setItem("vs-router.preferences", JSON.stringify({ safe: true, timeout: 180 }));
  const fetch = open("/", [versions[0]]);
  const apply = await screen.findByRole("button", { name: "Применить" });
  await waitFor(() => expect(apply).toBeEnabled());
  await userEvent.click(apply);
  expect(within(screen.getByRole("dialog", { name: "Применить изменения?" }))
    .getByText("Стабильной версии нет: это первое применение, откатывать будет некуда")).toBeVisible();
  expect(fetch.mock.calls.some(([url]) => url === "/api/apply")).toBe(false);
});

it("applies the draft selected for review", async () => {
  const fetch = open("/apply");
  const draft = await screen.findByRole("combobox", { name: "Черновик" });
  const apply = () => screen.getAllByRole("button", { name: "Применить" }).at(-1)!;
  await waitFor(() => expect(apply()).toBeEnabled());
  await userEvent.selectOptions(draft, "2");
  expect(draft).toHaveValue("2");
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === "/api/diff/1/2")).toBe(true));
  expect(screen.getByRole("heading", { name: "Изменения" })).toBeVisible();
  await userEvent.click(apply());
  await waitFor(() => expect(fetch).toHaveBeenCalledWith("/api/apply", expect.objectContaining({
    body: expect.stringContaining('"version_id":2'),
  })));
});

it("mobile drawer preserves grouped navigation, configuration, keyboard escape and focus return", async () => {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: query === "(prefers-reduced-motion: reduce)",
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  open("/");
  const menu = await screen.findByRole("button", { name: "Разделы" });
  const status = screen.getByRole("link", { name: /Конфигурация: .*Открыть применение/ });
  expect(status).toHaveAttribute("href", "/apply");
  await userEvent.click(menu);
  const drawer = screen.getByRole("dialog");
  expect(within(drawer).getByRole("navigation", { name: "Разделы панели" })).toBeVisible();
  expect(within(drawer).getByRole("region", { name: "Интернет" })).toBeVisible();
  expect(within(drawer).getByRole("complementary", { name: "Состояние конфигурации" })).toBeVisible();
  expect(within(drawer).queryByRole("link", { name: "Проверить изменения" })).not.toBeInTheDocument();
  expect(document.querySelector('.page-actions a[href="/apply"]')).toHaveTextContent("Проверить изменения");
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(menu).toHaveFocus();
  await userEvent.click(menu);
  await userEvent.click(within(screen.getByRole("dialog")).getByRole("link", { name: "Туннели" }));
  expect(await screen.findByRole("heading", { name: "Туннели", level: 1 })).toBeVisible();
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});

it("labels the events page and explains that its journal is unavailable", async () => {
  open("/events");
  expect(await screen.findByRole("heading", { name: "Журнал событий", level: 1 })).toBeVisible();
  expect(screen.getByText("Просмотр событий пока не подключён к API.")).toBeVisible();
});

/** Product identity and DHCP availability come from the host profile, not management. */
const profile = (dhcp: boolean, product: HostProfile["profile"] = dhcp ? "router" : "panel", declared = true): HostProfile =>
  ({ profile: product, declared, dhcp });

function openOn(path: string, hostProfile: unknown = profile(true), management: unknown = { dhcp: false }) {
  const fetch = vi.fn((url: string) => Promise.resolve(new Response(JSON.stringify(
    url === "/api/versions" ? versions :
    url === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
    url === "/api/apply/status" ? null :
    url === "/api/host/profile" ? hostProfile :
    url === "/api/host/management" ? management :
    url === "/api/host/interfaces" ? [] : {},
  ))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
  return fetch;
}

const nav = () => screen.getByRole("navigation", { name: "Разделы панели" });
const navHrefs = () => within(nav()).getAllByRole("link").map((link) => link.getAttribute("href"));
const otherHrefs = navigation.flatMap(({ items }) => items.map(({ to }) => to)).filter((to) => to !== "/dhcp");
const noProductClaim = () => expect(document.body.textContent).not.toMatch(/vs-(?:router|panel)/i);

it("criterion_1_useHostProfile_fetches_real_endpoint_and_shares_query_key_cache", async () => {
  const expected = profile(false);
  const fetch = vi.fn(() => Promise.resolve(new Response(JSON.stringify(expected))));
  vi.stubGlobal("fetch", fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) =>
    <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const first = renderHook(() => useHostProfile(), { wrapper });
  const second = renderHook(() => useHostProfile(), { wrapper });
  await waitFor(() => expect(first.result.current.isSuccess).toBe(true));
  expect(second.result.current.data).toEqual(expected);
  expect(client.getQueryData(queryKeys.hostProfile())).toEqual(expected);
  expect(client.getQueryCache().getAll()).toHaveLength(1);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch).toHaveBeenCalledWith("/api/host/profile", expect.objectContaining({ credentials: "include" }));
});

it.each([
  ["panel", "vs-panel"],
  ["router", "vs-router"],
] as const)("criterion_2_%s_marker_displays_%s", async (product, label) => {
  openOn("/", profile(product === "router", product));
  expect(await screen.findByText(label)).toBeVisible();
});

it("criterion_3_undeclared_profile_shows_capabilities_without_product_claim", async () => {
  openOn("/", profile(false, null, false));
  expect(await screen.findByText(/Продукт не заявлен/)).toBeVisible();
  expect(screen.getByText(/по возможностям хоста/)).toBeVisible();
  noProductClaim();
});

it("criterion_4_pending_read_never_claims_product", async () => {
  const fetch = vi.fn((url: string) => url === "/api/host/profile"
    ? new Promise<Response>(() => {})
    : Promise.resolve(new Response(JSON.stringify(url === "/api/auth/me"
      ? { id: 1, username: "admin", role: "admin" }
      : url === "/api/versions" ? versions : url === "/api/host/interfaces" ? [] : null))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={["/"]}><App /></MemoryRouter>);
  expect(await screen.findByText("Продукт не прочитан")).toBeVisible();
  noProductClaim();
});

it("criterion_4_failed_read_never_claims_product", async () => {
  const fetch = vi.fn((url: string) => Promise.resolve(url === "/api/host/profile"
    ? new Response(JSON.stringify({ code: "host.unavailable", message: "Недоступно" }), { status: 503 })
    : new Response(JSON.stringify(url === "/api/auth/me"
      ? { id: 1, username: "admin", role: "admin" }
      : url === "/api/versions" ? versions : url === "/api/host/interfaces" ? [] : null))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={["/"]}><App /></MemoryRouter>);
  await waitFor(() => expect(fetch.mock.calls.filter(([url]) => url === "/api/host/profile").length).toBeGreaterThan(1), { timeout: 3000 });
  expect(await screen.findByText("Продукт не прочитан")).toBeVisible();
  noProductClaim();
});

it("criterion_4_failed_refetch_suppresses_cached_identity", async () => {
  let fail = false;
  const fetch = vi.fn(() => Promise.resolve(fail
    ? new Response(JSON.stringify({ code: "host.unavailable", message: "Недоступно" }), { status: 503 })
    : new Response(JSON.stringify(profile(true)))));
  vi.stubGlobal("fetch", fetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) =>
    <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const { result } = renderHook(() => useHostProfile(), { wrapper });
  await waitFor(() => expect(result.current.data?.profile).toBe("router"));
  fail = true;
  await result.current.refetch();
  await waitFor(() => expect(result.current.isError).toBe(true));
  expect(result.current.data).toBeUndefined();
  expect(client.getQueryData(queryKeys.hostProfile())).toEqual(profile(true));
});

it("criterion_5_false_hides_DHCP_link_despite_management_claiming_true", async () => {
  const fetch = openOn("/", profile(false), { dhcp: true });
  await screen.findByText("vs-panel");
  expect(fetch.mock.calls.some(([url]) => url === "/api/host/profile")).toBe(true);
  expect(within(nav()).queryByRole("link", { name: "DHCP" })).not.toBeInTheDocument();
  expect(within(nav()).getByRole("link", { name: "DNS" })).toBeVisible();
});

it.each(["/dhcp", "/DHCP/", "/d%68cp"])("criterion_5_false_blocks_direct_DHCP_route_%s", async (path) => {
  openOn(path, profile(false), { dhcp: true });
  await screen.findByText("vs-panel");
  await waitFor(() => expect(screen.queryByRole("heading", { name: "DHCP (Kea)", level: 1 })).not.toBeInTheDocument());
  expect(within(nav()).queryByRole("link", { name: "DHCP" })).not.toBeInTheDocument();
});

it("criterion_6_true_keeps_DHCP_link_and_route_despite_management_false", async () => {
  openOn("/dhcp", profile(true), { dhcp: false });
  await screen.findByText("vs-router");
  expect(await screen.findByRole("heading", { name: "DHCP (Kea)", level: 1 })).toBeVisible();
  expect(within(nav()).getByRole("link", { name: "DHCP" })).toHaveAttribute("href", "/dhcp");
});

it("criterion_6_older_profile_record_keeps_DHCP_link_and_route", async () => {
  openOn("/dhcp", {});
  expect(await screen.findByRole("heading", { name: "DHCP (Kea)", level: 1 })).toBeVisible();
  expect(within(nav()).getByRole("link", { name: "DHCP" })).toBeVisible();
  expect(screen.getByText("Продукт не прочитан")).toBeVisible();
});

it("criterion_6_unread_profile_keeps_DHCP_link_and_route", async () => {
  const fetch = vi.fn((url: string) => url === "/api/host/profile"
    ? new Promise<Response>(() => {})
    : Promise.resolve(new Response(JSON.stringify(url === "/api/auth/me"
      ? { id: 1, username: "admin", role: "admin" }
      : url === "/api/versions" ? versions : url === "/api/host/interfaces" ? [] : null))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={["/dhcp"]}><App /></MemoryRouter>);
  expect(await screen.findByRole("heading", { name: "DHCP (Kea)", level: 1 })).toBeVisible();
  expect(within(nav()).getByRole("link", { name: "DHCP" })).toBeVisible();
});

it("hides the DHCP section where the host has no DHCP server", async () => {
  openOn("/", profile(false));
  await screen.findByText("vs-panel");
  expect(within(nav()).queryByRole("link", { name: "DHCP" })).not.toBeInTheDocument();
  expect(within(nav()).getByRole("link", { name: "DNS" })).toBeVisible();
});

it("redirects away from the DHCP page where the host has no DHCP server", async () => {
  openOn("/dhcp", profile(false));
  await screen.findByText("vs-panel");
  await waitFor(() => expect(screen.queryByRole("heading", { name: "DHCP (Kea)", level: 1 })).not.toBeInTheDocument());
});

it("keeps the DHCP section when the host record does not say", async () => {
  openOn("/dhcp", {});
  expect(await screen.findByRole("heading", { name: "DHCP (Kea)", level: 1 })).toBeVisible();
  expect(within(nav()).getByRole("link", { name: "DHCP" })).toBeVisible();
});

it.each([false, true])("criterion_7_other_navigation_unchanged_when_DHCP_is_%s", async (dhcp) => {
  openOn("/", profile(dhcp));
  await screen.findByText(dhcp ? "vs-router" : "vs-panel");
  // Subscribers exist only on the panel (ADR-0018/0026), so a router host hides
  // exactly that one item — and nothing else moves in either direction.
  const hidden = dhcp ? ["/subscribers"] : [];
  expect(navHrefs().filter((to) => to !== "/dhcp"))
    .toEqual(otherHrefs.filter((to) => !hidden.includes(to)));
});
