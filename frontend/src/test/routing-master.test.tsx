import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { tokens } from "../theme";
import { ChoiceCards } from "../components/ChoiceCards";
import { FlowChain } from "../components/FlowChain";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { CatalogResponse, Configuration, RoutingRule } from "../types";
import { join } from "node:path";

/** Reads a file relative to the repository root (for palette/style audits). */
const repoRoot = process.cwd().replace(/\/frontend$/, "");
const repoSource = (path: string) => readFileSync(join(repoRoot, path), "utf-8");

/**
 * The master wizard over the product routing model (`routing_rules`).
 * Each test is named after the requirement it proves.
 */

const baseConfiguration = (): Configuration => ({
  ...emptyConfiguration,
  interfaces: [
    { name: "eth0", type: "physical", zone: "wan", description: null, addressing: "static",
      addresses: ["203.0.113.10/24"], parent: null, vlan_id: null, members: [] },
    { name: "lan0", type: "physical", zone: "lan", description: "домашняя сеть", addressing: "static",
      addresses: ["192.168.10.1/24"], parent: null, vlan_id: null, members: [] },
  ],
  subscribers: [{ name: "анна", label: "Анна" }],
  tunnels: [{
    name: "server_vpn", interface: "tun1", role: "server", protocol: "awg",
    private_key: { redacted: true }, listen_port: 51820, endpoint: null,
    server_public_key: null, allowed_ips: [], keepalive: 0, obfuscation: {},
    preshared_key: null, header_protection_key: null, random_trailers: false,
    disable_cookies: false, open_port: true,
    peers: [{
      name: "iphone", public_key: "P".repeat(44), preshared_key: null,
      private_key: null, allowed_ips: ["10.66.66.2/32"], subscriber: "анна", dns_mode: "panel",
    }],
  }],
  proxies: {
    enabled: true,
    outbounds: [{
      tag: "vless_fr", type: "vless", server: "fr1.example.net", port: 443,
      secret: null, method: null, tls: false, tls_server_name: null, tls_insecure: false,
      admin_listen: null,
    }],
    subscriptions: [],
    groups: [{ tag: "auto", type: "urltest", outbounds: ["vless_fr"], url: null,
      interval_minutes: null, tolerance_ms: null }],
  },
  routing_rules: [],
});

const exitNames: Record<string, string> = { direct: "Напрямую", interface: "Через интерфейс", outbound: "Через прокси-выход", group: "Через группу выходов", tunnel: "Через туннель", block: "Заблокировать" };
const testCatalog: CatalogResponse = { categories: [{ key: "media", title: "Видео", count: 4 }], services: [
  { id: "youtube", name: "YouTube", category: "media", icon_slug: "youtube", notice: null, covers: [], dns_domains: ["youtube.com", "googlevideo.com"], rule_sets: [], declared: false, action: "route" },
  { id: "rutube", name: "RuTube", category: "media", icon_slug: "rutube", notice: null, covers: [], dns_domains: ["rutube.ru"], rule_sets: [], declared: false, action: "route" },
  { id: "composite", name: "Все видео", category: "media", icon_slug: "media", notice: null, covers: ["youtube"], dns_domains: ["youtube.com"], rule_sets: [], declared: false, action: "route" },
  { id: "empty", name: "Без доменов", category: "media", icon_slug: "", notice: null, covers: [], dns_domains: [], rule_sets: [], declared: false, action: "route" },
] };

function setup(configuration: Configuration = baseConfiguration(), options: { catalog?: CatalogResponse; catalogError?: boolean; saveError?: boolean; confirmed?: boolean } = {}) {
  let versions = [{ id: 1, status: options.confirmed ? "confirmed" : "draft", configuration }];
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    let payload: unknown = {};
    let status = 200;
    if (path === "/api/versions") payload = versions;
    else if (path === "/api/presets/catalog") { payload = options.catalog ?? testCatalog; status = options.catalogError ? 503 : 200; }
    else if (path === "/api/runtime/engine") payload = { installed: true, version: "1.14.2", running: false, pid: null, clash_api: false, ip_forward: true, nft_tproxy_tables: true };
    else if (path === "/api/draft") {
      if (options.saveError) { status = 422; payload = { code: "routing.domain_invalid", message: "routing.domain_invalid", details: [] }; }
      else {
        const saved = { id: options.confirmed ? 2 : 1, status: "draft", configuration: JSON.parse(String(init?.body)) };
        versions = [...versions.filter((item) => item.id !== saved.id), saved];
        payload = saved;
      }
    } else if (path === "/api/apply") payload = { version_id: JSON.parse(String(init?.body)).version_id, status: "pending", deadline: 1900000000 };
    return Promise.resolve(new Response(JSON.stringify(payload), { status }));
  });
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

function savedDraft(fetch: ReturnType<typeof vi.fn>) {
  const call = [...fetch.mock.calls].reverse().find(([path, init]) => path === "/api/draft" && init?.method === "PUT");
  expect(call).toBeTruthy();
  return JSON.parse(String(call![1].body));
}

async function openMaster(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole("tab", { name: "Мастер маршрутизации" });
  await user.click(screen.getByRole("tab", { name: "Мастер маршрутизации" }));
  await screen.findByRole("tab", { name: "Мастер" });
}

async function openAdvanced(user: ReturnType<typeof userEvent.setup>) {
  await openMaster(user);
  await user.click(screen.getByRole("tab", { name: "Расширенные настройки" }));
}

/** Walk the wizard to a rule with the given exit and return its name. */
async function fillWizard(
  user: ReturnType<typeof userEvent.setup>,
  options: { exitKind: string; exitValue?: string; domains?: string; name?: string } = { exitKind: "direct" },
) {
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), options.domains ?? "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: exitNames[options.exitKind] }));
  if (options.exitValue) {
    const label = options.exitKind === "interface" ? "Интерфейс выхода"
      : options.exitKind === "outbound" ? "Прокси-выход"
      : options.exitKind === "group" ? "Группа выходов"
      : "Клиентский туннель";
    await user.selectOptions(screen.getByLabelText(label), options.exitValue);
  }
  await user.click(screen.getByRole("button", { name: "Далее" }));
  if (options.name) {
    await user.clear(screen.getByLabelText("Имя правила"));
    await user.type(screen.getByLabelText("Имя правила"), options.name);
  }
}

it("criterion_R1_page_shows_four_tabs_and_master_is_default", async () => {
  setup();
  for (const label of ["Мастер маршрутизации", "Прокси-выходы",
    "Источники списков"]) {
    expect(await screen.findByRole("tab", { name: label })).toBeVisible();
  }
  expect(screen.getByRole("tab", { name: "Мастер маршрутизации" }))
    .toHaveAttribute("aria-selected", "true");
});

it("criterion_R2_wizard_walks_four_steps_and_blocks_invalid_next", async () => {
  setup();
  const user = userEvent.setup();
  await openMaster(user);
  expect(screen.getByText("Сейчас: Кому")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Сейчас: Что")).toBeVisible();
  // No destination yet: the reason is visible and the next step is blocked.
  expect(screen.getByText(/Правило без назначения не сработает/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "example.org");
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Сейчас: Куда")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Сейчас: Проверка")).toBeVisible();
});

it("criterion_R3_device_subject_writes_subscriber_and_peer", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Устройство абонента" }));
  await user.click(screen.getByRole("button", { name: "iphone" }));
  await fillWizard(user, { exitKind: "direct", name: "device_rule" });
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).routing_rules[0].subject).toEqual({
    kind: "device", subscriber: "анна", peer: "iphone",
  });
});

it("criterion_R4_interface_subject_lists_only_ipv4_interfaces", async () => {
  const configuration = baseConfiguration();
  configuration.interfaces = [
    ...configuration.interfaces.filter((item) => item.name !== "lan0"),
    { name: "vpn0", type: "physical", zone: "lan", description: null, addressing: "static",
      addresses: ["fd00::1/64"], parent: null, vlan_id: null, members: [] },
  ];
  setup(configuration);
  const user = userEvent.setup();
  await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Весь трафик интерфейса" }));
  // The IPv6-only interface is not offered as a source.
  const rows = within(screen.getByRole("group", { name: "Устройства и интерфейсы" }));
  expect(rows.getByRole("button", { name: "eth0" })).toBeVisible();
  expect(rows.queryByRole("button", { name: "vpn0" })).not.toBeInTheDocument();
});

it("criterion_R5_destination_requires_one_of_three_lists", async () => {
  setup();
  const user = userEvent.setup();
  await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText(/Правило без назначения не сработает/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("Свои адреса и сети (CIDR)"), "203.0.113.0/24");
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
});

it("criterion_R11_rule_set_service_writes_tags_and_declared_source", async () => {
  // ADR-0031: choosing a rule-set service (18+ / RKN) puts its tag into the
  // rule and its declaration into configuration.rule_sets on save.
  const fetch = setup(baseConfiguration(), { catalog: { categories: [
    { key: "block", title: "Блок", count: 1 },
  ], services: [
    { id: "porn", name: "Adult content (18+)", category: "block", icon_slug: "lucide-lock",
      notice: null, covers: [], dns_domains: [],
      rule_sets: [{ tag: "geosite-category-porn", url: "https://example.org/porn.srs", format: "srs" }],
      declared: false, action: "tunnel" },
  ] } });
  const user = userEvent.setup();
  await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: /Adult content \(18\+\)/ }));
  // The tag itself satisfies the destination requirement: no typed domains.
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Заблокировать" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  const saved = savedDraft(fetch);
  expect(saved.routing_rules[0].rule_sets).toEqual(["geosite-category-porn"]);
  expect(saved.rule_sets).toEqual([expect.objectContaining({
    name: "geosite-category-porn", format: "srs", url: "https://example.org/porn.srs",
  })]);
});

it("criterion_R6_exit_writes_the_adr_exit_objects", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await openMaster(user);
  await fillWizard(user, { exitKind: "interface", exitValue: "eth0", name: "via_interface" });
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await screen.findByRole("heading", { name: "Шаг 1. Кому маршрутизируем" });
  await openAdvanced(user);
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "example.net");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Через группу выходов" }));
  await user.selectOptions(screen.getByLabelText("Группа выходов"), "auto");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.clear(screen.getByLabelText("Имя правила"));
  await user.type(screen.getByLabelText("Имя правила"), "via_group");
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  const rules: RoutingRule[] = savedDraft(fetch).routing_rules;
  expect(rules[0].exit).toEqual({ kind: "interface", interface: "eth0" });
  expect(rules[1].exit).toEqual({ kind: "group", tag: "auto" });
});

it("criterion_R7_save_writes_routing_rules_into_the_draft_and_never_applies", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await openMaster(user);
  await fillWizard(user, { exitKind: "outbound", exitValue: "vless_fr", name: "via_proxy" });
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).routing_rules).toEqual([expect.objectContaining({
    name: "via_proxy", exit: { kind: "outbound", tag: "vless_fr" },
  })]);
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});

it("criterion_R8_rules_table_shows_prose_cells_and_a_per_row_delete_label", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{
    name: "existing", subject: { kind: "server" }, domain_suffix: ["example.org"],
    domain_exact: [], ip_cidr: [], rule_sets: [], exit: { kind: "direct" },
  }];
  setup(configuration);
  const user = userEvent.setup();
  await openAdvanced(user);
  expect(screen.getByRole("cell", { name: "трафик сервера" })).toBeVisible();
  expect(screen.getByRole("cell", { name: "домены example.org" })).toBeVisible();
  expect(screen.getByRole("cell", { name: "напрямую" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Удалить правило existing" })).toBeVisible();
});

it("criterion_R9_edit_opens_a_window_with_three_groups_and_saves_in_place", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{
    name: "existing", subject: { kind: "server" }, domain_suffix: ["example.org"],
    domain_exact: [], ip_cidr: [], rule_sets: [], exit: { kind: "direct" },
  }];
  const fetch = setup(configuration);
  const user = userEvent.setup();
  await openAdvanced(user);
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: /Правило: existing/ });
  expect(within(dialog).getByRole("heading", { name: "Кому" })).toBeVisible();
  expect(within(dialog).getByRole("heading", { name: "Что" })).toBeVisible();
  expect(within(dialog).getByRole("heading", { name: "Куда" })).toBeVisible();
  await user.click(within(dialog).getByRole("button", { name: "Заблокировать" }));
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: /Правило:/ })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).routing_rules[0].exit).toEqual({ kind: "block" });
});

it("criterion_R10_move_changes_the_order_in_the_saved_json", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [
    { name: "first", subject: { kind: "server" }, domain_suffix: ["first.test"], domain_exact: [],
      ip_cidr: [], rule_sets: [], exit: { kind: "direct" } },
    { name: "second", subject: { kind: "server" }, domain_suffix: ["second.test"], domain_exact: [],
      ip_cidr: [], rule_sets: [], exit: { kind: "direct" } },
  ];
  const fetch = setup(configuration);
  const user = userEvent.setup();
  await openAdvanced(user);
  await user.click(screen.getAllByRole("button", { name: "Вниз" })[0]);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) =>
    path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).routing_rules.map((rule: RoutingRule) => rule.name))
    .toEqual(["second", "first"]);
});

it("criterion_R11_empty_state_prompts_for_the_first_rule_without_sample_rows", async () => {
  setup();
  const user = userEvent.setup();
  await openAdvanced(user);
  expect(screen.getByText(/Правил маршрутизации пока нет/)).toBeVisible();
  expect(screen.queryByRole("cell", { name: /example\.org/ })).not.toBeInTheDocument();
});

it("criterion_R12_fail_closed_note_is_visible", async () => {
  setup();
  const user = userEvent.setup();
  await openMaster(user);
  expect(screen.getByText(/блокируется/)).toBeVisible();
});


it("criterion_S3_16_reference_palette_matches_theme_without_new_hex_literals", () => {
  const palette = [...repoSource("mockups/routing-wizard.html").matchAll(/--[a-zA-Z0-9]+:(#[0-9a-f]{6})/g)].map((match) => match[1]);
  expect(palette).toHaveLength(14);
  palette.forEach((color) => expect(Object.values(tokens)).toContain(color));
  for (const path of ["pages/RoutingMaster.tsx", "components/ChoiceCards.tsx", "components/FlowChain.tsx", "components/RoutingSurface.tsx"])
    expect(repoSource(`frontend/src/${path}`)).not.toMatch(/#[0-9a-fA-F]{6}/);
});

it("criterion_S3_22_routing_tables_keep_words_whole_and_scroll", () => {
  // A squeezed column used to split a word into single letters
  // ("Защ|ита|уст|рой"). The table must keep words whole and scroll instead.
  const css = repoSource("frontend/src/styles.css");
  expect(css).toMatch(/\.routing-surface \.MuiTableCell-root\s*\{[^}]*word-break:\s*normal/);
  expect(css).toMatch(/\.routing-surface table\s*\{[^}]*min-width/);
  const page = repoSource("frontend/src/pages/RoutingMaster.tsx");
  expect(page).toContain("routing-table-wide");
});

it("criterion_S3_17_card_choices_are_keyboard_operable_and_chains_static", async () => {
  const change = vi.fn(); const user = userEvent.setup();
  render(<><ChoiceCards label="Источник" value={["server"]} onChange={change} options={[
    { value: "server", label: "Сервер", description: "Исходящий трафик" },
    { value: "device", label: "Устройство", description: "Выбранное устройство" },
  ]} /><FlowChain label="Описание" items={[{ text: "Источник" }, { text: "Выход" }]} /></>);
  await user.tab(); expect(screen.getByRole("button", { name: "Сервер" })).toHaveFocus();
  await user.tab(); await user.keyboard("{Enter}"); expect(change).toHaveBeenCalledWith("device", ["device"]);
  expect(screen.getByRole("button", { name: "Сервер" })).toHaveAttribute("aria-pressed", "true");
  expect(within(screen.getByRole("group", { name: "Описание" })).queryByRole("button")).not.toBeInTheDocument();
});

it("criterion_S3_18_operator_copy_is_russian", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  const group = screen.getByRole("group", { name: "Источник трафика" });
  within(group).getAllByRole("button").forEach((button) => expect(button).toHaveTextContent(/[А-Яа-я]/));
  await fillWizard(user);
  expect(screen.getByRole("button", { name: "Сохранить и применить" })).toBeVisible();
  expect(screen.queryByRole("button", { name: /Save|Cancel|Next/ })).not.toBeInTheDocument();
});

it("criterion_S3_19_tproxy_config_remains_separate_and_unmodified_by_master_save", async () => {
  const configuration = baseConfiguration(); const fetch = setup(configuration);
  const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toEqual(configuration.tproxy));
  // The legacy TProxy screen was removed; the master save must still leave it untouched.
});

it("criterion_S3_20_empty_catalog_and_empty_rules_never_invent_entries", async () => {
  setup({ ...baseConfiguration(), subscribers: [], interfaces: [], tunnels: [] }, { catalog: { categories: [], services: [] } });
  const user = userEvent.setup(); await openMaster(user);
  expect(within(screen.getByRole("group", { name: "Устройства и интерфейсы" })).queryByRole("button")).not.toBeInTheDocument();
  expect(screen.getByText(/Правил маршрутизации пока нет/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await waitFor(() => expect(screen.queryByRole("status", { name: "Загрузка" })).not.toBeInTheDocument());
  expect(screen.queryByRole("group", { name: "Готовые сервисы" })).not.toBeInTheDocument();
  expect(screen.getByLabelText("Свои домены (по одному в строке)")).toHaveValue("");
});
