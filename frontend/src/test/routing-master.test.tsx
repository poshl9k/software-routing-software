import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { tokens } from "../theme";
import { ChoiceCards } from "../components/ChoiceCards";
import { FlowChain } from "../components/FlowChain";
import { Icon } from "../components/Icon";
import { api } from "../api";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { CatalogResponse, Configuration, RoutingRule } from "../types";

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
  for (const label of ["Мастер маршрутизации", "Правила sing-box (TProxy)", "Прокси-выходы",
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
    domain_exact: [], ip_cidr: [], exit: { kind: "direct" },
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
    domain_exact: [], ip_cidr: [], exit: { kind: "direct" },
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
      ip_cidr: [], exit: { kind: "direct" } },
    { name: "second", subject: { kind: "server" }, domain_suffix: ["second.test"], domain_exact: [],
      ip_cidr: [], exit: { kind: "direct" } },
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

it("criterion_R13_legacy_tproxy_tab_still_works", async () => {
  setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("tab", { name: "Правила sing-box (TProxy)" }));
  expect(await screen.findByText("Выключено · черновик")).toBeVisible();
  expect(screen.getByRole("tab", { name: "Простой" })).toBeVisible();
});

it("criterion_R14_broken_references_are_explained_in_russian", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{
    name: "broken", subject: { kind: "server" }, domain_suffix: ["example.org"],
    domain_exact: [], ip_cidr: [], exit: { kind: "outbound", tag: "removed_proxy" },
  }];
  const fetch = vi.fn().mockImplementation((path: string) =>
    Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [{ id: 1, status: "draft", configuration }]
        : path === "/api/runtime/engine"
          ? { installed: true, version: "1.14.2", running: false, pid: null,
              clash_api: false, ip_forward: true, nft_tproxy_tables: true }
          : { code: "configuration.invalid", message: "configuration.invalid",
              details: [{ message: "routing.outbound_reference" }] },
    ), { status: path === "/api/versions" ? 200 : 422 })));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  const user = userEvent.setup();
  await openAdvanced(user);
  // The operator edits the rule and saves: the server refuses the document
  // and the guard must arrive in Russian, not as a JSON dump.
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: /Правило: broken/ });
  await user.click(within(dialog).getByRole("button", { name: "Напрямую" }));
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: /Правило:/ })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.getByText(/больше не объявлен/)).toBeVisible());
  expect(screen.getByText(/routing\.outbound_reference/)).toBeVisible();
});

it("criterion_S3_1_numbered_card_surfaces_keep_four_step_progress", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  for (const [index, title] of ["Шаг 1. Кому маршрутизируем", "Шаг 2. Что маршрутизировать", "Шаг 3. Куда направить", "Шаг 4. Проверка"].entries()) {
    const heading = screen.getByRole("heading", { name: title });
    expect(heading.closest(".card")).not.toBeNull();
    expect(heading.closest(".card")?.querySelector(".routing-subtitle")).toBeTruthy();
    expect(screen.getByRole("navigation", { name: "Этапы настройки" }).querySelector('[aria-current="step"]')).toHaveTextContent(["Кому", "Что", "Куда", "Проверка"][index]);
    if (index === 1) await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "example.org");
    if (index < 3) await user.click(screen.getByRole("button", { name: "Далее" }));
  }
});

it("criterion_S3_2_subject_cards_show_selected_and_unavailable_reasons", async () => {
  setup({ ...baseConfiguration(), subscribers: [], interfaces: [] });
  const user = userEvent.setup(); await openMaster(user);
  const group = screen.getByRole("group", { name: "Источник трафика" });
  expect(within(group).getAllByRole("button")).toHaveLength(3);
  expect(within(group).getByRole("button", { name: "Весь трафик сервера" })).toHaveAttribute("aria-pressed", "true");
  const device = within(group).getByRole("button", { name: "Устройство абонента" });
  expect(device).toBeDisabled(); expect(device).toHaveTextContent("Абонентских устройств нет");
  const iface = within(group).getByRole("button", { name: "Весь трафик интерфейса" });
  expect(iface).toBeDisabled(); expect(iface).toHaveTextContent("Нет интерфейсов с IPv4-адресом");
  expect(within(group).queryByRole("combobox")).not.toBeInTheDocument();
});

it("criterion_S3_3_object_rows_show_real_identity_and_select_subject", async () => {
  const fetch = setup(); const user = userEvent.setup(); await openMaster(user);
  const list = screen.getByRole("group", { name: "Устройства и интерфейсы" });
  expect(within(list).getAllByRole("button")).toHaveLength(3);
  const device = within(list).getByRole("button", { name: "iphone" });
  expect(device).toHaveTextContent("10.66.66.2/32 · абонент «анна» · пир iphone");
  const iface = within(list).getByRole("button", { name: "lan0 — домашняя сеть" });
  expect(iface).toHaveTextContent("192.168.10.1/24 · зона: локальная сеть");
  expect(within(list).queryByRole("textbox")).not.toBeInTheDocument();
  await user.click(iface); await fillWizard(user);
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).routing_rules[0].subject).toEqual({ kind: "interface", interface: "lan0" }));
});

it("criterion_S3_4_chosen_subject_is_a_sentence_above_rows", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "iphone" }));
  const summary = screen.getByText("Трафик устройства «iphone» абонента «анна»");
  expect(summary.compareDocumentPosition(screen.getByRole("group", { name: "Устройства и интерфейсы" })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await user.click(screen.getByRole("button", { name: "eth0" }));
  expect(screen.getByText("Трафик интерфейса eth0")).toBeVisible();
});

it("criterion_S3_5_catalog_presets_add_their_domains_without_showing_the_list", async () => {
  const fetch = setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const youtube = await screen.findByRole("button", { name: "YouTube" });
  // The tile says how many domains it brings, not the list itself.
  expect(youtube).toHaveTextContent("2 домена");
  expect(youtube.querySelector("svg")).not.toBeNull();
  expect(screen.queryByRole("button", { name: "Все видео" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Без доменов" })).not.toBeInTheDocument();
  const field = screen.getByLabelText("Свои домены (по одному в строке)");
  // Choosing a service must not dump its domains into the manual field.
  await user.click(youtube);
  expect(field).toHaveValue("");
  expect(youtube).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByText(/Выбрано сервисов: 1/)).toBeVisible();
  // The domains are in the rule; the field stays the operator's own list.
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).routing_rules[0].domain_suffix)
    .toEqual(["youtube.com", "googlevideo.com"]));
});

it("criterion_S3_5_several_services_can_be_chosen_at_once", async () => {
  const fetch = setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const youtube = await screen.findByRole("button", { name: "YouTube" });
  const rutube = screen.getByRole("button", { name: "RuTube" });
  await user.click(youtube);
  await user.click(rutube);
  expect(youtube).toHaveAttribute("aria-pressed", "true");
  expect(rutube).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByText(/Выбрано сервисов: 2/)).toBeVisible();
  // The manual field still holds only what the operator typed.
  const field = screen.getByLabelText("Свои домены (по одному в строке)");
  expect(field).toHaveValue("");
  await user.type(field, "own.test");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).routing_rules[0].domain_suffix)
    .toEqual(["own.test", "youtube.com", "googlevideo.com", "rutube.ru"]));
});

it("criterion_S3_5_unchecking_a_service_removes_only_its_own_domains", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const youtube = await screen.findByRole("button", { name: "YouTube" });
  await user.click(youtube);
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "own.test");
  await user.click(youtube);
  expect(youtube).toHaveAttribute("aria-pressed", "false");
  expect(screen.getByLabelText("Свои домены (по одному в строке)")).toHaveValue("own.test");
});

it("criterion_S3_5_loading_and_failure_leave_manual_fields_available", async () => {
  let reject!: (error: Error) => void;
  const spy = vi.spyOn(api, "presetCatalog").mockRejectedValue(new Error("offline"))
    .mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
  setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByRole("status", { name: "Загрузка" })).toBeVisible();
  reject(new Error("offline"));
  await waitFor(() => expect(screen.queryByRole("status", { name: "Загрузка" })).not.toBeInTheDocument(), { timeout: 2500 });
  expect(screen.queryByRole("group", { name: "Готовые сервисы" })).not.toBeInTheDocument();
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "manual.test");
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
  spy.mockRestore();
});

it("criterion_S3_6_manual_lists_are_alternatives_and_preserve_exact_domains", async () => {
  const fetch = setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText(/Списки — альтернативы/)).toBeVisible();
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "suffix.test");
  await user.type(screen.getByLabelText("Точные домены (по строкам)"), "exact.test");
  await user.type(screen.getByLabelText("Свои адреса и сети (CIDR)"), "203.0.113.0/24");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).routing_rules[0]).toMatchObject({ domain_suffix: ["suffix.test"], domain_exact: ["exact.test"], ip_cidr: ["203.0.113.0/24"] }));
});

it("criterion_S3_7_six_exit_cards_only_show_relevant_target", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const exits = screen.getByRole("group", { name: "Выход" });
  expect(within(exits).getAllByRole("button")).toHaveLength(6);
  const tunnel = within(exits).getByRole("button", { name: "Через туннель" });
  expect(tunnel).toBeDisabled(); expect(tunnel).toHaveTextContent("на странице «Туннели»");
  expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  for (const [kind, label] of [["Через интерфейс", "Интерфейс выхода"], ["Через прокси-выход", "Прокси-выход"], ["Через группу выходов", "Группа выходов"]]) {
    await user.click(within(exits).getByRole("button", { name: kind }));
    expect(screen.getAllByRole("combobox")).toHaveLength(1);
    expect(screen.getByRole("combobox", { name: label })).toBeVisible();
  }
  await user.click(within(exits).getByRole("button", { name: "Заблокировать" }));
  expect(screen.getByText(/прямого выхода в интернет не будет/)).toBeVisible();
});

it("criterion_S3_8_review_chain_uses_static_badges_and_honest_fallback", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  const chain = screen.getByRole("group", { name: "Путь выбранного трафика" });
  expect(chain.querySelectorAll(".MuiChip-root")).toHaveLength(4);
  expect(chain.querySelectorAll("svg")).toHaveLength(3);
  expect(within(chain).queryByRole("button")).not.toBeInTheDocument();
  expect(screen.getByRole("group", { name: "Трафик без совпадения" })).toHaveTextContent("заблокировать");
  expect(screen.getByRole("group", { name: "Остальной трафик" })).toHaveTextContent("через группу auto");
});

it("criterion_S3_9_review_names_rule_and_actual_order", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{ name: "first", subject: { kind: "server" }, domain_suffix: ["first.test"], domain_exact: [], ip_cidr: [], exit: { kind: "direct" } }];
  setup(configuration); const user = userEvent.setup(); await openMaster(user);
  await fillWizard(user, { exitKind: "direct", name: "second" });
  expect(screen.getByText(/Правило 2 из 2.*«second»/)).toBeVisible();
});

it("criterion_S3_10_warning_distinguishes_draft_from_global_apply", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  expect(screen.getByText(/Сохранение записывает только черновик/)).toHaveTextContent("Изменения не действуют до отдельного применения");
  expect(screen.queryByText(/Политика пока выключена/)).not.toBeInTheDocument();
});

it("criterion_S3_11_save_then_global_apply_uses_new_draft_id", async () => {
  const fetch = setup(baseConfiguration(), { confirmed: true });
  const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  for (const label of ["Отмена", "Сохранить черновик", "Сохранить и применить"]) expect(screen.getByRole("button", { name: label })).toBeEnabled();
  await user.dblClick(screen.getByRole("button", { name: "Сохранить и применить" }));
  await waitFor(() => expect(fetch.mock.calls.filter(([path]) => path === "/api/apply")).toHaveLength(1));
  const calls = fetch.mock.calls;
  expect(calls.findIndex(([path]) => path === "/api/draft")).toBeLessThan(calls.findIndex(([path]) => path === "/api/apply"));
  expect(JSON.parse(calls.find(([path]) => path === "/api/apply")![1].body)).toMatchObject({ version_id: 2, safe_mode: false, confirmation_timeout: 180 });
});

it("criterion_S3_11_failed_save_never_applies_and_keeps_input", async () => {
  const fetch = setup(baseConfiguration(), { saveError: true });
  const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  await user.click(screen.getByRole("button", { name: "Сохранить и применить" }));
  expect(await screen.findByText(/имя домена указано неверно/)).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
  expect(screen.getByLabelText("Имя правила")).toHaveValue("example_org");
});

it("criterion_S3_21_rule_name_is_generated_from_the_destination_and_unique", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{ name: "example_org", subject: { kind: "server" },
    domain_suffix: ["example.org"], domain_exact: [], ip_cidr: [], exit: { kind: "direct" } }];
  setup(configuration); const user = userEvent.setup(); await openMaster(user);
  await fillWizard(user, { exitKind: "direct", domains: "example.org" });
  // The name is not an ordinal counter and not a repeat of an existing rule.
  const name = (screen.getByLabelText("Имя правила") as HTMLInputElement).value;
  expect(name).not.toBe("rule_1");
  expect(name).not.toBe("rule_2");
  expect(name).toMatch(/^example/);
  expect(name).not.toBe("example_org");
  expect(screen.getByText(/Создано по назначению/)).toBeVisible();
});

it("criterion_S3_21_a_name_written_by_hand_survives_a_destination_change", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "first.test");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const field = screen.getByLabelText("Имя правила");
  await user.clear(field);
  await user.type(field, "my_own_name");
  await user.click(screen.getByRole("button", { name: "Назад" }));
  await user.click(screen.getByRole("button", { name: "Назад" }));
  await user.type(screen.getByLabelText("Свои домены (по одному в строке)"), "second.test");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByLabelText("Имя правила")).toHaveValue("my_own_name");
});

it("criterion_S3_12_preview_has_readonly_system_rows_and_candidate", async () => {
  setup(); const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  const table = screen.getByRole("table");
  const rows = within(table).getAllByRole("row");
  expect(rows).toHaveLength(4);
  expect(rows[1]).toHaveTextContent("системное правило");
  expect(rows[1]).toHaveTextContent("После пользовательских правил");
  expect(rows[2]).toHaveTextContent("Конечный выход");
  expect(rows[3]).toHaveTextContent("example_org"); expect(rows[3]).toHaveTextContent("example.org");
  expect(within(table).queryByRole("button")).not.toBeInTheDocument();
  expect(table).not.toHaveTextContent("перехват DNS");
});

it("criterion_S3_13_expert_engine_precedes_rules_with_one_creation_action", async () => {
  const configuration = baseConfiguration();
  configuration.routing_rules = [{ name: "existing", subject: { kind: "server" }, domain_suffix: ["example.org"], domain_exact: [], ip_cidr: [], exit: { kind: "direct" } }];
  setup(configuration); const user = userEvent.setup(); await openAdvanced(user);
  const heading = screen.getByRole("heading", { name: "Движок и источники" });
  expect(heading.compareDocumentPosition(screen.getByRole("table")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(screen.getByRole("group", { name: "Порядок обработки" })).toHaveTextContent("источник трафикаsing-boxпервое совпавшее правиловыход правила");
  expect(screen.getAllByText("системное правило")).toHaveLength(2);
  expect(screen.getAllByRole("button", { name: "+ Правило" })).toHaveLength(1);
  for (const label of ["Изменить", "Вверх", "Вниз", "Удалить правило existing"]) expect(screen.getByRole("button", { name: label })).toBeVisible();
  expect(screen.queryByRole("tab", { name: /Наборы правил/ })).not.toBeInTheDocument();
});

const repoSource = (path: string) => readFileSync(`${process.cwd()}/../${path}`, "utf8");
it("criterion_S3_14_shared_primitives_are_documented_and_page_imports_allowed", () => {
  const page = repoSource("frontend/src/pages/RoutingMaster.tsx");
  const imports = [...page.matchAll(/import \{([^}]+)\} from "@mui\/material"/g)].flatMap((match) => match[1].split(",").map((value) => value.trim()));
  expect(imports.every((name) => ["Button", "Typography", "Dialog", "DialogContent", "DialogTitle"].includes(name))).toBe(true);
  for (const name of ["ChoiceCards", "FlowChain", "RoutingSurface", "SummaryPanel"]) {
    expect(page).toContain(name);
    expect(repoSource("docs/ui-refactor.md")).toContain(name);
    expect(repoSource("docs/adr/0011-ui-component-system-and-state.md")).toContain(name);
  }
});

it("criterion_S3_15_category_icons_are_stroked_svg_not_glyphs", () => {
  const { container } = render(<>{(["media", "social", "developer", "cloud", "gaming", "ai", "block"] as const).map((name) => <Icon key={name} name={name} />)}</>);
  expect(container.querySelectorAll("svg")).toHaveLength(7);
  container.querySelectorAll("svg").forEach((icon) => {
    expect(icon).toHaveAttribute("viewBox", "0 0 24 24"); expect(icon).toHaveAttribute("stroke", "currentColor");
    expect(icon.querySelector("path")).not.toBeNull();
  });
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

it("criterion_S3_19_legacy_tab_remains_separate_and_unmodified_by_master_save", async () => {
  const configuration = baseConfiguration(); const fetch = setup(configuration);
  const user = userEvent.setup(); await openMaster(user); await fillWizard(user);
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toEqual(configuration.tproxy));
  await user.click(screen.getByRole("tab", { name: "Правила sing-box (TProxy)" }));
  expect(await screen.findByRole("tab", { name: "Простой" })).toBeVisible();
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
