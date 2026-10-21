import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { Configuration, RoutingRule } from "../types";

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

function setup(configuration: Configuration = baseConfiguration()) {
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) =>
    Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [{ id: 1, status: "draft", configuration }]
        : path === "/api/runtime/engine"
          ? { installed: true, version: "1.14.2", running: false, pid: null,
              clash_api: false, ip_forward: true, nft_tproxy_tables: true }
          : { id: 1, status: "draft", configuration: JSON.parse(String(init?.body)) },
    ), { status: 200 })));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

function savedDraft(fetch: ReturnType<typeof vi.fn>) {
  const call = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT");
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
  await user.type(screen.getByLabelText("Домены (по строкам)"), options.domains ?? "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Выход"), options.exitKind);
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
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
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
  await user.selectOptions(screen.getByLabelText("Источник трафика"), "device");
  await user.selectOptions(screen.getByLabelText("Устройство"), "iphone");
  await fillWizard(user, { exitKind: "direct", name: "device_rule" });
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
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
  await user.selectOptions(screen.getByLabelText("Источник трафика"), "interface");
  // The IPv6-only interface is not offered as a source.
  const options = within(screen.getByLabelText("Интерфейс-источник")).getAllByRole("option")
    .map((option) => (option as HTMLOptionElement).value)
    .filter((value) => value !== "");
  expect(options).toEqual(["eth0"]);
});

it("criterion_R5_destination_requires_one_of_three_lists", async () => {
  setup();
  const user = userEvent.setup();
  await openMaster(user);
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText(/Правило без назначения не сработает/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("IPv4-сети (по строкам)"), "203.0.113.0/24");
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
});

it("criterion_R6_exit_writes_the_adr_exit_objects", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await openMaster(user);
  await fillWizard(user, { exitKind: "interface", exitValue: "eth0", name: "via_interface" });
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await openAdvanced(user);
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.net");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Выход"), "group");
  await user.selectOptions(screen.getByLabelText("Группа выходов"), "auto");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.clear(screen.getByLabelText("Имя правила"));
  await user.type(screen.getByLabelText("Имя правила"), "via_group");
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
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
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
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
  await user.selectOptions(within(dialog).getByLabelText("Выход"), "block");
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
  await user.selectOptions(within(dialog).getByLabelText("Выход"), "direct");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: /Правило:/ })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.getByText(/больше не объявлен/)).toBeVisible());
  expect(screen.getByText(/routing\.outbound_reference/)).toBeVisible();
});
