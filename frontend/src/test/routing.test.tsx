import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { RuntimeEngine, TProxyDNS, TProxyRule } from "../types";

const engine: RuntimeEngine = { installed: true, version: "1.2.3", running: false, pid: null,
  clash_api: false, ip_forward: true, nft_tproxy_tables: true };

function setup(fail = false, rules: TProxyRule[] = [], proxies = emptyConfiguration.proxies,
  tproxy = emptyConfiguration.tproxy, status: "draft" | "confirmed" = "draft") {
  const configuration = {
    ...emptyConfiguration,
    interfaces: [{ name: "lan0", zone: "lan" as const, kind: "physical" as const }],
    tproxy: { ...tproxy, rules },
    proxies,
  };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) =>
    Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [{ id: 1, status, configuration }]
        : path === "/api/presets/catalog"
          ? { categories: [{ key: "media", title: "Медиа", count: 1 }], services: [{
            id: "video", name: "Видео", category: "media", icon_slug: "video", notice: "",
            covers: [], dns_domains: ["video.example"], rule_sets: [
              { tag: "video-set", url: "https://example.org/video.srs", format: "srs" }],
            action: "route", declared: false,
          }] }
        : path === "/api/runtime/engine"
          ? engine
        : fail
          ? { code: "validation.failed", message: "Ошибка проверки конфигурации", details: [] }
          : { id: 1, status: "draft", configuration: JSON.parse(String(init?.body)) },
    ), { status: path === "/api/versions" || !fail ? 200 : 422 })));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

function savedDraft(fetch: ReturnType<typeof vi.fn>) {
  const call = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT");
  expect(call).toBeTruthy();
  return JSON.parse(String(call![1].body));
}

it("offers the outbound editor from an empty TProxy page", async () => {
  setup();
  const user = userEvent.setup();
  expect(await screen.findByText("Прокси-выходы не настроены")).toBeVisible();
  expect(screen.getByText(/Нет прокси-выходов. Добавьте выход/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Открыть прокси-выходы" }));
  expect(screen.getByRole("tab", { name: "Прокси-выходы" })).toHaveAttribute("aria-selected", "true");
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  expect(screen.getByRole("button", { name: "+ Добавить выход" })).toBeVisible();
});

it("enables the proxy section when the first outbound is added from TProxy", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Добавить по ссылке" }));
  await user.type(screen.getByLabelText("Ссылка на прокси"), "vless://uuid@exit.example.com:443#first_exit");
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Добавить выход по ссылке" })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).proxies).toMatchObject({
    enabled: true, outbounds: [expect.objectContaining({ tag: "first_exit" })],
  });
});

it("shows system rows and first-match rule columns in both views", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByText("Выключено · черновик");
  for (const header of ["#", "Куда", "Условия", "Действия"]) {
    expect(screen.getByRole("columnheader", { name: header })).toBeVisible();
  }
  for (const row of ["Sniff", "Порт 53", "Локальные IPv4-адреса", "UDP"]) {
    expect(screen.getByRole("cell", { name: row })).toBeVisible();
  }
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  for (const header of ["#", "Действие", "Условия", "Выход", "Действия"]) {
    expect(screen.getAllByRole("columnheader", { name: header }).length).toBeGreaterThan(0);
  }
  expect(screen.getByText(/Если ни одно правило не подошло/)).toBeVisible();
});

it("adds a direct target rule with no proxy outbounds", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "direct_site");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "direct.example");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: /^Добавить$/ }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).tproxy.rules).toContainEqual(expect.objectContaining({
    name: "direct_site", domain_suffix: ["direct.example"], action: "direct", outbound: null,
  }));
});

it("declares a catalog rule-set and adds its direct rule with no outbounds", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.click(screen.getByRole("button", { name: "Из каталога" }));
  await user.click(await screen.findByRole("checkbox", { name: "Видео" }));
  await user.click(screen.getByRole("button", { name: "Выбрать (1)" }));
  await waitFor(() => expect(document.querySelector(".MuiModal-root")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: /^Добавить$/ }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  const draft = savedDraft(fetch);
  expect(draft.rule_sets).toContainEqual(expect.objectContaining({ name: "video-set" }));
  expect(draft.tproxy.rules).toContainEqual(expect.objectContaining({
    rule_sets: ["video-set"], action: "direct", outbound: null,
  }));
});

it("declares a manual HTTPS rule-set in the draft and rejects HTTP", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Набор" }));
  await user.type(screen.getByLabelText("Тег"), "manual-set");
  await user.type(screen.getByLabelText("URL источника"), "http://example.org/list.srs");
  expect(screen.getByRole("button", { name: "Добавить в черновик" })).toBeDisabled();
  await user.clear(screen.getByLabelText("URL источника"));
  await user.type(screen.getByLabelText("URL источника"), "https://example.org/list.srs");
  await user.selectOptions(screen.getByLabelText("Формат"), "srs");
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  expect(savedDraft(fetch).rule_sets).toContainEqual({
    name: "manual-set", format: "srs", url: "https://example.org/list.srs",
    max_records: 100_000, max_bytes: 5_000_000,
  });
});

it("creates a guided rule with catalog rule-set declarations in the draft only", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByText("Выключено · черновик");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.click(screen.getByRole("button", { name: "Из каталога" }));
  await user.click(await screen.findByRole("checkbox", { name: "Видео" }));
  await user.click(screen.getByRole("button", { name: "Выбрать (1)" }));
  await waitFor(() => expect(document.querySelector(".MuiModal-root")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: /^Добавить$/ }));
  expect(screen.getAllByText(/Из каталога: Видео/).length).toBeGreaterThan(0);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  const [, init] = fetch.mock.calls.find(([path, req]) => path === "/api/draft" && req?.method === "PUT")!;
  const sent = JSON.parse(String(init.body));
  expect(sent.rule_sets).toContainEqual({ name: "video-set", format: "srs", url: "https://example.org/video.srs",
    max_records: 100_000, max_bytes: 5_000_000 });
  expect(sent.tproxy.rules[0].rule_sets).toEqual(["video-set"]);
  expect(sent.tproxy.rules[0].action).toBe("direct");
  expect(fetch.mock.calls.some(([path]) => path === "https://example.org/video.srs" || path === "/api/apply")).toBe(false);
});

it("reports duplicate catalog sets in expert view without declaring twice", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByText("Выключено · черновик");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "Из каталога" }));
  await user.click(await screen.findByRole("checkbox", { name: "Видео" }));
  await user.click(screen.getByRole("button", { name: "Выбрать (1)" }));
  await waitFor(() => expect(document.querySelector(".MuiModal-root")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Из каталога" }));
  await user.click(await screen.findByRole("checkbox", { name: "Видео" }));
  await user.click(screen.getByRole("button", { name: "Выбрать (1)" }));
  expect(screen.getByText(/Уже добавлено в черновик: video-set/)).toBeVisible();
  await waitFor(() => expect(document.querySelector(".MuiModal-root")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(true));
  const [, init] = fetch.mock.calls.find(([path, req]) => path === "/api/draft" && req?.method === "PUT")!;
  expect(JSON.parse(String(init.body)).rule_sets.filter((set: { name: string }) => set.name === "video-set")).toHaveLength(1);
});

it("warns about DNS rule references before deleting its server", async () => {
  const configuration = emptyConfiguration.tproxy;
  const server = { tag: "resolver", type: "udp" as const, server: "1.1.1.1", server_port: null,
    tls_name: null, path: null, domain_resolver: null, detour: null };
  const fetch = vi.fn().mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
    path === "/api/versions" ? [{ id: 1, status: "draft", configuration: {
      ...emptyConfiguration, tproxy: { ...configuration, dns: { servers: [server], rules: [
        { name: "domains", domain_suffix: ["example.org"], rule_sets: [], server: "resolver" },
      ] } },
    } }] : []))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "Удалить DNS-сервер resolver" }));
  expect(screen.getByText(/DNS-правило domains/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Удалить" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Удалить DNS-сервер?" })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  expect(await screen.findByText(/ссылка сломана: resolver/)).toBeVisible();
  await waitFor(() => expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled());
});

it("saves disabled ingress and an ordered block rule in the draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  expect(await screen.findByText("Выключено · черновик")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  expect(screen.getByRole("button", { name: "Включить" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  expect(screen.getByText("Шаг 1 из 3: условия")).toBeVisible();
  await user.type(screen.getByLabelText("Имя правила"), "blocked_site");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Шаг 2 из 3: назначение")).toBeVisible();
  await user.selectOptions(screen.getByLabelText("Куда направить"), "block");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Шаг 3 из 3: проверка")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toMatchObject({
    enabled: false, ingress_interfaces: ["lan0"], rules: [expect.objectContaining({
      name: "blocked_site", domain_suffix: ["example.org"], action: "block", outbound: null, order: 0,
    })],
  }));
});

it("confirms enabling a valid rule in the draft without applying it", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  const enable = screen.getByRole("button", { name: "Включить" });
  expect(enable).toBeDisabled();
  expect(screen.getByText(/Выберите хотя бы один источник/)).toBeVisible();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  expect(enable).toBeDisabled();
  expect(screen.getByText(/Добавьте хотя бы одно правило/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "route_test");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  expect(enable).toBeEnabled();
  await user.click(enable);
  expect(screen.getByText(/Ошибка в настройках может нарушить подключение/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  expect(screen.getByText("Выключено · несохранённый черновик")).toBeVisible();
  await user.click(enable);
  await user.click(screen.getByRole("button", { name: "Включить в черновике" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Сохранить" })).toBeVisible());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy.enabled).toBe(true));
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});

it("blocks enabling a route when its proxy section is off or outbound is missing", async () => {
  const rule: TProxyRule = { name: "proxy_rule", domain_suffix: ["example.org"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "route", outbound: "proxy_a", order: 0 };
  setup(false, [rule], proxiesWithOutbound, { ...emptyConfiguration.tproxy, ingress_interfaces: ["lan0"] });
  const user = userEvent.setup();
  expect(await screen.findByRole("button", { name: "Включить" })).toBeDisabled();
  expect(screen.getByText(/Включите секцию прокси-выходов/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Включить прокси-выходы в черновике" }));
  expect(screen.getByRole("button", { name: "Включить" })).toBeEnabled();
});

it("labels confirmed enabled configuration as applied without claiming live health", async () => {
  const rule: TProxyRule = { name: "allowed", domain_suffix: ["example.org"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "direct", outbound: null, order: 0 };
  setup(false, [rule], emptyConfiguration.proxies,
    { ...emptyConfiguration.tproxy, enabled: true, ingress_interfaces: ["lan0"] }, "confirmed");
  expect(await screen.findByText("Включено · применено")).toBeVisible();
  expect(await screen.findByText(/Движок: остановлен · версия 1.2.3/)).toBeVisible();
});

it("keeps the header enable action visible and confirms a valid draft change", async () => {
  const rule: TProxyRule = { name: "allowed", domain_suffix: ["example.org"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "direct", outbound: null, order: 0 };
  const fetch = setup(false, [rule], emptyConfiguration.proxies,
    { ...emptyConfiguration.tproxy, ingress_interfaces: ["lan0"] });
  const user = userEvent.setup();
  const enable = await screen.findByRole("button", { name: "Включить" });
  expect(enable).toBeEnabled();
  expect(await screen.findByText(/Движок: остановлен · версия 1.2.3/)).toBeVisible();
  await user.click(enable);
  expect(screen.getByText(/Ошибка в настройках может нарушить подключение/)).toBeVisible();
  expect(screen.getByText("Выключено · несохранённый черновик")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Включить в черновике" }));
  expect(screen.getByText("Включено · несохранённый черновик")).toBeVisible();
  await waitFor(() => expect(screen.getByRole("button", { name: "Сохранить" })).toBeVisible());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.enabled).toBe(true);
  });
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});

it("retains unsaved rule edits after a rejected draft", async () => {
  const rule: TProxyRule = { name: "initial", domain_suffix: ["example.net"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "direct", outbound: null, order: 0 };
  setup(true, [rule]);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.clear(screen.getByLabelText("Имя правила"));
  await user.type(screen.getByLabelText("Имя правила"), "retry_rule");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  expect(await screen.findByText(/Ошибка проверки конфигурации/)).toBeVisible();
  expect(screen.getByRole("cell", { name: /retry_rule: домен example.net/ })).toBeVisible();
});

it("saves daily update window as an alternative to six-hour interval", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.selectOptions(screen.getByLabelText("Режим обновления"), "window");
  await user.clear(screen.getByLabelText("Начало окна"));
  await user.type(screen.getByLabelText("Начало окна"), "01:30");
  await user.clear(screen.getByLabelText("Конец окна"));
  await user.type(screen.getByLabelText("Конец окна"), "04:00");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.update_schedule).toEqual({
      mode: "window", interval_hours: 6, window_start: "01:30", window_end: "04:00",
    });
  });
});

it("shows configured first-match order and updates it on move", async () => {
  const fetch = setup(false, [
    { name: "later", domain_suffix: ["later.test"], ip_cidr: [], source_ip_cidr: [],
      rule_sets: [], protocol: "any", ports: [], action: "block", outbound: null, order: 20 },
    { name: "first", domain_suffix: ["first.test"], ip_cidr: [], source_ip_cidr: [],
      rule_sets: [], protocol: "any", ports: [], action: "direct", outbound: null, order: 10 },
  ]);
  const user = userEvent.setup();
  expect(await screen.findByRole("cell", { name: /first: домен first.test/ })).toBeVisible();
  expect(screen.getByRole("cell", { name: /later: домен later.test/ })).toBeVisible();
  expect(screen.getByRole("cell", { name: "Обычный маршрут" })).toBeVisible();
  expect(screen.getByRole("cell", { name: "Блокировать" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getAllByRole("button", { name: "Вверх" })[1]);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.rules.map((r: TProxyRule) => [r.name, r.order]))
      .toEqual([["later", 0], ["first", 1]]);
  });
});

const proxyOutbound = {
  tag: "proxy_a", type: "vless" as const, server: "203.0.113.10", port: 443,
  secret: null, method: null, tls: false, tls_server_name: null, tls_insecure: false, admin_listen: null,
};
const proxiesWithOutbound = {
  enabled: false, outbounds: [proxyOutbound], subscriptions: [], groups: [],
};

async function openNewExpertRule(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "initial");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "initial.test");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.clear(screen.getByLabelText("Имя правила"));
  await user.clear(screen.getByLabelText("Домены (по строкам)"));
}

it("routes a rule to a chosen outbound on save", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await openNewExpertRule(user);
  await user.type(screen.getByLabelText("Имя правила"), "via_proxy");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.com");
  await user.selectOptions(screen.getByLabelText("Действие"), "route");
  await user.selectOptions(await screen.findByLabelText("Выход"), "proxy_a");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.rules).toEqual([
      { name: "via_proxy", domain_suffix: ["example.com"], ip_cidr: [], source_ip_cidr: [],
        rule_sets: [], protocol: "any", ports: [],
        action: "route", outbound: "proxy_a", order: 0 },
    ]);
  });
  expect(await screen.findByRole("cell", { name: /via_proxy: домен example.com/ })).toBeVisible();
  expect(screen.getAllByRole("cell", { name: "proxy_a" }).length).toBeGreaterThan(0);
});

it("clears the outbound when a routing rule stops routing", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await openNewExpertRule(user);
  await user.type(screen.getByLabelText("Имя правила"), "sw");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.com");
  await user.selectOptions(screen.getByLabelText("Действие"), "route");
  await user.selectOptions(await screen.findByLabelText("Выход"), "proxy_a");
  await user.selectOptions(screen.getByLabelText("Действие"), "block");
  expect(screen.queryByLabelText("Выход")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const rule = JSON.parse(String(init.body)).tproxy.rules[0];
    expect(rule.action).toBe("block");
    expect(rule.outbound).toBeNull();
  });
});

it("saves the policy final action and its outbound", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.selectOptions(screen.getByLabelText("Для несовпавшего трафика"), "route");
  await user.selectOptions(await screen.findByLabelText("Выход по умолчанию"), "proxy_a");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const tproxy = JSON.parse(String(init.body)).tproxy;
    expect(tproxy.final).toBe("route");
    expect(tproxy.final_outbound).toBe("proxy_a");
  });
});

it("shows the simple rule flow and keeps engine fields in expert view", async () => {
  setup();
  const user = userEvent.setup();
  expect(await screen.findByRole("tab", { name: "Простой" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("heading", { name: "Правила · первое совпадение" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Включить" })).toBeDisabled();
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  expect(screen.queryByLabelText("Таймаут UDP, секунд")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  expect(screen.getByLabelText("Таймаут UDP, секунд")).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Простой" }));
  expect(screen.queryByLabelText("Таймаут UDP, секунд")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  expect(screen.getByText("Шаг 1 из 3: условия")).toBeVisible();
});

it("adds, reorders and deletes rules while preserving first-match and final", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  for (const [name, domain, action] of [["first", "first.test", "direct"], ["second", "second.test", "block"]]) {
    await user.click(screen.getByRole("button", { name: "+ Правило" }));
    await user.type(screen.getByLabelText("Имя правила"), name);
    await user.type(screen.getByLabelText("Домены (по строкам)"), domain);
    await user.click(screen.getByRole("button", { name: "Далее" }));
    await user.selectOptions(screen.getByLabelText("Куда направить"), action);
    await user.click(screen.getByRole("button", { name: "Далее" }));
    await user.click(screen.getByRole("button", { name: "Добавить" }));
  }
  expect(screen.getByRole("cell", { name: /first: домен first.test/ })).toBeVisible();
  expect(screen.getByRole("cell", { name: /second: домен second.test/ })).toBeVisible();
  await user.click(screen.getAllByRole("button", { name: "Вверх" })[1]);
  await user.click(screen.getByRole("button", { name: "Удалить правило first" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toMatchObject({
    rules: [expect.objectContaining({ name: "second", domain_suffix: ["second.test"],
      action: "block", outbound: null, order: 0 })], final: "direct", enabled: false,
  }));
});

it("shows read-only system rules and reports a failed runtime read honestly", async () => {
  const fetch = setup();
  fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
    path === "/api/versions" ? [{ id: 1, status: "draft", configuration: emptyConfiguration }] :
      path === "/api/runtime/engine" ? { code: "agent.unavailable", message: "Недоступен", details: [] } : {},
  ), { status: path === "/api/runtime/engine" ? 503 : 200 })));
  const user = userEvent.setup();
  expect(await screen.findByText(/Движок: состояние недоступно/)).toBeVisible();
  expect(screen.queryByText(/Движок: работает/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Показать дополнительные настройки" }));
  expect(screen.getByText(/Системные правила: sniff определяет домен/)).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  expect(screen.getByRole("heading", { name: "Правила · первое совпадение" })).toBeVisible();
  expect(screen.getByText(/Если ни одно правило не подошло/)).toBeVisible();
  expect(screen.queryByRole("button", { name: /Удалить системное/ })).not.toBeInTheDocument();
});

it("selects all LAN sources and saves a domain block without enabling traffic", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("radio", { name: "Все устройства (LAN)" }));
  expect(screen.getByRole("radio", { name: "Выбранные интерфейсы" })).not.toBeChecked();
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "video");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "rutube.ru");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Куда направить"), "block");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toMatchObject({
    ingress_interfaces: ["lan0"], enabled: false,
    rules: [expect.objectContaining({ name: "video", domain_suffix: ["rutube.ru"], action: "block" })],
  }));
});

it("saves a TProxy bypass exclusion in the draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить исключение" }));
  await user.type(screen.getByLabelText("Имя исключения"), "corp");
  await user.type(screen.getByLabelText("Назначение IPv4 (bypass)"), "10.9.0.0/16");
  await user.selectOptions(screen.getByLabelText("Протокол (bypass)"), "tcp");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(
      ([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.bypass).toEqual([{
      name: "corp", source_ip_cidr: [], ip_cidr: ["10.9.0.0/16"],
      ports: [], protocol: "tcp",
    }]);
  });
});

it("saves an expert UDP DNS server and its matching DNS rule", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Сервер" }));
  await user.type(screen.getByLabelText("Тег DNS-сервера"), "cloudflare");
  await user.type(screen.getByLabelText("Сервер DNS"), "1.1.1.1");
  await user.click(screen.getByRole("button", { name: "+ DNS-правило" }));
  await user.type(screen.getByLabelText("Имя DNS-правила"), "example_dns");
  await user.type(screen.getByLabelText("Домены DNS-правила"), "example.org");
  await user.selectOptions(screen.getByLabelText("DNS-сервер правила"), "cloudflare");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  const expected: TProxyDNS = {
    servers: [{ tag: "cloudflare", type: "udp", server: "1.1.1.1", server_port: null,
      tls_name: null, path: null, domain_resolver: null, detour: null }],
    rules: [{ name: "example_dns", domain_suffix: ["example.org"], rule_sets: [],
      server: "cloudflare" }],
  };
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(
      ([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    expect(JSON.parse(String(init.body)).tproxy.dns).toEqual(expected);
  });
});

it("saves expert matchers and engine parameters only to draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("switch", { name: "Sniff" }));
  await user.type(screen.getByLabelText("Таймаут UDP, секунд"), "120");
  await user.click(screen.getByRole("tab", { name: "Простой" }));
  await openNewExpertRule(user);
  await user.type(screen.getByLabelText("Имя правила"), "precise");
  await user.type(screen.getByLabelText("Точный домен"), "example.org");
  await user.type(screen.getByLabelText("MAC источника"), "aa:bb:cc:dd:ee:ff");
  await user.type(screen.getByLabelText("Вход (inbound)"), "tproxy_in");
  await user.selectOptions(screen.getByLabelText("Частный IP"), "false");
  await user.selectOptions(screen.getByLabelText("Сеть"), "udp");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const tproxy = JSON.parse(String(init.body)).tproxy;
    expect(tproxy.enabled).toBe(false);
    expect(tproxy.sniff).toBe(true);
    expect(tproxy.udp_timeout_seconds).toBe(120);
    expect(tproxy.rules[0]).toMatchObject({ domain_exact: ["example.org"],
      source_mac: ["aa:bb:cc:dd:ee:ff"], inbound: ["tproxy_in"],
      ip_is_private: false, network: "udp" });
  });
});

it("rejects conflicting domain matchers and invalid regex with visible backend codes", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await openNewExpertRule(user);
  await user.type(screen.getByLabelText("Имя правила"), "conflict");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.type(screen.getByLabelText("Точный домен"), "example.net");
  expect(screen.getByText(/Типы доменных условий нельзя смешивать/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();
  await user.clear(screen.getByLabelText("Точный домен"));
  await user.type(screen.getByLabelText("Регулярное выражение домена"), "(");
  expect(screen.getByText(/Типы доменных условий нельзя смешивать/)).toBeVisible();
  await user.clear(screen.getByLabelText("Домены (по строкам)"));
  expect(screen.getByText(/Некорректное регулярное выражение/)).toBeVisible();
  expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(false);
});

it("saves a single-level logical OR with two distinct child matchers", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await openNewExpertRule(user);
  await user.type(screen.getByLabelText("Имя правила"), "combined");
  await user.selectOptions(screen.getByLabelText("Логическая группа"), "or");
  expect(screen.getByText(/Укажите хотя бы одно условие правила/)).toBeVisible();
  await user.type(screen.getByLabelText("Подправило 1: Точный домен"), "example.org");
  await user.type(screen.getByLabelText("Подправило 2: MAC источника"), "aa:bb:cc:dd:ee:ff");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const [rule] = JSON.parse(String(init.body)).tproxy.rules;
    expect(rule.logical_mode).toBe("or");
    expect(rule.logical_rules).toMatchObject([
      { name: "child_a", domain_exact: ["example.org"], action: "direct" },
      { name: "child_b", source_mac: ["aa:bb:cc:dd:ee:ff"], action: "direct" },
    ]);
  });
});

it("keeps an existing policy while importing an outbound into the draft", async () => {
  const rule: TProxyRule = { name: "existing", domain_suffix: ["existing.test"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "direct", outbound: null, order: 0 };
  const fetch = setup(false, [rule], emptyConfiguration.proxies,
    { ...emptyConfiguration.tproxy, ingress_interfaces: ["lan0"] });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Добавить по ссылке" }));
  await user.type(screen.getByLabelText("Ссылка на прокси"), "vless://uuid@exit.example.com:443#new_exit");
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Добавить выход по ссылке" })).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch)).toMatchObject({
    tproxy: { rules: [expect.objectContaining({ name: "existing", action: "direct" })] },
    proxies: { enabled: true, outbounds: [expect.objectContaining({ tag: "new_exit" })] },
  }));
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});

it("saves a three-step outbound route without replacing DNS policy", async () => {
  const dns = { servers: [{ tag: "resolver", type: "udp" as const, server: "1.1.1.1", server_port: null,
    tls_name: null, path: null, domain_resolver: null, detour: null }], rules: [] };
  const fetch = setup(false, [], { ...proxiesWithOutbound, enabled: true },
    { ...emptyConfiguration.tproxy, dns });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "+ Правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "tunnel_site");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Куда направить"), "route");
  await user.selectOptions(screen.getByLabelText("Выход"), "proxy_a");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Шаг 3 из 3: проверка")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(savedDraft(fetch).tproxy).toMatchObject({
    enabled: false, ingress_interfaces: ["lan0"], final: "direct", dns,
    rules: [expect.objectContaining({ name: "tunnel_site", domain_suffix: ["example.org"],
      action: "route", outbound: "proxy_a", order: 0 })],
  }));
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});
