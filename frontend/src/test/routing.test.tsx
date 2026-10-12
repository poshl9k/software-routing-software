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

it("creates a guided rule with catalog rule-set declarations in the draft only", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByText("Выключено · черновик");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.click(screen.getByRole("button", { name: "Выбрать из каталога" }));
  await user.click(await screen.findByRole("checkbox", { name: "Видео" }));
  await user.click(screen.getByRole("button", { name: "Выбрать (1)" }));
  expect(screen.getByText(/Добавлено наборов в черновик: 1/)).toBeVisible();
  await waitFor(() => expect(document.querySelector(".MuiModal-root")).toBeNull());
  await waitFor(() => expect(getComputedStyle(screen.getByRole("button", { name: /^Добавить$/ })).pointerEvents).not.toBe("none"));
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
  expect(await screen.findByText(/ссылка сломана: resolver/)).toBeVisible();
  await waitFor(() => expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled());
});

it("saves disabled TProxy ingress and ordered block rule in draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  expect(await screen.findByText("Выключено · черновик")).toBeVisible();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  expect(screen.getByRole("switch", { name: "Включить выборочную маршрутизацию" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "blocked_site");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.selectOptions(screen.getByLabelText("Действие"), "block");
  await user.click(await screen.findByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const sent = JSON.parse(String(init.body));
    expect(sent.tproxy.enabled).toBe(false);
    expect(sent.tproxy.ingress_interfaces).toEqual(["lan0"]);
    expect(sent.tproxy.rules).toEqual([{
      name: "blocked_site", domain_suffix: ["example.org"], ip_cidr: [],
      source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [],
      action: "block", outbound: null, order: 0,
    }]);
  });
  expect(await screen.findByText(/blocked_site · домен example.org → Блокировать/)).toBeVisible();
});

it("confirms enabling only after a valid ingress and rule; saves enabled draft, not applied", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  const toggle = screen.getByRole("switch", { name: "Включить выборочную маршрутизацию" });
  expect(toggle).toBeDisabled();
  expect(screen.getByText(/Выберите хотя бы один источник/)).toBeVisible();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  expect(toggle).toBeDisabled();
  expect(screen.getByText(/Добавьте хотя бы одно правило/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "route_test");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  expect(toggle).toBeEnabled();
  await user.click(toggle);
  expect(screen.getByText(/Ошибка в настройках может нарушить подключение/)).toBeVisible();
  expect(toggle).not.toBeChecked();
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  expect(toggle).not.toBeChecked();
  await user.click(toggle);
  await user.click(screen.getByRole("button", { name: "Включить в черновике" }));
  expect(toggle).toBeChecked();
  await user.click(await screen.findByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBeTruthy());
  const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
  expect(JSON.parse(String(init.body)).tproxy.enabled).toBe(true);
  expect(await screen.findByText("Включено · черновик")).toBeVisible();
  expect(screen.queryByText("Включено · применено")).not.toBeInTheDocument();
});

it("blocks enabled route when outbound section is off or reference is missing", async () => {
  const rule: TProxyRule = { name: "proxy_rule", domain_suffix: ["example.org"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "route", outbound: "proxy_a", order: 0 };
  setup(false, [rule], proxiesWithOutbound, { ...emptyConfiguration.tproxy, ingress_interfaces: ["lan0"] });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  expect(screen.getByRole("switch", { name: "Включить выборочную маршрутизацию" })).toBeDisabled();
  expect(screen.getByText(/Включите секцию прокси-выходов/)).toBeVisible();
  await user.selectOptions(screen.getByLabelText("Выход"), "");
  expect(screen.getByRole("switch", { name: "Включить выборочную маршрутизацию" })).toBeDisabled();
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

it("retains unsaved TProxy edits after rejected draft", async () => {
  setup(true);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "retry_rule");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.net");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  expect(await screen.findByText(/Ошибка проверки конфигурации/)).toBeVisible();
  expect(screen.getByDisplayValue("retry_rule")).toBeVisible();
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
  await screen.findByText(/1\. first/);
  expect(screen.getByText("1. first")).toBeVisible();
  expect(screen.getByText("2. later")).toBeVisible();
  expect(screen.getByText("Что: домен first.test · Куда: Обычный маршрут")).toBeVisible();
  expect(screen.getByText("Что: домен later.test · Куда: Блокировать")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Вверх later" }));
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

it("routes a rule to a chosen outbound on save", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
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
  expect(await screen.findByText(/via_proxy · домен example.com → Прокси-выход · proxy_a/)).toBeVisible();
});

it("clears the outbound when a routing rule stops routing", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
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

it("offers guided setup and keeps expert fields in the expert view", async () => {
  setup();
  const user = userEvent.setup();
  expect(await screen.findByRole("tab", { name: "Настроить" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("heading", { name: "Начните настройку" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Выбрать источник" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Включить" })).toBeDisabled();
  expect(screen.getByText(/Первое подходящее правило определяет путь трафика/)).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  expect(screen.getByText(/Исключений нет/)).toBeVisible();
  expect(screen.queryByLabelText("Таймаут UDP, секунд")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  expect(screen.getByRole("heading", { name: "Источники" })).toBeVisible();
  expect(screen.getByLabelText("Таймаут UDP, секунд")).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Настроить" }));
  expect(screen.queryByLabelText("Таймаут UDP, секунд")).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Правила" })).toBeVisible();
});

it("adds, reorders and deletes guided rules while preserving first-match and final", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  for (const [name, domain, action] of [["first", "first.test", "direct"], ["second", "second.test", "block"]]) {
    await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
    await user.type(screen.getAllByLabelText("Имя правила").at(-1)!, name);
    await user.type(screen.getByLabelText("Домены"), domain);
    await user.selectOptions(screen.getAllByLabelText("Куда").at(-1)!, action);
    await user.click(screen.getByRole("button", { name: "Добавить" }));
  }
  expect(screen.getByText("1. first")).toBeVisible();
  expect(screen.getByText("2. second")).toBeVisible();
  expect(screen.getByText("Что: домен second.test · Куда: Блокировать")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Вверх second" }));
  expect(screen.getByText("1. second")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Удалить правило first" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const sent = JSON.parse(String(init.body)).tproxy;
    expect(sent.rules).toEqual([{ name: "second", domain_suffix: ["second.test"], ip_cidr: [],
      source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "block", outbound: null, order: 0 }]);
    expect(sent.final).toBe("direct");
    expect(sent.enabled).toBe(false);
  });
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
  expect(screen.getByRole("heading", { name: "Служебные правила (добавляются автоматически)" })).toBeVisible();
  expect(screen.getByText(/DNS-запросы \(порт 53\)/)).toBeVisible();
  expect(screen.getByText(/Локальные адреса IPv4/)).toBeVisible();
  expect(screen.getByText(/Таймаут UDP/)).toBeVisible();
  expect(screen.queryByRole("button", { name: /Удалить системное/ })).not.toBeInTheDocument();
});

it("selects all LAN sources and a service-domain shortcut without enabling traffic", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("radio", { name: "Все устройства (LAN)" }));
  expect(screen.getByRole("radio", { name: "Выбранные интерфейсы" })).not.toBeChecked();
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "video");
  await user.click(screen.getByRole("button", { name: "RuTube (rutube.ru)" }));
  expect(screen.getByLabelText("Домены")).toHaveValue("rutube.ru");
  await user.selectOptions(screen.getByLabelText("Куда"), "block");
  await user.click(screen.getByRole("button", { name: "Добавить" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const sent = JSON.parse(String(init.body)).tproxy;
    expect(sent.ingress_interfaces).toEqual(["lan0"]);
    expect(sent.rules[0]).toMatchObject({ name: "video", domain_suffix: ["rutube.ru"], action: "block" });
    expect(sent.enabled).toBe(false);
  });
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
  await user.click(screen.getByRole("button", { name: "+ Добавить DNS-сервер" }));
  await user.type(screen.getByLabelText("Тег DNS-сервера"), "cloudflare");
  await user.type(screen.getByLabelText("Сервер DNS"), "1.1.1.1");
  await user.click(screen.getByRole("button", { name: "+ Добавить DNS-правило" }));
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
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
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
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "conflict");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.type(screen.getByLabelText("Точный домен"), "example.net");
  expect(screen.getByText(/tproxy.domain_matchers_conflict/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();
  await user.clear(screen.getByLabelText("Точный домен"));
  await user.type(screen.getByLabelText("Регулярное выражение домена"), "(");
  expect(screen.getByText(/tproxy.domain_matchers_conflict/)).toBeVisible();
  await user.clear(screen.getByLabelText("Домены (по строкам)"));
  expect(screen.getByText(/tproxy.domain_regex_invalid/)).toBeVisible();
  expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(false);
});

it("saves a single-level logical OR with two distinct child matchers", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("tab", { name: "Эксперт" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "combined");
  await user.selectOptions(screen.getByLabelText("Логическая группа"), "or");
  expect(screen.getByText(/tproxy.rule_matcher_required/)).toBeVisible();
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

it("blocks quickstart when an existing policy would be replaced or proxies are disabled", async () => {
  const fetch = setup(false, [], proxiesWithOutbound, { ...emptyConfiguration.tproxy, enabled: true });
  await screen.findByRole("button", { name: "Редактировать" });
  expect(screen.queryByRole("button", { name: "Выбрать источник" })).not.toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Правила" })).toBeVisible();
  expect(screen.getByRole("tab", { name: "Настроить" })).toHaveAttribute("aria-selected", "true");
  expect(fetch.mock.calls.some(([path, init]) => path === "/api/draft" && init?.method === "PUT")).toBe(false);
});

it("blocks quickstart saving when proxy outputs are disabled", async () => {
  setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Выбрать источник" }));
  expect(screen.getByText(/Включите секцию прокси-выходов/)).toBeVisible();
  await user.selectOptions(screen.getByLabelText("Выход (мастер)"), "proxy_a");
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "Настроить правило" }));
  await user.type(screen.getByLabelText("Имя правила (мастер)"), "route_site");
  await user.type(screen.getByLabelText("Домены (мастер)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Проверить и сохранить" }));
  expect(screen.getByRole("button", { name: "Сохранить черновик" })).toBeDisabled();
});

it("walks quickstart through source, rule and confirmation; saves disabled draft", async () => {
  const fetch = setup(false, [], { ...proxiesWithOutbound, enabled: true });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Выбрать источник" }));
  expect(screen.getByRole("heading", { name: "Источник" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Настроить правило" })).toBeDisabled();
  await user.selectOptions(screen.getByLabelText("Выход (мастер)"), "proxy_a");
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "Настроить правило" }));
  expect(screen.getByRole("heading", { name: "Правила" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Проверить и сохранить" })).toBeDisabled();
  await user.type(screen.getByLabelText("Имя правила (мастер)"), "tunnel_site");
  await user.type(screen.getByLabelText("Домены (мастер)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Проверить и сохранить" }));
  expect(screen.getByRole("heading", { name: "Включить после сохранения" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Сохранить черновик" })).toBeEnabled();
  await user.click(screen.getAllByRole("button", { name: "Показать дополнительные настройки" }).at(-1)!);
  await user.clear(screen.getByLabelText("Тег прямого DNS"));
  await user.type(screen.getByLabelText("Тег прямого DNS"), "1bad");
  expect(screen.getByRole("button", { name: "Сохранить черновик" })).toBeDisabled();
  await user.clear(screen.getByLabelText("Тег прямого DNS"));
  await user.type(screen.getByLabelText("Тег прямого DNS"), "dns_direct");
  await user.clear(screen.getByLabelText("Тег туннельного DNS"));
  await user.type(screen.getByLabelText("Тег туннельного DNS"), "dns_tunnel");
  expect(screen.getByText(/политика останется выключенной/)).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => String(path).includes("preview"))).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
  await waitFor(() => {
    const [, init] = fetch.mock.calls.find(([path, init]) => path === "/api/draft" && init?.method === "PUT")!;
    const sent = JSON.parse(String(init.body)).tproxy;
    expect(sent.enabled).toBe(false);
    expect(sent.ingress_interfaces).toEqual(["lan0"]);
    expect(sent.final).toBe("direct");
    expect(sent.sniff).toBe(true);
    expect(sent.final_outbound).toBeNull();
    expect(sent.rules).toEqual([{ ...emptyConfiguration.tproxy.rules[0],
      name: "tunnel_site", domain_suffix: ["example.org"], ip_cidr: [],
      source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [],
      action: "route", outbound: "proxy_a", order: 0 }]);
    expect(sent.dns.servers.map((server: TProxyDNS["servers"][number]) => [server.tag, server.detour]))
      .toEqual([["dns_direct", "direct"], ["dns_tunnel", "proxy_a"]]);
    expect(sent.dns.rules).toEqual([{ name: "dns_tunnel_site", domain_suffix: ["example.org"],
      rule_sets: [], server: "dns_tunnel" }]);
  });
});
