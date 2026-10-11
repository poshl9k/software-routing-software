import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { TProxyDNS, TProxyRule } from "../types";

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
        : fail
          ? { code: "validation.failed", message: "Ошибка проверки конфигурации", details: [] }
          : { id: 1, status: "draft", configuration: JSON.parse(String(init?.body)) },
    ), { status: path === "/api/versions" || !fail ? 200 : 422 })));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

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
  await user.click(screen.getByRole("button", { name: "Удалить DNS-сервер resolver" }));
  expect(screen.getByText(/DNS-правило domains/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Удалить" }));
  expect(await screen.findByText(/ссылка сломана: resolver/)).toBeVisible();
  await waitFor(() => expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled());
});

it("saves disabled TProxy ingress and ordered block rule in draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  expect(await screen.findByText("Выключено в черновике")).toBeVisible();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  expect(screen.getByRole("switch", { name: "Включить выборочную маршрутизацию" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "blocked_site");
  await user.type(screen.getByLabelText("Домены (по строкам)"), "example.org");
  await user.selectOptions(screen.getByLabelText("Действие"), "block");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
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
  expect(await screen.findByText(/blocked_site · block · домен example.org/)).toBeVisible();
});

it("confirms enabling only after a valid ingress and rule; saves enabled draft, not applied", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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
  expect(await screen.findByText("Включено в черновике")).toBeVisible();
  expect(screen.queryByText("Применено: включено")).not.toBeInTheDocument();
});

it("blocks enabled route when outbound section is off or reference is missing", async () => {
  const rule: TProxyRule = { name: "proxy_rule", domain_suffix: ["example.org"], ip_cidr: [],
    source_ip_cidr: [], rule_sets: [], protocol: "any", ports: [], action: "route", outbound: "proxy_a", order: 0 };
  setup(false, [rule], proxiesWithOutbound, { ...emptyConfiguration.tproxy, ingress_interfaces: ["lan0"] });
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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
  expect(await screen.findByText("Применено: включено")).toBeVisible();
  expect(screen.getByText(/статус конфигурации не проверяет доступность выхода/)).toBeVisible();
});

it("retains unsaved TProxy edits after rejected draft", async () => {
  setup(true);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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
  await screen.findByText(/first · direct/);
  expect(screen.getAllByText(/(?:later|first) ·/).map((el) => el.textContent)).toEqual([
    "1. first · direct · домен first.test → Обычный маршрут",
    "2. later · block · домен later.test → Блокировать",
  ]);
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
  expect(await screen.findByText(/via_proxy · route · домен example.com → Прокси-выход → proxy_a/)).toBeVisible();
});

it("clears the outbound when a routing rule stops routing", async () => {
  const fetch = setup(false, [], proxiesWithOutbound);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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

it("shows the Simple overview and reveals expert fields on toggle", async () => {
  setup();
  const user = userEvent.setup();
  // Browse defaults to Простой: counters + flow summary.
  expect(screen.getByText(/Источники: 0/)).toBeVisible();
  expect(screen.getByText(/→ исключения → правила по порядку →/)).toBeVisible();
  // Editing opens in Эксперт with the full field editor.
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  expect(await screen.findByText("Источники трафика")).toBeVisible();
  // Compact mode is read-only, even when draft editing was started.
  await user.click(screen.getByRole("tab", { name: "Простой" }));
  await waitFor(() =>
    expect(screen.queryByText("Источники трафика")).not.toBeInTheDocument());
  expect(screen.getByText(/→ исключения → правила по порядку →/)).toBeVisible();
  expect(screen.queryByRole("button", { name: "Сохранить" })).not.toBeInTheDocument();
});

it("saves a TProxy bypass exclusion in the draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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
  setup(false, [], proxiesWithOutbound, { ...emptyConfiguration.tproxy, enabled: true });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Редактировать" });
  await user.click(screen.getByRole("tab", { name: "Мастер" }));
  expect(screen.getByText(/Мастер доступен только для пустой выключенной/)).toBeVisible();
  expect(screen.getByText(/Включите секцию прокси-выходов/)).toBeVisible();
});

it("walks quickstart through tunnel, matchers, DNS and summary; saves disabled draft", async () => {
  const fetch = setup(false, [], { ...proxiesWithOutbound, enabled: true });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Редактировать" });
  await user.click(screen.getByRole("tab", { name: "Мастер" }));
  expect(screen.getByText("Туннель")).toBeVisible();
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.selectOptions(screen.getByLabelText("Выход (мастер)"), "proxy_a");
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Что в туннель")).toBeVisible();
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("Имя правила (мастер)"), "tunnel_site");
  await user.type(screen.getByLabelText("Домены (мастер)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("DNS")).toBeVisible();
  // Engine tags dns-direct/dns-tunnel are valid (hyphens allowed by contract).
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
  await user.clear(screen.getByLabelText("Тег прямого DNS"));
  await user.type(screen.getByLabelText("Тег прямого DNS"), "1bad");
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.clear(screen.getByLabelText("Тег прямого DNS"));
  await user.type(screen.getByLabelText("Тег прямого DNS"), "dns_direct");
  await user.clear(screen.getByLabelText("Тег туннельного DNS"));
  await user.type(screen.getByLabelText("Тег туннельного DNS"), "dns_tunnel");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByText("Применение")).toBeVisible();
  expect(screen.getByText(/Конечное действие: direct; TProxy останется выключен/)).toBeVisible();
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
