import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { TProxyDNS, TProxyRule } from "../types";

function setup(fail = false, rules: TProxyRule[] = [], proxies = emptyConfiguration.proxies) {
  const configuration = {
    ...emptyConfiguration,
    interfaces: [{ name: "lan0", zone: "lan" as const, kind: "physical" as const }],
    tproxy: { ...emptyConfiguration.tproxy, rules },
    proxies,
  };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) =>
    Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [{ id: 1, status: "draft", configuration }]
        : fail
          ? { code: "validation.failed", message: "Ошибка проверки конфигурации", details: [] }
          : { id: 1, status: "draft", configuration: JSON.parse(String(init?.body)) },
    ), { status: path === "/api/versions" || !fail ? 200 : 422 })));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter><RouterProvider><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

it("saves disabled TProxy ingress and ordered block rule in draft", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  expect(screen.getByRole("button", { name: "Включить TProxy" })).toBeDisabled();
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
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
  expect(await screen.findByText(/blocked_site · block/)).toBeVisible();
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
    "first · direct", "later · block",
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
  secret: null, tls: false, tls_server_name: null, tls_insecure: false, admin_listen: null,
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
  expect(await screen.findByText(/via_proxy · route → proxy_a/)).toBeVisible();
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
  expect(screen.getByText(/→ sing-box →/)).toBeVisible();
  // Editing opens in Эксперт with the full field editor.
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  expect(await screen.findByText("Источники трафика")).toBeVisible();
  // Switching to Простой while editing keeps the compact overview + footer only.
  await user.click(screen.getByRole("tab", { name: "Простой" }));
  await waitFor(() =>
    expect(screen.queryByText("Источники трафика")).not.toBeInTheDocument());
  expect(screen.getByText(/→ sing-box →/)).toBeVisible();
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeVisible();
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

it("walks the wizard through 4 steps and saves a draft rule with disabled state checks", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Редактировать" });
  await user.click(screen.getByRole("tab", { name: "Мастер" }));
  // Step 0 — sources: check disabled without source
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: "lan0" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  // Step 1 — matchers: check disabled without matcher
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("Имя правила (мастер)"), "blocked_site");
  await user.type(screen.getByLabelText("Домены (мастер)"), "example.org");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  // Step 2 — action
  await user.selectOptions(screen.getByLabelText("Действие (мастер)"), "block");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  // Step 3 — local draft summary; no preview API call before save.
  expect(screen.getByText("Правило: blocked_site")).toBeVisible();
  expect(screen.getByText("Назначение: block")).toBeVisible();
  expect(screen.getByText(/Полный предпросмотр sing-box доступен после сохранения черновика/)).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => String(path).includes("preview"))).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить черновик" }));
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
  expect(await screen.findByText(/blocked_site · block/)).toBeVisible();
});
