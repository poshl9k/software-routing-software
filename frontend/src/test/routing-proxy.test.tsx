import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { useEffect } from "react";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider, useRouterState } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { ProxyOutbound, ProxySettings, RuleSetStatus, TProxy } from "../types";

type Role = "admin" | "operator";

function setup(options?: {
  fail?: boolean;
  proxies?: ProxySettings;
  tproxy?: TProxy;
  role?: Role;
  rulesets?: RuleSetStatus[];
  updateFails?: boolean;
  preview?: unknown;
  refresh?: unknown;
}) {
  const configuration = {
    ...emptyConfiguration,
    proxies: options?.proxies ?? emptyConfiguration.proxies,
    tproxy: options?.tproxy ?? emptyConfiguration.tproxy,
  };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/versions")
      return Promise.resolve(
        new Response(JSON.stringify([{ id: 1, status: "draft", configuration }])),
      );
    if (path === "/api/auth/me")
      return Promise.resolve(
        new Response(
          JSON.stringify({ id: 1, username: options?.role ?? "admin", role: options?.role ?? "admin" }),
        ),
      );
    if (path === "/api/rulesets")
      return Promise.resolve(
        new Response(JSON.stringify(options?.rulesets ?? [])),
      );
    if (path === "/api/rulesets/update") {
      if (options?.updateFails)
        return Promise.resolve(
          new Response(
            JSON.stringify({ code: "download.http_error", message: "Ошибка загрузки", details: [] }),
            { status: 409 },
          ),
        );
      return Promise.resolve(new Response(JSON.stringify({ status: "ok", name: "geo" })));
    }
    if (path === "/api/proxy/subscriptions/preview")
      return Promise.resolve(new Response(JSON.stringify(options?.preview ?? { members: [], skipped: [], outbounds: [], groups: [] })));
    if (path === "/api/proxy/subscriptions/sub1/refresh")
      return Promise.resolve(new Response(JSON.stringify(options?.refresh ?? { added: [], updated: [], unchanged: [], orphans: [], skipped: [], outbounds: [], groups: [] })));
    if (options?.fail)
      return Promise.resolve(
        new Response(
          JSON.stringify({
            code: "validation.failed",
            message: "Ошибка проверки конфигурации",
            details: [],
          }),
          { status: 422 },
        ),
      );
    return Promise.resolve(
      new Response(
        JSON.stringify({
          id: 1,
          status: "draft",
          configuration: JSON.parse(String(init?.body)),
        }),
      ),
    );
  });
  vi.stubGlobal("fetch", fetch);
  function Session() {
    const { loadUser } = useRouterState();
    useEffect(() => {
      void loadUser();
    }, [loadUser]);
    return null;
  }
  render(
    <MemoryRouter>
      <RouterProvider>
        <Session />
        <Routing />
      </RouterProvider>
    </MemoryRouter>,
  );
  return fetch;
}

const openTab = async (user: ReturnType<typeof userEvent.setup>, name: string) =>
  user.click(screen.getByRole("tab", { name }));
const saveButton = () => screen.getByRole("button", { name: "Сохранить" });
// Editor fields now live inside a modal dialog; close it before touching page-level
// controls (add buttons, other dialogs, the page footer).
const closeDialog = async (user: ReturnType<typeof userEvent.setup>) =>
  user.click(screen.getByRole("button", { name: "Отмена" }));
const sentProxies = (fetch: ReturnType<typeof setup>) => {
  const call = fetch.mock.calls.find(
    ([path, init]) => path === "/api/draft" && (init as RequestInit)?.method === "PUT",
  );
  return JSON.parse(String((call![1] as RequestInit).body)).proxies as ProxySettings;
};

it("saves proxy outbound, subscription and group as a draft with a write-only secret", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));

  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "ss1");
  await user.type(screen.getByLabelText("Сервер"), "exit.example.com");
  await user.type(screen.getByLabelText("Порт"), "8388");
  await user.type(screen.getByLabelText("Секрет (пароль / UUID)"), "topsecret");
  await closeDialog(user);

  await user.click(screen.getByRole("button", { name: "+ Подписка по URL" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.type(screen.getByLabelText("URL подписки"), "https://sub.example.com/list");
  await user.selectOptions(screen.getByLabelText("Формат"), "clash");
  await closeDialog(user);

  await user.click(screen.getByRole("button", { name: "+ Добавить группу" }));
  await user.type(screen.getByLabelText("Тег группы"), "grp");
  await user.click(screen.getByRole("checkbox", { name: "ss1" }));
  await closeDialog(user);

  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch)).toBeTruthy());
  const proxies = sentProxies(fetch);
  expect(proxies.outbounds).toEqual([
    {
      tag: "ss1",
      type: "shadowsocks",
      server: "exit.example.com",
      port: 8388,
      secret: { plaintext: "topsecret" },
      method: null,
      tls: false,
      tls_server_name: null,
      tls_insecure: false,
      admin_listen: null,
    },
  ]);
  expect(proxies.subscriptions).toEqual([
    expect.objectContaining({ name: "sub1", url: "https://sub.example.com/list", format: "clash", interval_hours: 24, enabled: false }),
  ]);
  expect(proxies.groups).toEqual([
    expect.objectContaining({ tag: "grp", type: "selector", outbounds: ["ss1"], url: null, interval_minutes: null }),
  ]);
  // The secret is sent as write-only plaintext, never as a redacted marker.
  expect(JSON.stringify(proxies)).not.toContain("redacted");
  // Read-only view keeps the exit but never renders the secret.
  expect((await screen.findAllByText("ss1")).length).toBeGreaterThan(0);
  expect(screen.queryByText("topsecret")).not.toBeInTheDocument();
  expect(screen.queryByDisplayValue("topsecret")).not.toBeInTheDocument();
});

it("imports pasted links into the saved draft and clears the input", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  const input = screen.getByLabelText("Ссылки для импорта (по одной в строке)");
  await user.type(input, "vless://uuid-one@exit.example.com:443?security=tls#alpha{enter}trojan://pass-two@other.example.com:443#beta");
  await user.click(screen.getByRole("button", { name: "Импортировать" }));
  expect(input).toHaveValue("");
  expect(screen.getByText("Импортировано выходов: 2")).toBeVisible();
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(2));
  expect(sentProxies(fetch).outbounds).toMatchObject([
    { tag: "alpha", type: "vless", server: "exit.example.com", port: 443, tls: true, secret: { plaintext: "uuid-one" } },
    { tag: "beta", type: "trojan", server: "other.example.com", port: 443, secret: { plaintext: "pass-two" } },
  ]);
});

it("warns about policy and group references before deleting an outbound", async () => {
  const outbound: ProxyOutbound = { tag: "exit_a", type: "vless", server: "example.org", port: 443,
    secret: null, method: null, tls: false, tls_server_name: null, tls_insecure: false, admin_listen: null };
  setup({ proxies: { ...emptyConfiguration.proxies, outbounds: [outbound],
    groups: [{ tag: "pool", type: "selector", outbounds: ["exit_a"], url: null, interval_minutes: null }] },
    tproxy: { ...emptyConfiguration.tproxy, final: "route", final_outbound: "exit_a",
      rules: [{ name: "sites", domain_suffix: ["example.org"], ip_cidr: [], source_ip_cidr: [],
        rule_sets: [], protocol: "any", ports: [], action: "route", outbound: "exit_a", order: 0 }] } });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Изменить выход exit_a" }));
  await user.click(screen.getByRole("button", { name: "Удалить выход exit_a" }));
  expect(screen.getByText(/правило sites, конечное действие, группа pool/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  expect(screen.getByDisplayValue("exit_a")).toBeVisible();
});

it("removes selected outbounds from the saved draft", async () => {
  const base: ProxyOutbound = {
    tag: "first", type: "shadowsocks", server: "exit.example.com", port: 8388,
    secret: { redacted: true }, method: "aes-256-gcm", tls: false,
    tls_server_name: null, tls_insecure: false, admin_listen: null,
  };
  const fetch = setup({ proxies: {
    ...emptyConfiguration.proxies,
    outbounds: [base, { ...base, tag: "second" }, { ...base, tag: "third" }],
  } });
  const user = userEvent.setup();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("checkbox", { name: "Выбрать выход first" }));
  await user.click(screen.getByRole("checkbox", { name: "Выбрать выход third" }));
  await user.click(screen.getByRole("button", { name: "Удалить выбранные" }));
  expect(screen.getByText(/Ссылки на first, third: нет/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Удалить" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Удалить выбранные" })).toBeDisabled());
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(1));
  expect(sentProxies(fetch).outbounds[0].tag).toBe("second");
  vi.restoreAllMocks();
});

it("duplicates selected outbounds with unique backend-valid tags", async () => {
  const base: ProxyOutbound = {
    tag: "first", type: "shadowsocks", server: "exit.example.com", port: 8388,
    secret: { redacted: true }, method: "aes-256-gcm", tls: false,
    tls_server_name: null, tls_insecure: false, admin_listen: null,
  };
  const fetch = setup({ proxies: {
    ...emptyConfiguration.proxies,
    outbounds: [base, { ...base, tag: "first_copy" }],
  } });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("checkbox", { name: "Выбрать выход first" }));
  await user.click(screen.getByRole("button", { name: "Дублировать выбранные" }));
  expect(saveButton()).toBeEnabled();
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(3));
  expect(sentProxies(fetch).outbounds[2]).toMatchObject({ tag: "first_copy2", method: "aes-256-gcm" });
});

it("blocks saving an outbound without a server/port and a non-https subscription", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "ss1");
  expect(saveButton()).toBeDisabled();
  await user.type(screen.getByLabelText("Сервер"), "exit.example.com");
  await user.type(screen.getByLabelText("Порт"), "70000");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Порт"));
  await user.type(screen.getByLabelText("Порт"), "8388");
  await closeDialog(user);
  await user.click(screen.getByRole("button", { name: "+ Подписка по URL" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.type(screen.getByLabelText("URL подписки"), "http://not-secure.example.com");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("URL подписки"));
  await user.type(screen.getByLabelText("URL подписки"), "https://secure.example.com/list");
  expect(saveButton()).toBeEnabled();
});

it("validates inline subscription content and header and filter syntax", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Подписка по URL" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.click(screen.getByLabelText("Список вручную (inline)"));
  expect(screen.queryByLabelText("URL подписки")).not.toBeInTheDocument();
  expect(saveButton()).toBeDisabled();
  await user.type(screen.getByLabelText("Список вручную"), "vless://example");
  expect(saveButton()).toBeEnabled();
  const headers = screen.getByLabelText("Заголовки (Name: value, по одному на строку)");
  await user.type(headers, "Bad header: value");
  expect(saveButton()).toBeDisabled();
  await user.clear(headers);
  fireEvent.change(headers, { target: { value: "Authorization: Bearer token" } });
  expect(saveButton()).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Включить по regex"), { target: { value: "[" } });
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Включить по regex"));
  await user.type(screen.getByLabelText("Включить по regex"), "^eu-");
  await user.type(screen.getByLabelText("Исключить по regex"), "(");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Исключить по regex"));
  expect(saveButton()).toBeEnabled();
});

it("saves subscription selection, URL test, filters and member fields", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Подписка по URL" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.type(screen.getByLabelText("URL подписки"), "https://sub.example.com/list");
  await user.selectOptions(screen.getByLabelText("Режим выбора"), "urltest");
  const tolerance = screen.getByLabelText("Допуск проверки, мс");
  await user.type(screen.getByLabelText("URL проверки скорости"), "https://probe.example.com/204");
  await user.type(screen.getByLabelText("Интервал проверки, минут"), "30");
  await user.type(tolerance, "5001");
  expect(saveButton()).toBeDisabled();
  fireEvent.change(tolerance, { target: { value: "-1" } });
  expect(saveButton()).toBeDisabled();
  await user.clear(tolerance);
  await user.type(tolerance, "0");
  expect(saveButton()).toBeEnabled();
  await user.clear(tolerance);
  await user.type(tolerance, "5000");
  expect(saveButton()).toBeEnabled();
  fireEvent.change(screen.getByLabelText("Заголовки (Name: value, по одному на строку)"), { target: { value: "Authorization: Bearer token" } });
  await user.type(screen.getByLabelText("Включить по regex"), "^eu-");
  await user.type(screen.getByLabelText("Исключить по regex"), "deprecated$");
  await user.type(screen.getByLabelText("Активный участник"), "eu-1");
  fireEvent.change(screen.getByLabelText("Исключённые участники (по одному на строку)"), { target: { value: "old-1\nold-2" } });
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).subscriptions).toHaveLength(1));
  expect(sentProxies(fetch).subscriptions[0]).toMatchObject({
    mode: "urltest", url_test: "https://probe.example.com/204", test_interval_minutes: 30,
    test_tolerance_ms: 5000, headers: ["Authorization: Bearer token"],
    filter_include: "^eu-", filter_exclude: "deprecated$", active_member: "eu-1",
    excluded_members: ["old-1", "old-2"],
  });
});

it("hides stored subscription headers and preserves them unless replaced", async () => {
  const fetch = setup({ proxies: { ...emptyConfiguration.proxies, subscriptions: [{
    name: "sub1", url: "https://sub.example.com/list", format: "auto", interval_hours: 24,
    enabled: false, headers: ["Authorization: Bearer private-token"],
  }] } });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  expect(screen.queryByText(/private-token/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  expect(screen.getByLabelText("Заголовки (Name: value, по одному на строку)")).toHaveValue("");
  expect(screen.queryByDisplayValue(/private-token/)).not.toBeInTheDocument();
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).subscriptions).toHaveLength(1));
  expect(sentProxies(fetch).subscriptions[0].headers).toEqual(["Authorization: Bearer private-token"]);
});

it("saves inline content without requiring a subscription URL", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Подписка по URL" }));
  await user.type(screen.getByLabelText("Имя подписки"), "manual");
  await user.click(screen.getByLabelText("Список вручную (inline)"));
  await user.type(screen.getByLabelText("Список вручную"), "vless://node");
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).subscriptions).toHaveLength(1));
  expect(sentProxies(fetch).subscriptions[0]).toMatchObject({ inline: true, inline_content: "vless://node", url: "" });
});

it("shows group tolerance only for urltest and enforces the 0..5000 ms bounds", async () => {
  const fetch = setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "exit1");
  await user.selectOptions(screen.getByLabelText("Тип"), "direct");
  await closeDialog(user);
  await user.click(screen.getByRole("button", { name: "+ Добавить группу" }));
  await user.type(screen.getByLabelText("Тег группы"), "pool");
  await user.click(screen.getByRole("checkbox", { name: "exit1" }));
  expect(screen.queryByLabelText("Допуск, мс")).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Тип группы"), "urltest");
  const tolerance = screen.getByLabelText("Допуск, мс");
  expect(tolerance).toHaveValue(null);
  await user.type(tolerance, "5001");
  expect(saveButton()).toBeDisabled();
  fireEvent.change(tolerance, { target: { value: "-1" } });
  expect(saveButton()).toBeDisabled();
  await user.clear(tolerance);
  await user.type(tolerance, "0");
  expect(saveButton()).toBeEnabled();
  await user.clear(tolerance);
  await user.type(tolerance, "5000");
  expect(saveButton()).toBeEnabled();
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).groups).toHaveLength(1));
  expect(sentProxies(fetch).groups[0]).toMatchObject({ type: "urltest", tolerance_ms: 5000 });
});

it("rejects duplicate outbound tags and a reserved direct tag", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "dup");
  await user.type(screen.getByLabelText("Сервер"), "a.example.com");
  await user.type(screen.getByLabelText("Порт"), "8388");
  await closeDialog(user);
  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "dup");
  await user.type(screen.getByLabelText("Сервер"), "b.example.com");
  await user.type(screen.getByLabelText("Порт"), "8389");
  // Both exits are otherwise valid, so only the duplicate tag keeps save off.
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Тег выхода"));
  await user.type(screen.getByLabelText("Тег выхода"), "direct");
  expect(saveButton()).toBeDisabled();
});

it("shows empty-state prompts for every proxy collection and the rule-set list", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  expect(screen.getByText(/TProxy настраивается отдельно и меняет трафик только после общего применения/)).toBeVisible();
  expect(screen.getByText("Нет прокси-выходов")).toBeVisible();
  expect(screen.getByText("Нет групп")).toBeVisible();
  await user.click(screen.getByRole("tab", { name: "Подписки" }));
  expect(screen.getByText("Нет подписок")).toBeVisible();
  await openTab(user, "Источники списков");
  expect(screen.getByText("Rule-set не подключены")).toBeVisible();
  expect(screen.getByRole("table")).toBeVisible();
});

it("surfaces a rejected draft and retains the local outbound for retry", async () => {
  setup({ fail: true });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
  await user.type(screen.getByLabelText("Тег выхода"), "keep");
  await user.type(screen.getByLabelText("Сервер"), "exit.example.com");
  await user.type(screen.getByLabelText("Порт"), "8388");
  await user.click(saveButton());
  expect(await screen.findByText(/Ошибка проверки конфигурации/)).toBeVisible();
  expect(screen.getByLabelText("Тег выхода")).toHaveValue("keep");
  expect(saveButton()).toBeEnabled();
});

it("keeps proxy exits read-only for an operator", async () => {
  const fetch = setup({ role: "operator" });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  // `loadUser` resolves asynchronously; the toggle flips to disabled once the
  // operator role is known.
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Редактировать" })).toBeDisabled(),
  );
  expect(fetch.mock.calls.filter(([, init]) => (init as RequestInit)?.method)).toHaveLength(0);
});

const SUB_OUT: ProxyOutbound = { tag: "sub_node", type: "vless", server: "exit.example.org", port: 443,
  secret: { plaintext: "uuid-secret" }, method: null, tls: true, tls_server_name: "front.example.org",
  tls_insecure: false, admin_listen: null };
const SUB_GROUP = { tag: "sub1", type: "selector" as const, outbounds: ["sub_node"],
  url: null, interval_minutes: null, tolerance_ms: null };
const SUB = { name: "sub1", url: "https://provider.example.org/feed?token=hidden", format: "auto" as const,
  interval_hours: 24, enabled: false, mode: "selector" as const, inline: false, inline_content: null };
const MEMBER = { tag: "sub_node", label: "Узел Европа", protocol: "vless", server: "exit.example.org",
  port: 443, transport: "grpc", sni: "front.example.org", security: "tls" };

it("previews URL on agent with authorization and shows server details", async () => {
  const fetch = setup({ proxies: { ...emptyConfiguration.proxies, subscriptions: [SUB] },
    preview: { members: [MEMBER], skipped: [], outbounds: [SUB_OUT], groups: [SUB_GROUP] } });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  await user.click(await screen.findByRole("tab", { name: "Подписки" }));
  await user.click(screen.getByRole("button", { name: "Просмотр" }));
  expect(await screen.findByText("Узел Европа")).toBeVisible();
  expect(screen.getByText("grpc")).toBeVisible();
  expect(screen.getByText("front.example.org / tls")).toBeVisible();
  const call = fetch.mock.calls.find(([path]) => path === "/api/proxy/subscriptions/preview")!;
  expect(JSON.parse(String((call[1] as RequestInit).body))).toMatchObject({ authorized: true, subscription: { url: SUB.url } });
  expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(false);
});

it("applies preview outbounds and selector group into enabled draft without applying engine", async () => {
  const fetch = setup({ proxies: { ...emptyConfiguration.proxies, subscriptions: [SUB] },
    preview: { members: [MEMBER], skipped: [], outbounds: [SUB_OUT], groups: [SUB_GROUP] } });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  await user.click(screen.getByRole("button", { name: "Просмотр" }));
  await screen.findAllByText("Узел Европа");
  await user.click(screen.getByRole("button", { name: "Применить предложение" }));
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).groups).toHaveLength(1));
  expect(sentProxies(fetch)).toMatchObject({ enabled: true, outbounds: [SUB_OUT], groups: [SUB_GROUP],
    subscriptions: [expect.objectContaining({ enabled: true, url: SUB.url })] });
  expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
});

it("keeps URL masked and intact after inline toggle cycle", async () => {
  const fetch = setup({ proxies: { ...emptyConfiguration.proxies, subscriptions: [SUB] } });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  await user.click(screen.getByLabelText("Список вручную (inline)"));
  await user.type(screen.getByLabelText("Список вручную"), "vless://node");
  await user.click(screen.getByLabelText("Список вручную (inline)"));
  expect(screen.getByText(/URL подписки: https:\/\/•••/)).toBeVisible();
  expect(screen.queryByDisplayValue(SUB.url)).not.toBeInTheDocument();
  await user.click(saveButton());
  await waitFor(() => expect(sentProxies(fetch).subscriptions[0].url).toBe(SUB.url));
});

it("refresh shows diff and orphan warning without deleting anything", async () => {
  const fetch = setup({ proxies: { ...emptyConfiguration.proxies, subscriptions: [SUB] },
    refresh: { added: [MEMBER], updated: [], unchanged: [], orphans: [{ ...MEMBER, tag: "sub_old", label: "Сирота" }],
      skipped: [{ line: 3, reason: "vmess.unsupported" }], outbounds: [SUB_OUT], groups: [SUB_GROUP] } });
  const user = userEvent.setup();
  await openTab(user, "Прокси-выходы");
  await user.click(await screen.findByRole("tab", { name: "Подписки" }));
  await user.click(screen.getByRole("button", { name: "Обновить сейчас" }));
  expect(await screen.findByText(/Изменения: добавлено 1, обновлено 0, без изменений 0, сирот 1/)).toBeVisible();
  expect(screen.getByText(/Пропущено: 1/)).toBeVisible();
  expect(screen.getByText(/не удаляются автоматически/)).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(false);
});

const GEO: RuleSetStatus = {
  name: "geo",
  format: "geosite",
  url: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/x",
  kind: "rule_set",
  status: "ok",
  stale: false,
  last_attempt: 100,
  last_success: 100,
  sha256: "abc",
  declared: true,
};

it("lists rule-set sources with status/stale and refreshes via the typed RPC", async () => {
  const fetch = setup({ rulesets: [GEO] });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Источники списков");

  expect(await screen.findByText("geo")).toBeVisible();
  expect(screen.getByText("ок")).toBeVisible();
  expect(screen.getByText("не устарел по данным агента")).toBeVisible();
  expect(screen.getAllByText(/01\.01\.1970/)).toHaveLength(2);
  expect(screen.getByText(/Ручное обновление — действие агента, не сохранение черновика/)).toBeVisible();

  await user.click(screen.getByRole("button", { name: "Обновить geo" }));
  await waitFor(() => {
    const call = fetch.mock.calls.find(([path]) => path === "/api/rulesets/update");
    expect(call).toBeTruthy();
    expect(JSON.parse(String((call![1] as RequestInit).body))).toMatchObject({
      name: "geo",
      authorized: true,
    });
  });
});

it("shows a stale rule-set source with an honest status badge", async () => {
  setup({ rulesets: [{ ...GEO, status: "never", stale: true, sha256: null }] });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Источники списков");
  expect(await screen.findByText("не обновлялся")).toBeVisible();
  expect(screen.getByText("устарел")).toBeVisible();
});

it("surfaces a rejected rule-set update", async () => {
  setup({ rulesets: [GEO], updateFails: true });
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Источники списков");
  await user.click(await screen.findByRole("button", { name: "Обновить geo" }));
  expect(await screen.findByText(/Ошибка загрузки/)).toBeVisible();
});

it("keeps the rule-set list read-only for an operator", async () => {
  setup({ role: "operator", rulesets: [GEO] });
  const user = userEvent.setup();
  await openTab(user, "Источники списков");
  expect(await screen.findByText("geo")).toBeVisible();
  expect(screen.queryByRole("button", { name: "Обновить geo" })).not.toBeInTheDocument();
});
