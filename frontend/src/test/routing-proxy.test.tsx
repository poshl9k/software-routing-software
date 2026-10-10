import { render, screen, waitFor } from "@testing-library/react";
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

  await user.click(screen.getByRole("button", { name: "+ Добавить подписку" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.type(screen.getByLabelText("URL подписки"), "https://sub.example.com/list");
  await user.selectOptions(screen.getByLabelText("Формат"), "clash");

  await user.click(screen.getByRole("button", { name: "+ Добавить группу" }));
  await user.type(screen.getByLabelText("Тег группы"), "grp");
  await user.click(screen.getByRole("checkbox", { name: "ss1" }));

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
    { name: "sub1", url: "https://sub.example.com/list", format: "clash", interval_hours: 24, enabled: false },
  ]);
  expect(proxies.groups).toEqual([
    { tag: "grp", type: "selector", outbounds: ["ss1"], url: null, interval_minutes: null },
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
  await user.click(screen.getByRole("button", { name: "+ Добавить подписку" }));
  await user.type(screen.getByLabelText("Имя подписки"), "sub1");
  await user.type(screen.getByLabelText("URL подписки"), "http://not-secure.example.com");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("URL подписки"));
  await user.type(screen.getByLabelText("URL подписки"), "https://secure.example.com/list");
  expect(saveButton()).toBeEnabled();
});

it("rejects duplicate outbound tags and a reserved direct tag", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  for (const [tag, server, port] of [
    ["dup", "a.example.com", "8388"],
    ["dup", "b.example.com", "8389"],
  ]) {
    await user.click(screen.getByRole("button", { name: "+ Добавить выход" }));
    await user.type(screen.getAllByLabelText("Тег выхода").at(-1)!, tag);
    await user.type(screen.getAllByLabelText("Сервер").at(-1)!, server);
    await user.type(screen.getAllByLabelText("Порт").at(-1)!, port);
  }
  // Both exits are otherwise valid, so only the duplicate tag keeps save off.
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getAllByLabelText("Тег выхода")[1]);
  await user.type(screen.getAllByLabelText("Тег выхода")[1], "direct");
  expect(saveButton()).toBeDisabled();
});

it("shows empty-state prompts for every proxy collection and the rule-set list", async () => {
  setup();
  const user = userEvent.setup();
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await openTab(user, "Прокси-выходы");
  expect(screen.getByText("Нет прокси-выходов")).toBeVisible();
  expect(screen.getByText("Нет подписок")).toBeVisible();
  expect(screen.getByText("Нет групп")).toBeVisible();
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
