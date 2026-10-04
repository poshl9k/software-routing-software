import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { emptyConfiguration } from "../fixtures";
import { observation, RouterProvider, useCountdown, useRouterState } from "../state";
const versions = [
  { id: 2, status: "draft", configuration: emptyConfiguration },
  { id: 1, status: "confirmed", configuration: emptyConfiguration },
];
function mockApi() {
  const fetch = vi
    .fn()
    .mockImplementation((path: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            path === "/api/versions"
              ? versions
              : path === "/api/host/interfaces" || path.startsWith("/api/diff")
                ? []
                : {},
          ),
        ),
      ),
    );
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
function open(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}
describe("screens", () => {
  it.each([
    ["/", "Обзор сети"],
    ["/network", "Сеть"],
    ["/firewall", "Firewall"],
    ["/ssh", "SSH"],
    ["/dhcp", "DHCP (Kea)"],
    ["/dns", "DNS (Unbound)"],
    ["/tunnels", "Туннели"],
    ["/proxy", "Прокси (Caddy)"],
    ["/routing", "Маршрутизация · sing-box TProxy"],
    ["/apply", "Применение изменений"],
    ["/onboarding", "Учётная запись администратора"],
  ])("renders %s", async (path, title) => {
    mockApi();
    open(path);
    expect(
      await screen.findByRole("heading", { name: title, level: 1 }),
    ).toBeVisible();
    await waitFor(() =>
      expect(screen.queryByRole("progressbar")).not.toBeInTheDocument(),
    );
  });
  it("keeps routing draft read-only for an operator", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 2, username: "operator", role: "operator" } : {},
    ))));
    open("/routing");
    expect(await screen.findByText("operator")).toBeVisible();
    expect(screen.getByRole("button", { name: "Редактировать" })).toBeDisabled();
    expect(fetch.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0);
  });
  it("does not offer admin-only backup or diagnostics to an operator", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 2, username: "operator", role: "operator" } : {},
    ))));
    open("/maintenance");
    expect(await screen.findByText("operator")).toBeVisible();
    expect(screen.getByRole("button", { name: "Экспорт" })).toBeDisabled();
    const fileLabel = screen.getByRole("button", { name: "Выбрать файл импорта" });
    expect(fileLabel).toHaveAttribute("aria-disabled", "true");
    expect(fileLabel.querySelector("input")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Ping" })).toBeDisabled();
    expect(screen.getAllByRole("button", { name: "Обновить" }).at(-1)).toBeDisabled();
    expect(fetch.mock.calls.some(([path]) => path === "/api/diag/rules-counters")).toBe(false);
  });
  it("does not offer draft deletion or apply commands to an operator", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 2, username: "operator", role: "operator" } : {},
    ))));
    open("/apply");
    expect(await screen.findByText("operator")).toBeVisible();
    for (const name of ["Применить", "Подтвердить изменения", "Откатить сейчас", "Сбросить черновик"])
      expect(screen.getByRole("button", { name })).toBeDisabled();
    expect(fetch.mock.calls.some(([path]) => path === "/api/apply/status")).toBe(false);
  });
  it("reports failed draft deletion and retains the draft", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const fetch = mockApi();
    fetch.mockImplementation((path: string, init?: RequestInit) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply/status" ? null :
      path === "/api/draft" && init?.method === "DELETE" ? {
        code: "draft.unavailable", message: "Черновик не удалён", details: [],
      } : [],
    ), { status: path === "/api/draft" && init?.method === "DELETE" ? 503 : 200 })));
    open("/apply");
    await screen.findByText("admin");
    await userEvent.click(screen.getByRole("button", { name: "Сбросить черновик" }));
    expect((await screen.findAllByText(/Черновик не удалён/))[0]).toBeVisible();
    expect(screen.getByRole("button", { name: "Сбросить черновик" })).toBeEnabled();
  });
  it("drops version and apply state when the admin signs out", async () => {
    mockApi();
    function Probe() {
      const { versions: rows, applyState, uncertain, setApplyState, setUncertain, signOut } = useRouterState();
      return <>
        <span data-testid="session-state">{`${rows.length}:${applyState?.result.status ?? "none"}:${uncertain}`}</span>
        <button onClick={() => { setApplyState(observation({version_id: 2, status: "pending", phases: {}})); setUncertain(true); }}>Seed</button>
        <button onClick={() => void signOut()}>Sign out</button>
      </>;
    }
    render(<RouterProvider><Probe /></RouterProvider>);
    await waitFor(() => expect(screen.getByTestId("session-state")).toHaveTextContent("2:none:false"));
    await userEvent.click(screen.getByRole("button", { name: "Seed" }));
    expect(screen.getByTestId("session-state")).toHaveTextContent("2:pending:true");
    await userEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByTestId("session-state")).toHaveTextContent("0:none:false"));
  });
  it("reports failed logout without claiming the session ended", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/auth/logout" ? {code: "auth.unavailable", message: "Выход не выполнен", details: []} :
      path === "/api/apply/status" ? null : {},
    ), {status: path === "/api/auth/logout" ? 503 : 200})));
    open("/");
    await screen.findByText("admin");
    await userEvent.click(screen.getByRole("button", {name: "Выйти"}));
    expect((await screen.findAllByText(/Выход не выполнен/))[0]).toBeVisible();
    expect(screen.getByText("admin")).toBeVisible();
    expect(screen.getByRole("heading", {name: "Обзор сети"})).toBeVisible();
  });
  it("clears cached apply state after a session-expired versions response", async () => {
    let reads = 0;
    vi.stubGlobal("fetch", vi.fn((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" && ++reads > 1
        ? { code: "auth.required", message: "auth.required", details: [] }
        : versions,
    ), {status: path === "/api/versions" && reads > 1 ? 401 : 200}))));
    function Probe() {
      const { versions: rows, applyState, setApplyState, refresh } = useRouterState();
      return <>
        <span data-testid="session-state">{`${rows.length}:${applyState?.result.status ?? "none"}`}</span>
        <button onClick={() => setApplyState(observation({version_id: 2, status: "pending", phases: {}}))}>Seed</button>
        <button onClick={() => void refresh()}>Refresh</button>
      </>;
    }
    render(<RouterProvider><Probe /></RouterProvider>);
    await waitFor(() => expect(screen.getByTestId("session-state")).toHaveTextContent("2:none"));
    await userEvent.click(screen.getByRole("button", { name: "Seed" }));
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(screen.getByTestId("session-state")).toHaveTextContent("0:none"));
  });
  it("previews saved TProxy draft for admin without applying it", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/draft/tproxy/preview" ? {
        version_id: 2,
        singbox: { inbounds: [{ type: "tproxy", tag: "tproxy-udp" }], route: { final: "direct" } },
      } : {},
    ))));
    open("/routing");
    await screen.findByText("admin");
    await userEvent.click(screen.getByRole("button", { name: "Предпросмотр сохранённого черновика" }));
    expect(await screen.findByText(/"tproxy-udp"/)).toBeVisible();
    expect(fetch.mock.calls.some(([path]) => path === "/api/draft/tproxy/preview")).toBe(true);
    expect(fetch.mock.calls.some(([path]) => path === "/api/apply")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Редактировать" }));
    expect(screen.queryByLabelText("Конфигурация sing-box")).not.toBeInTheDocument();
  });
  it("shows preview failure without claiming TProxy is active", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      { code: "agent.unavailable", message: "Предпросмотр недоступен", details: [] },
    ), { status: path === "/api/draft/tproxy/preview" ? 503 : 200 })));
    open("/routing");
    await screen.findByText("admin");
    await userEvent.click(screen.getByRole("button", { name: "Предпросмотр сохранённого черновика" }));
    expect(await screen.findByText(/Предпросмотр недоступен/)).toBeVisible();
    expect(screen.queryByLabelText("Конфигурация sing-box")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Включить TProxy" })).toBeDisabled();
  });
  it("does not mistake a draft for a pending agent marker", async () => {
    mockApi();
    open("/");
    expect(await screen.findByText("Черновик v2")).toBeVisible();
    expect(
      screen.getByText(/неподтверждённые изменения: неизвестно/),
    ).toBeVisible();
  });
  it("restores pending apply from the agent marker after opening the page", async () => {
    const fetch = mockApi();
    const deadline = Math.floor(Date.now() / 1000) + 120;
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply/status" ? {
        version_id: 2, status: "pending", applied_at: deadline - 60,
        deadline, phases: { nftables: "applied" },
      } : path.startsWith("/api/diff") ? [] : {},
    ))));
    open("/apply");
    expect(await screen.findByText(/Неподтверждённые изменения · v2/)).toBeVisible();
    expect(screen.getByRole("timer")).toHaveTextContent(/0[12]:[0-5][0-9]/);
    expect(screen.getByRole("button", { name: "Подтвердить изменения" })).toBeEnabled();
    expect(fetch.mock.calls.some(([path]) => path === "/api/apply/status")).toBe(true);
  });
  it("shows a persisted agent failure code after page reload", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply/status" ? {
        version_id: 2, status: "failed", applied_at: 0, deadline: null,
        phases: { nftables: "failed" },
        error: { code: "agent.reload_failed", message: "agent.reload_failed", details: [] },
      } : [],
    ))));
    open("/apply");
    expect(await screen.findByText(/Ошибка применения · v2/)).toBeVisible();
    expect(screen.getByText(/agent\.reload_failed/)).toBeVisible();
  });
  it("restores pending marker in the topbar on the overview", async () => {
    const fetch = mockApi();
    const deadline = Math.floor(Date.now() / 1000) + 120;
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply/status" ? {
        version_id: 2, status: "pending", applied_at: deadline - 60,
        deadline, phases: {},
      } : {},
    ))));
    open("/");
    expect(await screen.findByRole("button", { name: /Подтвердить ·/ })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Применить" })).not.toBeInTheDocument();
    expect(fetch.mock.calls.some(([path]) => path === "/api/apply/status")).toBe(true);
  });
  it("keeps the topbar apply disabled when the agent status read fails", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      { code: "agent.unavailable", message: "Агент недоступен", details: [] },
    ), { status: path === "/api/apply/status" ? 503 : 200 })));
    open("/");
    await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/apply/status")).toBe(true));
    expect(await screen.findByRole("link", { name: "Выполняется…" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Применить" })).not.toBeInTheDocument();
  });
  it("does not infer a safe state when the agent marker is unavailable", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path.startsWith("/api/diff") ? [] :
      { code: "agent.unavailable", message: "Агент недоступен", details: [] },
    ), { status: path === "/api/apply/status" ? 503 : 200 })));
    open("/apply");
    expect(await screen.findByText(/Результат команды неизвестен/)).toBeVisible();
    expect(screen.getAllByText(/Агент недоступен/)[0]).toBeVisible();
    expect(screen.getByRole("button", { name: "Подтвердить изменения" })).toBeDisabled();
  });
  it("rechecks the agent marker after a temporary status failure", async () => {
    const fetch = mockApi();
    let attempts = 0;
    fetch.mockImplementation((path: string) => {
      if (path === "/api/apply/status") {
        attempts += 1;
        return Promise.resolve(new Response(JSON.stringify(attempts === 1 ? {
          code: "agent.unavailable", message: "Агент недоступен", details: [],
        } : null), { status: attempts === 1 ? 503 : 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify(
        path === "/api/versions" ? versions :
        path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } : [],
      )));
    });
    open("/apply");
    expect(await screen.findByText(/Результат команды неизвестен/)).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Применить" }).at(-1)).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Обновить состояние" }));
    await waitFor(() => expect(screen.getAllByRole("button", { name: "Применить" }).at(-1)).toBeEnabled());
    expect(screen.queryByText(/Результат команды неизвестен/)).not.toBeInTheDocument();
    expect(attempts).toBe(2);
  });
  it("blocks apply until the agent confirms no pending marker", async () => {
    const fetch = mockApi();
    let resolveStatus!: (response: Response) => void;
    const pendingStatus = new Promise<Response>((resolve) => { resolveStatus = resolve; });
    fetch.mockImplementation((path: string) => path === "/api/apply/status" ? pendingStatus :
      Promise.resolve(new Response(JSON.stringify(
        path === "/api/versions" ? versions :
        path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
        path.startsWith("/api/diff") ? [] : {},
      ))));
    open("/apply");
    await screen.findByText("admin");
    await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/apply/status")).toBe(true));
    expect(screen.getAllByRole("button", { name: "Применить" }).at(-1)).toBeDisabled();
    await act(async () => { resolveStatus(new Response("null")); });
    expect(screen.getAllByRole("button", { name: "Применить" }).at(-1)).toBeEnabled();
  });
  it("disables topbar confirmation when marker verification fails", async () => {
    const fetch = mockApi();
    let statusReads = 0;
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? versions :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply" ? { version_id: 2, status: "pending", phases: {} } :
      path === "/api/apply/status" && ++statusReads > 1 ? {
        code: "agent.unavailable", message: "Агент недоступен", details: [],
      } : path === "/api/apply/status" ? null : [],
    ), { status: path === "/api/apply/status" && statusReads > 1 ? 503 : 200 })));
    const user = userEvent.setup();
    open("/");
    const button = await screen.findByRole("button", { name: "Применить" });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    await user.click(screen.getByRole("link", { name: "Применение" }));
    expect(await screen.findByText(/Результат команды неизвестен/)).toBeVisible();
    expect(screen.getByRole("button", { name: /Подтвердить ·/ })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Подтвердить изменения" })).toBeDisabled();
    expect(fetch.mock.calls.some(([path]) => path === "/api/confirm")).toBe(false);
  });
  it("unconfigured server shows a setup prompt with no fabricated data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "auth.required",
            message: "auth.required",
            details: [],
          }),
          { status: 401 },
        ),
      ),
    );
    open("/network");
    expect(
      await screen.findByText(/Нет сохранённой конфигурации — выполните первичную настройку/),
    ).toBeVisible();
    expect(screen.queryByText("без зоны (fail-closed)")).not.toBeInTheDocument();
    expect(screen.queryByText("eth0")).not.toBeInTheDocument();
    expect(screen.queryByText(/демонстрационные данные из макетов/)).not.toBeInTheDocument();
  });
  it("applies, counts down and confirms the actual returned version", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            path === "/api/versions"
              ? versions
              : path === "/api/apply/status"
                ? fetch.mock.calls.some(([called]) => called === "/api/apply") &&
                  !fetch.mock.calls.some(([called]) => called === "/api/confirm") ? {
                    version_id: 2, status: "pending", applied_at: Date.now() / 1000,
                    deadline: Date.now() / 1000 + 180, phases: { nftables: "applied" },
                  } : null
              : path === "/api/auth/me"
                ? { id: 1, username: "admin", role: "admin" }
              : path === "/api/host/interfaces" || path.startsWith("/api/diff")
                ? []
                : path === "/api/apply"
                  ? {
                      version_id: 2,
                      status: "pending",
                      phases: { nftables: "applied" },
                    }
                  : { version_id: 2, status: "confirmed" },
          ),
        ),
      ),
    );
    const user = userEvent.setup();
    open("/apply");
    const applyButtons = () =>
      screen
        .getAllByRole("button", { name: "Применить" })
        // The Apply screen's own button comes after the topbar one in the DOM.
        .slice(-1);
    await waitFor(() => expect(applyButtons()[0]).toBeEnabled());
    const safe = await screen.findByRole("switch", {
      name: "Безопасная настройка",
    });
    await waitFor(() => expect(safe).toBeEnabled());
    await user.click(safe);
    await user.click(applyButtons()[0]);
    expect(await screen.findByRole("timer")).toHaveTextContent(
      /0[23]:[0-5][0-9]/,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Подтвердить изменения" }),
      ).toBeEnabled(),
    );
    expect(applyButtons()[0]).toBeDisabled();
    await user.click(
      screen.getByRole("button", { name: "Подтвердить изменения" }),
    );
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        "/api/confirm",
        expect.objectContaining({ body: '{"version_id":2}' }),
      ),
    );
    expect(await screen.findByText(/Подтверждено · v2/)).toBeVisible();
  });
  it("first apply keeps the saved timer preference but sends safe_mode false", async () => {
    localStorage.setItem("vs-router.preferences", JSON.stringify({ safe: true, timeout: 180 }));
    const fetch = mockApi();
    fetch.mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? [versions[0]] :
      path === "/api/apply/status" ? null :
      path === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
      path === "/api/apply" ? { version_id: 2, status: "confirmed", phases: {} } : []
    ))));
    open("/apply");
    expect(await screen.findByText(/Первое применение выполняется без автоотката/)).toBeVisible();
    await waitFor(() => expect(screen.getAllByRole("button", { name: "Применить" }).at(-1)).toBeEnabled());
    await userEvent.click(screen.getAllByRole("button", { name: "Применить" }).at(-1)!);
    await waitFor(() => {
      const call = fetch.mock.calls.find(([path]) => path === "/api/apply");
      expect(call).toBeDefined();
      expect(JSON.parse(call![1].body).safe_mode).toBe(false);
    });
    expect(JSON.parse(localStorage.getItem("vs-router.preferences")!).safe).toBe(true);
  });
  it("onboarding submits credentials, then login, then a network draft", async () => {
    const fetch = mockApi();
    const user = userEvent.setup();
    open("/onboarding");
    await user.type(
      screen.getByLabelText("Пароль", { exact: false }),
      "strong-password",
    );
    await user.click(screen.getByRole("button", { name: "Продолжить →" }));
    await screen.findByRole("heading", { name: "Базовая сеть" });
    await user.click(screen.getByRole("button", { name: "Продолжить →" }));
    await user.click(
      screen.getByRole("button", { name: "Сохранить" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Первичная настройка готова",
      }),
    ).toBeVisible();
    const mutations = fetch.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(mutations.map(([path]) => path)).toEqual([
      "/api/setup",
      "/api/auth/login",
      "/api/draft",
    ]);
    expect(JSON.parse(mutations[0][1].body)).toEqual({
      username: "admin",
      password: "strong-password",
    });
    expect(JSON.parse(mutations[2][1].body).interfaces[0]).toMatchObject({
      name: "eth1",
      zone: "lan",
      addresses: ["192.168.10.1/24"],
    });
  });
  it("countdown clamps at zero and never confirms automatically", () => {
    vi.useFakeTimers();
    try {
      const deadline = Date.now() + 1500;
      function Counter() {
        return <span>{useCountdown(deadline)}</span>;
      }
      render(<Counter />);
      expect(screen.getByText("2")).toBeVisible();
      act(() => vi.advanceTimersByTime(2000));
      expect(screen.getByText("0")).toBeVisible();
    } finally {
      vi.useRealTimers();
    }
  });
  it("prefers a marker deadline over the local estimate", () => {
    expect(
      observation(
        {
          version_id: 2,
          status: "pending",
          deadline: 100,
          applied_at: 0,
        } as Parameters<typeof observation>[0],
        { version_id: 2, safe_mode: true, confirmation_timeout: 180 },
        0,
      ),
    ).toMatchObject({ deadline: 100000, approximate: false });
  });
  it("applies the draft from the topbar button without leaving the page", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            path === "/api/versions"
              ? versions
              : path === "/api/auth/me"
                ? { id: 1, username: "admin", role: "admin" }
              : path === "/api/apply/status"
                ? fetch.mock.calls.some(([called]) => called === "/api/apply") ? {
                    version_id: 2, status: "pending", applied_at: Date.now() / 1000,
                    deadline: Date.now() / 1000 + 180, phases: {},
                  } : null
              : path === "/api/host/interfaces" || path.startsWith("/api/diff")
                ? []
                : path === "/api/apply"
                  ? {
                      version_id: 2,
                      status: "pending",
                      phases: { nftables: "applied" },
                    }
                  : { version_id: 2, status: "confirmed" },
          ),
        ),
      ),
    );
    const user = userEvent.setup();
    open("/");
    const button = await screen.findByRole("button", {
      name: "Применить",
    });
    await waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(
      await screen.findByRole("button", { name: /Подтвердить/ }),
    ).toBeVisible();
    expect(
      screen.getAllByRole("button", { name: /Подтвердить/ }).length,
    ).toBeGreaterThan(0);
    expect(fetch).toHaveBeenCalledWith(
      "/api/apply",
      expect.objectContaining({ method: "POST" }),
    );
  });
});