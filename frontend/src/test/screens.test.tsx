import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { emptyConfiguration } from "../fixtures";
import { observation, useCountdown } from "../state";
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
      path === "/api/apply" ? { version_id: 2, status: "confirmed", phases: {} } : []
    ))));
    open("/apply");
    expect(await screen.findByText(/Первое применение выполняется без автоотката/)).toBeVisible();
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
    expect(button).toBeEnabled();
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
