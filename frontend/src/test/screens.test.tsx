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
              : path.startsWith("/api/diff")
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
    ["/dhcp", "DHCP (Kea)"],
    ["/dns", "DNS (Unbound)"],
    ["/tunnels", "Туннели"],
    ["/proxy", "Прокси (Caddy)"],
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
  it("does not mistake a draft for a pending agent marker", async () => {
    mockApi();
    open("/");
    expect(await screen.findByText("Черновик v2")).toBeVisible();
    expect(
      screen.getByText(/неподтверждённые изменения: неизвестно/),
    ).toBeVisible();
  });
  it("shows API failures and an explicit demo fallback", async () => {
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
      await screen.findByText(/демонстрационные данные из макетов/),
    ).toBeVisible();
    expect(screen.getByText("без зоны (fail-closed)")).toBeVisible();
  });
  it("applies, counts down and confirms the actual returned version", async () => {
    const fetch = mockApi();
    fetch.mockImplementation((path: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            path === "/api/versions"
              ? versions
              : path.startsWith("/api/diff")
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
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Применить черновик" }),
      ).toBeEnabled(),
    );
    const safe = await screen.findByRole("switch", {
      name: "Безопасная настройка",
    });
    await waitFor(() => expect(safe).toBeEnabled());
    await user.click(safe);
    await user.click(
      screen.getByRole("button", { name: "Применить черновик" }),
    );
    expect(await screen.findByRole("timer")).toHaveTextContent(
      /0[23]:[0-5][0-9]/,
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Подтвердить изменения" }),
      ).toBeEnabled(),
    );
    expect(
      screen.getByRole("button", { name: "Применить черновик" }),
    ).toBeDisabled();
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
      screen.getByRole("button", { name: "Сохранить черновик" }),
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
});
