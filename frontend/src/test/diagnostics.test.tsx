import { useEffect } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";
import App, { navigation } from "../App";
import Diagnostics from "../pages/Diagnostics";
import { RouterProvider, useRouterState } from "../state";
import type { RuntimeEngine } from "../types";

const engine: RuntimeEngine = { installed: true, version: "1.2.3", running: true, pid: 42, clash_api: true, ip_forward: true, nft_tproxy_tables: true };
function AuthenticatedDiagnostics() {
  const { loadUser } = useRouterState();
  useEffect(() => { void loadUser(); }, [loadUser]);
  return <Diagnostics />;
}
function mount() {
  vi.spyOn(api, "versions").mockResolvedValue([]);
  vi.spyOn(api, "me").mockResolvedValue({ id: 1, username: "admin", role: "admin" });
  render(<MemoryRouter><RouterProvider><AuthenticatedDiagnostics /></RouterProvider></MemoryRouter>);
  return userEvent.setup();
}
afterEach(() => vi.restoreAllMocks());

it("shows unknown engine state and disables controls when the read fails", async () => {
  vi.spyOn(api, "runtimeEngine").mockRejectedValue(new Error("503"));
  mount();
  expect(await screen.findByText("Состояние неизвестно")).toBeVisible();
  expect(screen.getByText(/Не удалось получить данные/)).toBeVisible();
  expect(screen.queryByText("Работает")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Запустить" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Перезапустить" })).toBeDisabled();
});

it("requires confirmation before restarting the engine", async () => {
  vi.spyOn(api, "runtimeEngine").mockResolvedValue(engine);
  const control = vi.spyOn(api, "runtimeEngineControl").mockResolvedValue(engine);
  const user = mount();
  await screen.findByText("Работает");
  await user.click(screen.getByRole("button", { name: "Перезапустить" }));
  expect(control).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Отмена" }));
  expect(control).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Перезапустить" }));
  await user.click(within(screen.getByRole("dialog", { name: "Перезапустить движок?" })).getByRole("button", { name: "Перезапустить" }));
  await waitFor(() => expect(control.mock.calls.map(([action]) => action)).toEqual(["restart"]));
});

it("filters connections and closes only the confirmed row", async () => {
  vi.spyOn(api, "runtimeEngine").mockResolvedValue(engine);
  vi.spyOn(api, "runtimeConnections").mockResolvedValue({ upload: 0, download: 0, connections: [
    { id: "tcp-id", metadata: { network: "tcp", host: "alpha.example" } },
    { id: "udp-id", metadata: { network: "udp", host: "beta.example" } },
  ] });
  const close = vi.spyOn(api, "runtimeCloseConnection").mockResolvedValue({});
  const user = mount();
  await user.click(screen.getByRole("tab", { name: "Соединения" }));
  expect(await screen.findByText(/alpha\.example/)).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: "Поиск соединений" }), "beta");
  expect(screen.queryByText(/alpha\.example/)).not.toBeInTheDocument();
  expect(screen.getByText(/beta\.example/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Закрыть" }));
  expect(close).not.toHaveBeenCalled();
  await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Отмена" }));
  expect(close).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  await user.click(screen.getByRole("button", { name: "Закрыть" }));
  await user.click(within(screen.getByRole("dialog", { name: "Закрыть соединение?" })).getByRole("button", { name: "Закрыть" }));
  await waitFor(() => expect(close.mock.calls.map(([id]) => id)).toEqual(["udp-id"]));
});

it("masks logs, pauses polling, and clears visible entries", async () => {
  vi.spyOn(api, "runtimeEngine").mockResolvedValue(engine);
  const logs = vi.spyOn(api, "runtimeLogs").mockResolvedValue([
    { type: "info", source: "sing-box", payload: "token=abc123 via https://example.org/path from 192.0.2.1" },
  ]);
  const user = mount();
  await user.click(screen.getByRole("tab", { name: "Журнал" }));
  const line = await screen.findByText(/\[скрыто\]/);
  expect(line.textContent).not.toMatch(/abc123|example\.org|192\.0\.2\.1/);
  expect(logs).toHaveBeenCalledWith("info", 100);
  await user.click(screen.getByRole("button", { name: "Пауза" }));
  expect(screen.getByRole("button", { name: "Продолжить" })).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Очистить" }));
  expect(screen.getByText("Нет записей")).toBeVisible();
  expect(screen.getByRole("button", { name: "Копировать" })).toBeDisabled();
});

it("registers diagnostics in management navigation and serves the route", async () => {
  expect(navigation.find((group) => group.group === "Управление")?.items).toEqual(expect.arrayContaining([
    expect.objectContaining({ to: "/diagnostics", label: "Диагностика" }),
  ]));
  vi.spyOn(api, "runtimeEngine").mockResolvedValue(engine);
  vi.spyOn(api, "versions").mockResolvedValue([]);
  vi.spyOn(api, "me").mockResolvedValue({ id: 1, username: "admin", role: "admin" });
  render(<MemoryRouter initialEntries={["/diagnostics"]}><App /></MemoryRouter>);
  expect(await screen.findByRole("heading", { name: "Диагностика", level: 1 })).toBeVisible();
  expect(screen.getByRole("link", { name: "Диагностика" })).toHaveAttribute("href", "/diagnostics");
});
