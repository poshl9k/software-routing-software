import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import App from "../App";
import { emptyConfiguration } from "../fixtures";

const versions = [
  { id: 3, status: "draft", configuration: emptyConfiguration },
  { id: 2, status: "draft", configuration: emptyConfiguration },
  { id: 1, status: "confirmed", configuration: emptyConfiguration },
];

function open(path: string) {
  const fetch = vi.fn((url: string) => Promise.resolve(new Response(JSON.stringify(
    url === "/api/versions" ? versions :
    url === "/api/auth/me" ? { id: 1, username: "admin", role: "admin" } :
    url === "/api/apply/status" ? null :
    url === "/api/host/interfaces" ? [] :
    url.startsWith("/api/diff") ? { changes: [], summary: [] } :
    url === "/api/apply" ? { version_id: 2, status: "confirmed", phases: {} } : {},
  ))));
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={[path]}><App /></MemoryRouter>);
  return fetch;
}

it("opens review from the topbar without applying a draft", async () => {
  const fetch = open("/");
  const review = await screen.findByRole("link", { name: "Проверить изменения" });
  await userEvent.click(review);
  expect(await screen.findByRole("heading", { name: "Применение изменений", level: 1 })).toBeVisible();
  expect(fetch.mock.calls.some(([url]) => url === "/api/apply")).toBe(false);
});

it("applies the draft selected for review", async () => {
  const fetch = open("/apply");
  const draft = await screen.findByRole("combobox", { name: "Черновик" });
  const apply = () => screen.getAllByRole("button", { name: "Применить" }).at(-1)!;
  await waitFor(() => expect(apply()).toBeEnabled());
  await userEvent.selectOptions(draft, "2");
  expect(draft).toHaveValue("2");
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => url === "/api/diff/1/2")).toBe(true));
  expect(screen.getByRole("heading", { name: /Изменения \(v1 → v2\)/ })).toBeVisible();
  await userEvent.click(apply());
  await waitFor(() => expect(fetch).toHaveBeenCalledWith("/api/apply", expect.objectContaining({
    body: expect.stringContaining('"version_id":2'),
  })));
});

it("mobile drawer preserves grouped navigation, configuration, keyboard escape and focus return", async () => {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: query === "(prefers-reduced-motion: reduce)",
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  open("/");
  const menu = await screen.findByRole("button", { name: "Разделы" });
  const status = screen.getByRole("link", { name: /Конфигурация: .*Открыть применение/ });
  expect(status).toHaveAttribute("href", "/apply");
  await userEvent.click(menu);
  const drawer = screen.getByRole("dialog");
  expect(within(drawer).getByRole("navigation", { name: "Разделы панели" })).toBeVisible();
  expect(within(drawer).getByRole("region", { name: "Интернет" })).toBeVisible();
  expect(within(drawer).getByRole("complementary", { name: "Состояние конфигурации" })).toBeVisible();
  expect(within(drawer).getByRole("link", { name: "Проверить изменения" })).toHaveAttribute("href", "/apply");
  await userEvent.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(menu).toHaveFocus();
  await userEvent.click(menu);
  await userEvent.click(within(screen.getByRole("dialog")).getByRole("link", { name: "Туннели" }));
  expect(await screen.findByRole("heading", { name: "Туннели", level: 1 })).toBeVisible();
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});

it("labels the events page and explains that its journal is unavailable", async () => {
  open("/events");
  expect(await screen.findByRole("heading", { name: "Журнал событий", level: 1 })).toBeVisible();
  expect(screen.getByText("Журнал пока недоступен")).toBeVisible();
});
