import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "../pages/Routing";
import { RouterProvider } from "../state";
import { emptyConfiguration } from "../fixtures";
import type { TProxyRule } from "../types";

function setup(fail = false, rules: TProxyRule[] = []) {
  const configuration = {
    ...emptyConfiguration,
    interfaces: [{ name: "lan0", zone: "lan" as const, kind: "physical" as const }],
    tproxy: { ...emptyConfiguration.tproxy, rules },
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
      name: "blocked_site", domain_suffix: ["example.org"], ip_cidr: [], action: "block", order: 0,
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
    { name: "later", domain_suffix: ["later.test"], ip_cidr: [], action: "block", order: 20 },
    { name: "first", domain_suffix: ["first.test"], ip_cidr: [], action: "direct", order: 10 },
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
