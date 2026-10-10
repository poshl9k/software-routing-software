import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { emptyConfiguration } from "../fixtures";

it("selects OS links, creates a VLAN and saves bridge members with draft references", async () => {
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const configuration = init?.body ? JSON.parse(String(init.body)) : emptyConfiguration;
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? [version] : path === "/api/host/interfaces" ? [
        { name: "eth0", kind: "physical", parent: null, operstate: "UP" },
        { name: "eth1", kind: "physical", parent: null, operstate: "DOWN" },
        { name: "bond0", kind: "bond", parent: null, operstate: "UP" },
      ] : version,
    )));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Добавить интерфейс" }));
  await user.selectOptions(screen.getByLabelText("Системное имя"), "eth0");
  await user.click(screen.getByRole("button", { name: "+ VLAN на eth0" }));
  await user.click(screen.getByRole("tab", { name: "Подключение" }));
  const parent = screen.getByLabelText("Родительский интерфейс");
  expect(within(parent).getByRole("option", { name: "eth1" })).toBeVisible();
  expect(within(parent).queryByRole("option", { name: "bond0" })).toBeNull();
  await user.selectOptions(parent, "eth1");
  await user.click(screen.getByRole("tab", { name: "Общие" }));
  await user.type(
    screen.getByPlaceholderText("напр. «оптика провайдера»"),
    "гостевая сеть",
  );
  await user.click(screen.getByRole("button", { name: "+ Мост" }));
  await user.click(screen.getByRole("tab", { name: "Подключение" }));
  await user.click(screen.getByRole("button", { name: "+ участник" }));
  const member = screen.getByLabelText(/Участник new-/);
  await user.selectOptions(member, "bond0");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "vlan1", type: "vlan", parent: "eth1", vlan_id: 1,
      description: "гостевая сеть" }),
    expect.objectContaining({ name: "br1", type: "bridge", members: ["bond0"] }),
    expect.objectContaining({ name: "eth1", zone: null }),
    expect.objectContaining({ name: "bond0", zone: null }),
  ]));
});

it("quick VLAN and bridge stage complete references without a partial write", async () => {
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const version = { id: 1, status: "draft", configuration: init?.body ? JSON.parse(String(init.body)) : emptyConfiguration };
    return Promise.resolve(new Response(JSON.stringify(path === "/api/versions" ? [version] : path === "/api/host/interfaces" ? [
      { name: "eth0", kind: "physical", parent: null, mac: "00:00:00:00:00:01", operstate: "UP" },
      { name: "eth1", kind: "physical", parent: null, mac: "00:00:00:00:00:02", operstate: "DOWN" },
    ] : version)));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Быстро подключить" }));
  await user.selectOptions(screen.getByLabelText("Сценарий подключения"), "vlan");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Родительский порт"), "eth0");
  await user.type(screen.getByLabelText("Системное имя"), "vlan42");
  await user.type(screen.getByLabelText("VLAN ID"), "42");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByLabelText("Родитель и VLAN ID")).toHaveValue("eth0 · 42");
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Быстро подключить" }));
  await user.selectOptions(screen.getByLabelText("Сценарий подключения"), "bridge");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("checkbox", { name: /eth0 · MAC/ }));
  await user.click(screen.getByRole("checkbox", { name: /eth1 · MAC/ }));
  await user.type(within(screen.getByRole("dialog")).getByLabelText("Системное имя"), "br42");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "vlan42", type: "vlan", parent: "eth0", vlan_id: 42 }),
    expect.objectContaining({ name: "br42", type: "bridge", members: ["eth0", "eth1"] }),
    expect.objectContaining({ name: "eth0", zone: null }),
    expect.objectContaining({ name: "eth1", zone: null }),
  ]));
});
