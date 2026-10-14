import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { emptyConfiguration } from "../fixtures";
import type { Configuration } from "../types";

it("selects OS links, creates a VLAN and saves bridge members with draft references", async () => {
  let configuration: Configuration = emptyConfiguration;
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method === "PUT") configuration = JSON.parse(String(init.body));
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
  const physicalEditor = screen.getByRole("dialog", { name: /Интерфейс:/ });
  expect(within(physicalEditor).getByLabelText("Системное имя")).toHaveAttribute("readonly");
  await user.selectOptions(within(physicalEditor).getByLabelText("Выбрать системное имя"), "eth0");
  await user.click(within(physicalEditor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await user.click(screen.getByRole("button", { name: "+ Виртуальный интерфейс" }));
  const createVlan = screen.getByRole("dialog", { name: "Виртуальный интерфейс" });
  await user.selectOptions(within(createVlan).getByLabelText("Тип виртуального интерфейса"), "vlan");
  await user.selectOptions(within(createVlan).getByLabelText("Родительский порт"), "eth1");
  await user.click(within(createVlan).getByRole("button", { name: "Создать" }));
  const vlanEditor = screen.getByRole("dialog", { name: /Интерфейс: vlan1/ });
  const parent = within(vlanEditor).getByLabelText("Родительский интерфейс");
  expect(within(parent).getByRole("option", { name: "eth1" })).toBeVisible();
  expect(within(parent).queryByRole("option", { name: "bond0" })).toBeNull();
  await user.type(
    within(vlanEditor).getByPlaceholderText("напр. «оптика провайдера»"),
    "гостевая сеть",
  );
  await user.click(within(vlanEditor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await user.click(screen.getByRole("button", { name: "+ Виртуальный интерфейс" }));
  const createBridge = screen.getByRole("dialog", { name: "Виртуальный интерфейс" });
  await user.selectOptions(within(createBridge).getByLabelText("Тип виртуального интерфейса"), "bridge");
  await user.click(within(createBridge).getByRole("button", { name: "Создать" }));
  const bridgeEditor = screen.getByRole("dialog", { name: /Интерфейс: br1/ });
  await user.click(within(bridgeEditor).getByRole("button", { name: "+ участник" }));
  const member = within(bridgeEditor).getByLabelText(/Участник new-/);
  await user.selectOptions(member, "bond0");
  await user.click(within(bridgeEditor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.filter(([, init]) => init?.method === "PUT").at(-1)![1].body));
  expect(saved.interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "vlan1", type: "vlan", parent: "eth1", vlan_id: 1,
      description: "гостевая сеть" }),
    expect.objectContaining({ name: "br1", type: "bridge", members: ["bond0"] }),
    expect.objectContaining({ name: "eth1", zone: null }),
    expect.objectContaining({ name: "bond0", zone: null }),
  ]));
});

it("opens the interface editor from a row and keeps role fields inside the dialog", async () => {
  const configuration = { ...emptyConfiguration, interfaces: [{
    name: "eth0", type: "physical" as const, zone: "lan", description: "Дом",
    addressing: "static" as const, addresses: [], parent: null, vlan_id: null, members: [],
  }] };
  vi.stubGlobal("fetch", vi.fn().mockImplementation((path: string) => Promise.resolve(
    new Response(JSON.stringify(path === "/api/versions"
      ? [{ id: 1, status: "draft", configuration }]
      : path === "/api/host/interfaces"
        ? [{ name: "eth0", kind: "physical", parent: null, operstate: "UP" }]
        : { id: 1, status: "draft", configuration })),
  )));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  expect(screen.queryByLabelText("Роль / зона")).toBeNull();
  await user.click(await screen.findByRole("button", { name: "Дом" }));
  const dialog = screen.getByRole("dialog", { name: /Интерфейс: Дом/ });
  expect(within(dialog).getByLabelText("Роль / зона")).toBeVisible();
  expect(within(dialog).getByLabelText("Режим адресации")).toBeInTheDocument();
  expect(within(dialog).getByLabelText("Системное имя")).toHaveAttribute("readonly");
  await user.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.queryByLabelText("Роль / зона")).toBeNull();
});

it("creates, edits and deletes static routes only through the single draft", async () => {
  const user = userEvent.setup();
  let configuration: Configuration = { ...emptyConfiguration, interfaces: [{
    name: "eth0", type: "physical" as const, zone: "wan", description: null,
    addressing: "static" as const, addresses: ["192.0.2.2/24"], parent: null,
    vlan_id: null, members: [],
  }] };
  const saves: Configuration[] = [];
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method === "PUT") {
      configuration = JSON.parse(String(init.body));
      saves.push(configuration);
    }
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(path === "/api/versions" ? [version] :
      path === "/api/host/interfaces" ? [] : path === "/api/host/addresses" ? {} : version)));
  });
  vi.stubGlobal("fetch", fetch);
  render(<MemoryRouter initialEntries={["/network?tab=routes"]}><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Добавить маршрут" }));
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.type(screen.getByLabelText(/Куда \(CIDR\)/), "10.8.0.1/24");
  await user.selectOptions(screen.getByLabelText("Интерфейс"), "eth0");
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();
  await user.clear(screen.getByLabelText(/Куда \(CIDR\)/));
  await user.type(screen.getByLabelText(/Куда \(CIDR\)/), "10.8.0.0/24");
  await user.type(screen.getByLabelText("Через шлюз"), "192.0.2.1");
  await user.clear(screen.getByLabelText("Метрика"));
  await user.type(screen.getByLabelText("Метрика"), "7");
  expect(screen.getByLabelText(/Куда \(CIDR\)/)).toHaveValue("10.8.0.0/24");
  expect(screen.getByLabelText("Интерфейс")).toHaveValue("eth0");
  expect(screen.getByLabelText("Через шлюз")).toHaveValue("192.0.2.1");
  expect(screen.getByLabelText("Метрика")).toHaveValue(7);
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(saves).toHaveLength(1));
  expect(saves[0].static_routes).toEqual([{ destination: "10.8.0.0/24", gateway: "192.0.2.1", interface: "eth0", metric: 7, enabled: true }]);
  await user.click(await screen.findByRole("button", { name: "Редактировать маршрут 10.8.0.0/24" }));
  await user.click(screen.getByRole("switch", { name: "Включён" }));
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(saves).toHaveLength(2));
  expect(saves[1].static_routes?.[0]).toEqual(expect.objectContaining({ enabled: false }));
  await user.click(await screen.findByRole("button", { name: "Удалить маршрут 10.8.0.0/24" }));
  expect(saves).toHaveLength(2);
  await user.click(screen.getByRole("button", { name: "Удалить" }));
  expect(saves).toHaveLength(2);
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(saves).toHaveLength(3));
  expect(saves[2].static_routes).toEqual([]);
});

it("quick VLAN and bridge stage complete references without a partial write", async () => {
  let configuration: Configuration = emptyConfiguration;
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (init?.method === "PUT") configuration = JSON.parse(String(init.body));
    const version = { id: 1, status: "draft", configuration };
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
  await screen.findByRole("dialog", { name: /Интерфейс: vlan42/ });
  await user.click(within(screen.getByRole("dialog", { name: /Интерфейс: vlan42/ })).getByRole("button", { name: "Сохранить" }));
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
  const bridgeEditor = await screen.findByRole("dialog", { name: /Интерфейс: br42/ });
  expect(fetch.mock.calls.filter(([, init]) => init?.method === "PUT")).toHaveLength(1);
  await user.click(within(bridgeEditor).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.filter(([, init]) => init?.method === "PUT").at(-1)![1].body));
  expect(saved.interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "vlan42", type: "vlan", parent: "eth0", vlan_id: 42 }),
    expect.objectContaining({ name: "br42", type: "bridge", members: ["eth0", "eth1"] }),
    expect.objectContaining({ name: "eth0", zone: null }),
    expect.objectContaining({ name: "eth1", zone: null }),
  ]));
});
