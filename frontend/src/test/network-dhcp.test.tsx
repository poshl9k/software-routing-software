import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { emptyConfiguration } from "../fixtures";

it("clears a previously entered static address when the interface is switched to DHCP", async () => {
  const draft = {
    ...emptyConfiguration,
    interfaces: [
      {
        name: "eth0",
        type: "physical",
        zone: "lan",
        description: null,
        addressing: "static",
        addresses: ["192.168.10.5/24"],
        parent: null,
        vlan_id: null,
        members: [],
      },
    ],
  };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const configuration = init?.body ? JSON.parse(String(init.body)) : draft;
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [version]
        : path === "/api/host/interfaces"
          ? [{ name: "eth0", kind: "physical", parent: null, operstate: "UP" }]
          : version,
    )));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Без названия" }));
  await user.click(screen.getByRole("tab", { name: "IP" }));
  const mode = screen.getByLabelText("Режим адресации");
  await user.selectOptions(mode, "DHCP");

  // The address field is emptied and locked while in DHCP mode.
  const address = screen.getByPlaceholderText("адрес по DHCP");
  expect(address).toBeDisabled();
  expect(address).toHaveValue("");

  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() =>
    expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true),
  );
  const saved = JSON.parse(
    String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body),
  );
  expect(saved.interfaces).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ name: "eth0", addressing: "dhcp", addresses: [] }),
    ]),
  );
});

it("quick DHCP adds to local draft only and saves through the editor", async () => {
  const fetch = vi.fn().mockImplementation((path: string) => {
    const version = { id: 1, status: "draft", configuration: emptyConfiguration };
    return Promise.resolve(new Response(JSON.stringify(path === "/api/versions" ? [version] : path === "/api/host/interfaces" ? [
      { name: "eth0", kind: "physical", parent: null, mac: "aa:bb:cc:dd:ee:ff", operstate: "UP" },
    ] : version)));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Быстро подключить" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  const port = screen.getByLabelText("Физический порт");
  expect(screen.getByRole("option", { name: /eth0 · MAC aa:bb:cc:dd:ee:ff · подключён/ })).toBeVisible();
  await user.selectOptions(port, "eth0");
  await user.type(screen.getByLabelText("Дружественное имя"), "Провайдер");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByLabelText("Адресация")).toHaveValue("DHCP");
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Добавить в черновик" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.getByRole("button", { name: "Провайдер" })).toBeVisible();
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces).toEqual([expect.objectContaining({ name: "eth0", type: "physical", zone: "wan", description: "Провайдер", addressing: "dhcp", addresses: [] })]);
});

it("quick static rejects missing CIDR and cancellation leaves no draft", async () => {
  const fetch = vi.fn().mockImplementation((path: string) => {
    const version = { id: 1, status: "draft", configuration: emptyConfiguration };
    return Promise.resolve(new Response(JSON.stringify(path === "/api/versions" ? [version] : path === "/api/host/interfaces" ? [
      { name: "eth1", kind: "physical", parent: null, mac: null, operstate: "DOWN" },
    ] : version)));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Быстро подключить" }));
  await user.selectOptions(screen.getByLabelText("Сценарий подключения"), "static");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.selectOptions(screen.getByLabelText("Физический порт"), "eth1");
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.type(screen.getByLabelText("Адрес (CIDR)"), "invalid");
  expect(screen.getByRole("button", { name: "Далее" })).toBeDisabled();
  await user.clear(screen.getByLabelText("Адрес (CIDR)"));
  await user.type(screen.getByLabelText("Адрес (CIDR)"), "192.168.20.1/24");
  await user.click(screen.getByRole("button", { name: "Далее" }));
  await user.click(screen.getByRole("button", { name: "Далее" }));
  expect(screen.getByLabelText("Адресация")).toHaveValue("192.168.20.1/24");
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(screen.queryByRole("button", { name: "Без названия" })).toBeNull();
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
});
