import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { DHCP } from "../pages/Services";
import { fmtRemaining } from "../components/format";
import { emptyConfiguration } from "../fixtures";
import type { Configuration, DHCPLease } from "../types";

it.each([
  [0, "истекла"],
  [-1, "истекла"],
  [59, "менее минуты"],
  [3600, "1 ч"],
  [2740, "45 мин"],
  [9900, "2 ч 45 мин"],
])("formats %i remaining lease seconds as %s", (seconds, expected) => {
  expect(fmtRemaining(seconds)).toBe(expected);
});

function mockDhcp(leaseResponse: (path: string) => Response) {
  const fetch = vi.fn().mockImplementation((path: string) => Promise.resolve(
    path === "/api/versions"
      ? new Response(JSON.stringify([{ id: 1, status: "draft", configuration: emptyConfiguration }]))
      : path.startsWith("/api/dhcp/leases")
        ? leaseResponse(path)
        : new Response(JSON.stringify({ generated_at: "2026-10-14T10:00:00Z", services: [] })),
  ));
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

it("opens a DHCP subnet in a grouped dialog and leaves no subnet form in the page flow", async () => {
  const subnet = { id: 1, interface: "lan0", subnet: "192.168.1.0/24", pools: [{ start: "192.168.1.100", end: "192.168.1.200" }], reservations: [], routers: ["192.168.1.1"], dns_servers: [], valid_lifetime: 3600 };
  const configuration = { ...emptyConfiguration, interfaces: [{ name: "lan0", type: "physical" as const, zone: "lan", description: null, addressing: "static" as const, addresses: ["192.168.1.1/24"], parent: null, vlan_id: null, members: [] }], dhcp_subnets: [subnet] };
  vi.stubGlobal("fetch", vi.fn((path: string) => Promise.resolve(new Response(JSON.stringify(
    path === "/api/versions" ? [{ id: 1, status: "draft", configuration }] : { generated_at: "2026-10-14T10:00:00Z", services: [] },
  )))));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Подсети и диапазоны" }));
  expect(screen.queryByLabelText("Срок аренды, с")).not.toBeInTheDocument();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Настроить" }));
  await user.click(within(screen.getByRole("dialog", { name: "Подсети DHCP" })).getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: /Подсеть 192\.168\.1\.0\/24/ });
  for (const section of ["Идентификация", "Диапазон", "Параметры", "Резервирования"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Подсеть CIDR")).toHaveAttribute("readonly");
  expect(within(dialog).getByRole("button", { name: "Отмена" })).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeVisible();
  await user.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Срок аренды, с")).not.toBeInTheDocument();
  expect(screen.getByText("192.168.1.0/24")).toBeVisible();
});

it("shows an empty state when DHCP subnets are not configured", async () => {
  mockDhcp(() => new Response("[]"));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Подсети и диапазоны" }));
  expect(screen.getByText("Подсети DHCP не настроены.")).toBeVisible();
});

it("applies lease search and restores the full list on reset", async () => {
  const lease = (ip: string, hostname: string) => ({
    ip, hostname, mac: "aa:bb:cc:dd:ee:ff", subnet: "192.168.1.0/24",
    cltt: 0, valid_lft: 3600, expires_in: 3600,
  });
  const full = [lease("192.168.1.10", "printer"), lease("192.168.1.11", "laptop")];
  const fetch = mockDhcp((path) => new Response(JSON.stringify(
    path === "/api/dhcp/leases/search?q=printer" ? [full[0]] : full,
  )));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Аренды" }));
  expect(await screen.findByText("192.168.1.11")).toBeVisible();
  await user.type(screen.getByRole("textbox", { name: "Поиск: MAC, IP, hostname" }), "printer");
  await user.click(screen.getByRole("button", { name: "Найти" }));
  await waitFor(() => expect(screen.queryByText("192.168.1.11")).toBeNull());
  expect(screen.getByText("192.168.1.10")).toBeVisible();
  expect(screen.getByText(/Показаны результаты по запросу «printer»/)).toBeVisible();
  expect(fetch.mock.calls.some(([path]) => path === "/api/dhcp/leases/search?q=printer")).toBe(true);
  await user.click(screen.getByRole("button", { name: "Сбросить" }));
  expect(await screen.findByText("192.168.1.11")).toBeVisible();
  expect(screen.getByRole("textbox", { name: "Поиск: MAC, IP, hostname" })).toHaveValue("");
});

it("shows an empty leases table when the API returns no leases", async () => {
  mockDhcp(() => new Response("[]"));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Аренды" }));
  expect(await screen.findByText("Аренд пока нет")).toBeVisible();
});

it("shows an unavailable status when the lease service fails", async () => {
  mockDhcp(() => new Response(JSON.stringify({ code: "kea.unavailable", message: "Kea недоступен", details: [] }), { status: 503 }));
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Аренды" }));
  expect(await screen.findByText("Kea ctrl-agent недоступен — аренды не прочитаны", {}, { timeout: 12000 })).toBeVisible();
  expect(screen.queryByText("Загрузка аренд…")).toBeNull();
  expect(screen.queryByText("Kea недоступен")).toBeNull();
});

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
  expect(await screen.findByRole("dialog", { name: /Интерфейс: Провайдер/ })).toBeVisible();
  expect(screen.getByText("Провайдер", { selector: "button" })).toBeInTheDocument();
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces).toEqual([expect.objectContaining({ name: "eth0", type: "physical", zone: "wan", description: "Провайдер", addressing: "dhcp", addresses: [] })]);
});

it("quick static allows an addressless parent, rejects malformed CIDR, and cancellation leaves no draft", async () => {
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
  expect(screen.getByRole("button", { name: "Далее" })).toBeEnabled();
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

it("saves PPPoE credentials through one draft and clears them on mode change", async () => {
  const initial = { ...emptyConfiguration, interfaces: [{
    name: "eth0", type: "physical", zone: "wan", description: null,
    addressing: "static", addresses: ["192.0.2.2/24"], parent: null, vlan_id: null, members: [],
  }] };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const configuration = init?.body ? JSON.parse(String(init.body)) : initial;
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(path === "/api/versions" ? [version] :
      path === "/api/host/interfaces" ? [{ name: "eth0", kind: "physical", parent: null, operstate: "UP" }] : version)));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Без названия" }));
  await user.selectOptions(screen.getByLabelText("Режим адресации"), "pppoe");
  expect(screen.queryByLabelText("Основной адрес (CIDR)")).toBeNull();
  expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();
  await user.type(screen.getByLabelText("Логин"), "subscriber");
  await user.type(screen.getByLabelText("Пароль"), "private-pass");
  expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(false);
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces[0]).toEqual(expect.objectContaining({ addressing: "pppoe", addresses: [], pppoe_username: "subscriber", pppoe_password: { plaintext: "private-pass" } }));
  await user.click(await screen.findByRole("button", { name: "Без названия" }));
  await user.selectOptions(screen.getByLabelText("Режим адресации"), "dhcp");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.filter(([, init]) => init?.method === "PUT")).toHaveLength(2));
  const second = JSON.parse(String(fetch.mock.calls.filter(([, init]) => init?.method === "PUT")[1][1].body));
  expect(second.interfaces[0]).not.toHaveProperty("pppoe_username");
  expect(second.interfaces[0]).not.toHaveProperty("pppoe_password");
});

function leaseFixture(): { configuration: Configuration; leases: DHCPLease[] } {
  const configuration: Configuration = {
    ...emptyConfiguration,
    interfaces: [{ name: "vlan1", type: "vlan", zone: "lan", description: "prostor-wifi-ssid",
      addressing: "static", addresses: ["172.20.1.1/24"], parent: null, vlan_id: 1, members: [] }],
    dhcp_subnets: [{ id: 1, interface: "vlan1", subnet: "172.20.1.0/24", pools: [],
      reservations: [], routers: [], dns_servers: [], valid_lifetime: 3600 }],
  };
  const leases: DHCPLease[] = [
    { ip: "172.20.1.21", mac: "3c:6a:a7:0d:5e:11", hostname: "poco-x8-pro",
      subnet: "1", cltt: 0, valid_lft: 3600, expires_in: 3600 },
    { ip: "172.20.1.34", mac: "da:4b:8e:1a:2c:3f", hostname: "",
      subnet: "1", cltt: 0, valid_lft: 3600, expires_in: 600 },
  ];
  return { configuration, leases };
}

function mockLeasesPage(configuration: Configuration, leases: DHCPLease[]) {
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/versions") return Promise.resolve(
      new Response(JSON.stringify([{ id: 1, status: "draft", configuration }])));
    if (path === "/api/dhcp/leases") return Promise.resolve(new Response(JSON.stringify(leases)));
    if (path === "/api/draft") return Promise.resolve(new Response(JSON.stringify({
      id: 2, status: "draft", configuration: JSON.parse(String(init?.body)),
    })));
    return Promise.resolve(new Response(JSON.stringify({ generated_at: "2026-11-25T10:00:00Z", services: [] })));
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}

it("opens leases first, showing the friendly subnet and private-MAC warning", async () => {
  const { configuration, leases } = leaseFixture();
  mockLeasesPage(configuration, leases);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  expect(await screen.findByRole("tab", { name: "Аренды" })).toHaveAttribute("aria-selected", "true");
  expect(await screen.findAllByText("prostor-wifi-ssid (vlan1) · 172.20.1.0/24")).toHaveLength(2);
  expect(screen.getByText("Приватный MAC")).toBeVisible();
  expect(screen.getByRole("button", { name: "Закрепить 172.20.1.34" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Закрепить 172.20.1.21" })).toBeEnabled();
  await user.click(screen.getByRole("button", { name: "Заметка для 172.20.1.21" }));
  const dialog = screen.getByRole("dialog", { name: "Заметка клиента" });
  expect(within(dialog).getByLabelText("MAC")).toHaveValue("3c:6a:a7:0d:5e:11");
  expect(within(dialog).getByLabelText("Подсеть")).toHaveValue("prostor-wifi-ssid (vlan1) · 172.20.1.0/24");
  expect(within(dialog).queryByLabelText("Постоянный IP")).toBeNull();
});

it("saves a client note from the leases tab into the draft", async () => {
  const { configuration, leases } = leaseFixture();
  const fetch = mockLeasesPage(configuration, leases);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Заметка для 172.20.1.21" }));
  const dialog = screen.getByRole("dialog", { name: "Заметка клиента" });
  await user.type(within(dialog).getByLabelText("Заметка"), "Телефон Алины");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body));
  expect(saved.dhcp_client_notes).toEqual([{ mac: "3c:6a:a7:0d:5e:11", note: "Телефон Алины" }]);
  expect(saved.dhcp_subnets[0].reservations).toEqual([]);
});

it("binds a lease with the current address and keeps the row in the list", async () => {
  const { configuration, leases } = leaseFixture();
  const fetch = mockLeasesPage(configuration, leases);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Закрепить 172.20.1.21" }));
  const dialog = screen.getByRole("dialog", { name: "Закрепить адрес" });
  expect(within(dialog).getByLabelText("Постоянный IP")).toHaveValue("172.20.1.21");
  await user.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body));
  expect(saved.dhcp_subnets[0].reservations).toEqual([{
    hw_address: "3c:6a:a7:0d:5e:11", ip_address: "172.20.1.21", hostname: "poco-x8-pro",
  }]);
  expect(await screen.findByText("172.20.1.21")).toBeVisible();
});
