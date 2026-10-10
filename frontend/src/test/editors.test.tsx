import { render, screen, waitFor, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Firewall from "../pages/Firewall";
import { DHCP, DNS } from "../pages/Services";
import { emptyConfiguration } from "../fixtures";
import type { Configuration } from "../types";

function mockApi(
  configuration: Configuration = emptyConfiguration,
  draft = true,
  fail = false,
) {
  const fetch = vi
    .fn()
    .mockImplementation((path: string, init?: RequestInit) => {
      if (path === "/api/versions")
        return Promise.resolve(
          new Response(
            JSON.stringify([
              { id: 1, status: draft ? "draft" : "confirmed", configuration },
            ]),
          ),
        );
      if (fail)
        return Promise.resolve(
          new Response(
            JSON.stringify({
              code: "validation.failed",
              message: "Ошибка проверки конфигурации",
              details: [],
            }),
            { status: 422 },
          ),
        );
      return Promise.resolve(
        new Response(
          JSON.stringify({
            id: draft ? 1 : 2,
            status: "draft",
            configuration: JSON.parse(String(init?.body)),
          }),
        ),
      );
    });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
async function open(page: React.ReactNode) {
  render(
    <MemoryRouter>
      <RouterProvider>{page}</RouterProvider>
    </MemoryRouter>,
  );
  const edit = await screen.findByRole("button", { name: "Редактировать" });
  await waitFor(() => expect(edit).toBeEnabled());
  await userEvent.click(edit);
}
const saveButton = () =>
  screen.getByRole("button", { name: "Сохранить" });

it("validates and cancels a new Firewall rule locally", async () => {
  const fetch = mockApi();
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.type(screen.getByLabelText("Имя"), "правило");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Имя"));
  await user.type(screen.getByLabelText("Имя"), "first");
  await user.clear(screen.getByLabelText("Откуда"));
  await user.type(screen.getByLabelText("Откуда"), "999.1.1.1");
  expect(saveButton()).toBeDisabled();
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  expect(fetch.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0);
});

it("saves a new Firewall rule with unchanged API values", async () => {
  const fetch = mockApi(emptyConfiguration, false);
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.type(screen.getByLabelText("Имя"), "allow_web");
  await user.selectOptions(screen.getByLabelText("Протокол"), "tcp_udp");
  await user.selectOptions(screen.getByLabelText("Действие"), "pass");
  await user.click(saveButton());
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const saved = JSON.parse(fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body);
  expect(saved.firewall_rules[0]).toMatchObject({ name: "allow_web", protocol: "tcp_udp", action: "pass", ingress_zone: "wan" });
});

it("validates DHCP lease seconds and saves them through the same draft", async () => {
  const configuration: Configuration = { ...emptyConfiguration,
    interfaces: [{ name: "lan0", type: "physical", zone: "lan", description: null, addressing: "static", addresses: ["192.168.1.1/24"], parent: null, vlan_id: null, members: [] }],
    dhcp_subnets: [{ id: 1, interface: "lan0", subnet: "192.168.1.0/24", pools: [], reservations: [], routers: [], dns_servers: [], valid_lifetime: 3600 }] };
  const fetch = mockApi(configuration);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("tab", { name: "Подсети и диапазоны" }));
  await user.click(screen.getByRole("button", { name: "Настроить" }));
  const field = screen.getByLabelText("Срок аренды, с");
  expect(field).toHaveValue(3600);
  expect(field).toHaveAttribute("min", "1");
  expect(screen.getByText(/Время, на которое DHCP выдаёт клиенту IP-адрес/)).toBeVisible();
  await user.clear(field);
  await user.type(field, "0");
  expect(saveButton()).toBeDisabled();
  await user.clear(field);
  await user.type(field, "7200");
  expect(saveButton()).toBeEnabled();
  await user.click(saveButton());
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const saved = JSON.parse(fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body);
  expect(saved.dhcp_subnets[0].valid_lifetime).toBe(7200);
});

it("saves a device reservation in its selected subnet and DNS lists through the draft", async () => {
  const configuration: Configuration = { ...emptyConfiguration, interfaces: [{ name: "lan0", type: "physical", zone: "lan", description: null, addressing: "static", addresses: ["192.168.1.1/24"], parent: null, vlan_id: null, members: [] }],
    dhcp_subnets: [{ id: 1, interface: "lan0", subnet: "192.168.1.0/24", pools: [{ start: "192.168.1.100", end: "192.168.1.200" }], reservations: [], routers: ["192.168.1.1"], dns_servers: ["192.168.1.1"], valid_lifetime: 3600 }] };
  const fetch = mockApi(configuration);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Добавить устройство" }));
  await user.type(screen.getByLabelText("Имя устройства"), "printer.home.lan");
  await user.type(screen.getByLabelText("MAC"), "aa:bb:cc:dd:ee:01");
  await user.type(screen.getByLabelText("Постоянный IP"), "192.168.1.20");
  await user.click(saveButton());
  await waitFor(() => expect(fetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const saved = JSON.parse(fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body);
  expect(saved.dhcp_subnets[0].reservations).toEqual([{ hostname: "printer.home.lan", hw_address: "aa:bb:cc:dd:ee:01", ip_address: "192.168.1.20" }]);
  expect(saved.dns).toEqual(configuration.dns);
  cleanup();
  const dnsFetch = mockApi(saved);
  render(<MemoryRouter><RouterProvider><DNS /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Добавить имя" }));
  await user.type(screen.getByLabelText("Имя DNS-записи"), "nas.home.lan");
  await user.type(screen.getByLabelText("Значение записи"), "192.168.1.20");
  await user.click(screen.getByRole("button", { name: "+ Добавить переадресацию" }));
  await user.type(screen.getByLabelText("Домен переадресации"), "corp.test");
  await user.click(screen.getAllByRole("button", { name: "Добавить DNS-сервер" })[0]);
  await user.type(screen.getByLabelText("Адрес DNS-сервера"), "10.0.0.53");
  await user.click(saveButton());
  await waitFor(() => expect(dnsFetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(true));
  const dnsSaved = JSON.parse(dnsFetch.mock.calls.find(([path]) => path === "/api/draft")![1].body);
  expect(dnsSaved.dns.records[0]).toMatchObject({ name: "nas.home.lan", value: "192.168.1.20" });
  expect(dnsSaved.dns.forwards[0]).toMatchObject({ domain: "corp.test", upstreams: [{ address: "10.0.0.53" }] });
  expect(dnsSaved.dhcp_subnets).toEqual(saved.dhcp_subnets);
});

it("renders an API save error and retains local edits for retry", async () => {
  mockApi(emptyConfiguration, true, true);
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "Добавить правило" }));
  await user.type(screen.getByLabelText("Имя"), "keep_me");
  await user.click(saveButton());
  expect(await screen.findByText(/Ошибка проверки конфигурации/)).toBeVisible();
  expect(screen.getByLabelText("Имя")).toHaveValue("keep_me");
  expect(saveButton()).toBeEnabled();
});

it("shows DoT tls_name and DoH doh_server fields and requires them", async () => {
  const fetch = mockApi(emptyConfiguration);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DNS /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Настроить" }));
  await user.click(screen.getAllByRole("button", { name: "Добавить DNS-сервер" })[0]);
  await user.click(screen.getAllByRole("button", { name: "Добавить DNS-сервер" })[1]);
  const tlsLabel = "Имя TLS (DoT)";
  const dohLabel = "Сервер DoH (dnscrypt-proxy)";
  // First row: switch to DoT
  await user.selectOptions(
    screen.getAllByLabelText("Протокол DNS-сервера")[0],
    "tls",
  );
  expect(screen.queryAllByLabelText(tlsLabel).length).toBe(1);
  await user.type(screen.getAllByLabelText(tlsLabel)[0], "dot.example.com");
  await user.type(screen.getAllByLabelText("Адрес DNS-сервера")[0], "1.1.1.1");
  // Second row: switch to DoH
  await user.selectOptions(
    screen.getAllByLabelText("Протокол DNS-сервера")[1],
    "https",
  );
  expect(screen.queryAllByLabelText(dohLabel).length).toBe(1);
  expect(screen.queryAllByLabelText(tlsLabel).length).toBe(1);
  await user.type(screen.getAllByLabelText(dohLabel)[0], "doh.example.com");
  await user.click(saveButton());
  await waitFor(() =>
    expect(
      fetch.mock.calls.filter(([path]) => path === "/api/draft"),
    ).toHaveLength(1),
  );
  const saved = JSON.parse(
    fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body,
  );
  expect(saved.dns.upstreams).toEqual([
    { address: "1.1.1.1", port: 53, mode: "tls", tls_name: "dot.example.com", doh_server: null },
    { address: "", port: 53, mode: "https", tls_name: null, doh_server: "doh.example.com" },
  ]);
});

it("shows device-first DHCP controls and rejects duplicate reservations", async () => {
  const configuration: Configuration = { ...emptyConfiguration, interfaces: [{ name: "lan0", type: "physical", zone: "lan", description: null, addressing: "static", addresses: ["192.168.1.1/24"], parent: null, vlan_id: null, members: [] }],
    dhcp_subnets: [{ id: 1, interface: "lan0", subnet: "192.168.1.0/24", pools: [], reservations: [{ hostname: "printer", hw_address: "aa:bb:cc:dd:ee:01", ip_address: "192.168.1.20" }], routers: [], dns_servers: [], valid_lifetime: 3600 }] };
  mockApi(configuration);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><DHCP /></RouterProvider></MemoryRouter>);
  expect(await screen.findByRole("tab", { name: "Устройства с постоянным IP" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("columnheader", { name: "Постоянный IP" })).toBeVisible();
  expect(screen.getByText("Статус загружается…")).toBeVisible();
  await user.click(screen.getByRole("button", { name: "Добавить устройство" }));
  await user.type(screen.getByLabelText("MAC"), "aa:bb:cc:dd:ee:01");
  await user.type(screen.getByLabelText("Постоянный IP"), "192.168.1.21");
  expect(saveButton()).toBeDisabled();
});

it("shows DNS list actions and honest logging visibility", async () => {
  mockApi();
  render(<MemoryRouter><RouterProvider><DNS /></RouterProvider></MemoryRouter>);
  expect(await screen.findByRole("button", { name: "Добавить имя" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Добавить домен" })).toBeEnabled();
  expect(screen.getByText("Через указанные DNS-серверы")).toBeVisible();
  expect(screen.getByText("Просмотр DNS-запросов здесь пока недоступен.")).toBeVisible();
});
