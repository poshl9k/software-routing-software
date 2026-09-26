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
  screen.getByRole("button", { name: "Сохранить черновик" });

it("renders Firewall editor, validates names and addresses, reorders and cancels locally", async () => {
  const fetch = mockApi();
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "правило");
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Имя правила"));
  await user.type(screen.getByLabelText("Имя правила"), "first");
  await user.clear(screen.getByLabelText("Источник", { exact: true }));
  await user.type(
    screen.getByLabelText("Источник", { exact: true }),
    "999.1.1.1",
  );
  expect(screen.getByLabelText("Источник", { exact: true })).toHaveAttribute(
    "aria-invalid",
    "true",
  );
  expect(saveButton()).toBeDisabled();
  await user.clear(screen.getByLabelText("Источник", { exact: true }));
  await user.type(
    screen.getByLabelText("Источник", { exact: true }),
    "@clients",
  );
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getAllByLabelText("Имя правила")[1], "second");
  await user.click(screen.getByRole("button", { name: "Вверх second" }));
  expect(
    screen
      .getAllByLabelText("Имя правила")
      .map((e) => (e as HTMLInputElement).value),
  ).toEqual(["second", "first"]);
  await user.click(screen.getByRole("button", { name: "Отмена" }));
  expect(screen.queryByDisplayValue("first")).not.toBeInTheDocument();
  expect(fetch.mock.calls.filter(([, init]) => init?.method)).toHaveLength(0);
});

it("creates a full draft with a new firewall rule and displays the saved version", async () => {
  const fetch = mockApi(emptyConfiguration, false);
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "allow_web");
  await user.selectOptions(screen.getByLabelText("Действие"), "pass");
  await user.click(saveButton());
  await screen.findByText("allow_web");
  const [, init] = fetch.mock.calls.find(([path]) => path === "/api/draft")!;
  expect(init.method).toBe("POST");
  expect(JSON.parse(init.body)).toEqual({
    ...emptyConfiguration,
    firewall_rules: [
      expect.objectContaining({
        name: "allow_web",
        action: "pass",
        ingress_zone: "wan",
        order: 0,
      }),
    ],
  });
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
  expect(screen.getByLabelText("Имя правила")).toHaveValue("allow_web");
  await user.click(saveButton());
  await waitFor(() =>
    expect(
      fetch.mock.calls.filter(([path]) => path === "/api/draft")[1][1].method,
    ).toBe("PUT"),
  );
});

it("saves DHCP reservations inside/outside the pool and DNS records/forwards through saveDraft", async () => {
  const configuration: Configuration = {
    ...emptyConfiguration,
    interfaces: [
      {
        name: "lan0",
        type: "physical",
        zone: "lan",
        addresses: ["192.168.1.1/24"],
        parent: null,
        vlan_id: null,
        members: [],
      },
    ],
  };
  const fetch = mockApi(configuration);
  const user = userEvent.setup();
  await open(<DHCP />);
  await user.click(screen.getByRole("button", { name: "+ Добавить подсеть" }));
  await user.type(screen.getByLabelText("Подсеть CIDR"), "192.168.1.0/24");
  await user.click(screen.getByRole("button", { name: "+ Добавить пул" }));
  await user.type(screen.getByLabelText("Начало пула"), "192.168.1.100");
  await user.type(screen.getByLabelText("Конец пула"), "192.168.1.200");
  for (const [ip, mac] of [
    ["192.168.1.120", "aa:bb:cc:dd:ee:01"],
    ["192.168.1.20", "aa:bb:cc:dd:ee:02"],
  ]) {
    await user.click(
      screen.getByRole("button", { name: "+ Добавить резервацию" }),
    );
    await user.type(screen.getAllByLabelText("IP резервации").at(-1)!, ip);
    await user.type(screen.getAllByLabelText("MAC резервации").at(-1)!, mac);
  }
  await user.click(saveButton());
  await waitFor(() =>
    expect(
      screen.queryByRole("button", { name: "Сохранить черновик" }),
    ).not.toBeInTheDocument(),
  );
  const dhcp = JSON.parse(
    fetch.mock.calls.find(([path]) => path === "/api/draft")![1].body,
  );
  expect(dhcp.dhcp_subnets[0]).toMatchObject({
    interface: "lan0",
    subnet: "192.168.1.0/24",
    pools: [{ start: "192.168.1.100", end: "192.168.1.200" }],
    reservations: [
      {
        ip_address: "192.168.1.120",
        hw_address: "aa:bb:cc:dd:ee:01",
        hostname: null,
      },
      {
        ip_address: "192.168.1.20",
        hw_address: "aa:bb:cc:dd:ee:02",
        hostname: null,
      },
    ],
  });
  expect(dhcp.dns).toEqual(configuration.dns);
  cleanup();
  const dnsFetch = mockApi(dhcp);
  await open(<DNS />);
  await user.click(screen.getByRole("button", { name: "+ Добавить запись" }));
  await user.type(screen.getByLabelText("Имя DNS-записи"), "nas.home.lan");
  await user.type(screen.getByLabelText("Значение записи"), "192.168.1.20");
  await user.click(
    screen.getByRole("button", { name: "+ Добавить переадресацию" }),
  );
  await user.type(screen.getByLabelText("Домен переадресации"), "corp.test");
  await user.type(
    screen.getByLabelText("Upstreams домена (построчно)"),
    "10.0.0.53",
  );
  await user.type(
    screen.getByLabelText("Upstream-серверы (построчно)"),
    "1.1.1.1",
  );
  await user.click(screen.getByRole("button", { name: "+ Добавить привязку" }));
  await user.click(screen.getByRole("switch", { name: "Журнал запросов" }));
  await user.click(saveButton());
  await waitFor(() =>
    expect(dnsFetch.mock.calls.some(([path]) => path === "/api/draft")).toBe(
      true,
    ),
  );
  const saved = JSON.parse(
    dnsFetch.mock.calls.find(([path]) => path === "/api/draft")![1].body,
  );
  expect(saved.dns).toMatchObject({
    interfaces: ["lan0"],
    records: [
      { name: "nas.home.lan", type: "A", ttl: 300, value: "192.168.1.20" },
    ],
    forwards: [{ domain: "corp.test", upstreams: ["10.0.0.53"] }],
    upstreams: ["1.1.1.1"],
    log_queries: true,
  });
  expect(saved.dhcp_subnets).toEqual(dhcp.dhcp_subnets);
});

it("renders an API save error and retains local edits for retry", async () => {
  mockApi(emptyConfiguration, true, true);
  const user = userEvent.setup();
  await open(<Firewall />);
  await user.click(screen.getByRole("button", { name: "+ Добавить правило" }));
  await user.type(screen.getByLabelText("Имя правила"), "keep_me");
  await user.click(saveButton());
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Ошибка проверки конфигурации",
  );
  expect(screen.getByLabelText("Имя правила")).toHaveValue("keep_me");
  expect(saveButton()).toBeEnabled();
});
