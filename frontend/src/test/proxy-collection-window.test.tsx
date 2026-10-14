import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { emptyConfiguration } from "../fixtures";
import { DDNS, Sites } from "../pages/ConnectionEditors";
import { ProxiesEditor } from "../pages/RoutingProxy";
import { RouterProvider } from "../state";
import type { Configuration, ProxyGroup, ProxyOutbound, ProxySubscription } from "../types";

function mount(page: React.ReactNode, configuration: Configuration = emptyConfiguration) {
  vi.stubGlobal("fetch", vi.fn(async (path: string) => new Response(JSON.stringify(
    path === "/api/versions" ? [{ id: 1, status: "confirmed", configuration }] : {},
  ))));
  render(<RouterProvider>{page}</RouterProvider>);
}

it("opens a new site in a grouped dialog and removes its fields on cancel", async () => {
  mount(<Sites />);
  const add = await screen.findByRole("button", { name: "+ Добавить сайт" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Имя сайта")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Hostname сайта")).not.toBeInTheDocument();

  await userEvent.click(add);
  const dialog = screen.getByRole("dialog", { name: /Сайт: Новая запись/ });
  for (const section of ["Идентификация", "Подключение", "Сертификат"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Имя сайта")).toBeVisible();
  expect(within(dialog).getByLabelText("Hostname сайта")).toBeVisible();
  expect(within(dialog).getByLabelText("Upstream")).toBeVisible();

  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Имя сайта")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Hostname сайта")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Upstream")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "+ Добавить сайт" })).toBeEnabled();
});

it("opens a configured site from its list row", async () => {
  mount(<Sites />, { ...emptyConfiguration, sites: [{
    name: "web", hostname: "home.example.org", upstream: "192.0.2.10:443",
    certificate_mode: "http01", wan_address: null, certificate: null,
    private_key: null, dns_api_token: null,
  }] });
  await userEvent.click(await screen.findByRole("button", { name: "web" }));
  const dialog = screen.getByRole("dialog", { name: /Сайт: web/ });
  expect(within(dialog).getByLabelText("Hostname сайта")).toHaveValue("home.example.org");
});

it("opens a new DDNS domain with identification, connection and secret sections", async () => {
  mount(<DDNS />);
  const add = await screen.findByRole("button", { name: "+ Добавить домен" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Имя DDNS")).not.toBeInTheDocument();

  await userEvent.click(add);
  const dialog = screen.getByRole("dialog", { name: /DDNS: Новая запись/ });
  for (const section of ["Идентификация", "Подключение", "Секрет"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Имя DDNS")).toBeVisible();
  expect(within(dialog).getByLabelText("Hostname DDNS")).toBeVisible();
  expect(within(dialog).getByLabelText("API token / TSIG key")).toBeVisible();
});

const OUTBOUND: ProxyOutbound = {
  tag: "alpha", type: "shadowsocks", server: "exit.example.com", port: 8388,
  secret: { redacted: true }, method: "aes-256-gcm", tls: false,
  tls_server_name: null, tls_insecure: false, admin_listen: null,
};
const SUBSCRIPTION: ProxySubscription = {
  name: "sub1", url: "https://sub.example.com/list", format: "auto",
  interval_hours: 24, enabled: false, mode: "selector", inline: false, inline_content: null,
};
const GROUP: ProxyGroup = {
  tag: "pool", type: "selector", outbounds: ["alpha"], url: null,
  interval_minutes: null, tolerance_ms: null,
};

function withProxies(proxies: Partial<Configuration["proxies"]>): Configuration {
  return { ...emptyConfiguration, proxies: { ...emptyConfiguration.proxies, ...proxies } };
}

async function enterProxyEdit(configuration: Configuration) {
  mount(<ProxiesEditor />, configuration);
  await userEvent.click(await screen.findByRole("button", { name: "Редактировать" }));
}

it("opens a proxy-outbound editor in a window and clears it from the page on close", async () => {
  await enterProxyEdit(withProxies({ outbounds: [OUTBOUND] }));
  // The page keeps only the list while no window is open: no dialog, no form.
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Тег выхода")).not.toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: "Изменить выход alpha" }));
  const dialog = screen.getByRole("dialog", { name: /Прокси-выход: alpha/ });
  for (const section of ["Идентификация", "Подключение", "Правила"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Тег выхода")).toHaveValue("alpha");
  expect(within(dialog).getByRole("button", { name: "Отмена" })).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeVisible();

  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Тег выхода")).not.toBeInTheDocument();
});

it("opens a subscription editor in a window with its own sections and footer", async () => {
  await enterProxyEdit(withProxies({ subscriptions: [SUBSCRIPTION] }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Имя подписки")).not.toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: /Подписка: sub1/ });
  for (const section of ["Идентификация", "Обновление", "Параметры"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Имя подписки")).toHaveValue("sub1");
  expect(within(dialog).getByRole("button", { name: "Отмена" })).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeVisible();

  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Имя подписки")).not.toBeInTheDocument();
});

it("opens a group editor in a window with its own sections and footer", async () => {
  await enterProxyEdit(withProxies({ outbounds: [OUTBOUND], groups: [GROUP] }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Тег группы")).not.toBeInTheDocument();

  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  const dialog = screen.getByRole("dialog", { name: /Группа выходов: pool/ });
  for (const section of ["Идентификация", "Состав"]) {
    expect(within(dialog).getByRole("heading", { name: section })).toBeVisible();
  }
  expect(within(dialog).getByLabelText("Тег группы")).toHaveValue("pool");
  expect(within(dialog).getByRole("button", { name: "Отмена" })).toBeVisible();
  expect(within(dialog).getByRole("button", { name: "Сохранить" })).toBeVisible();

  await userEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  expect(screen.queryByLabelText("Тег группы")).not.toBeInTheDocument();
});
