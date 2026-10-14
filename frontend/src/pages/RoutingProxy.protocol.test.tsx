import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import Routing from "./Routing";
import { emptyConfiguration } from "../fixtures";
import { RouterProvider, useRouterState } from "../state";
import type { ProxyOutbound, ProxySettings } from "../types";

function setup(proxies: ProxySettings, preview?: unknown) {
  const configuration = { ...emptyConfiguration, proxies };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/versions")
      return Promise.resolve(new Response(JSON.stringify([{ id: 1, status: "draft", configuration }])));
    if (path === "/api/auth/me")
      return Promise.resolve(new Response(JSON.stringify({ id: 1, username: "admin", role: "admin" })));
    if (path === "/api/rulesets") return Promise.resolve(new Response("[]"));
    if (path === "/api/proxy/subscriptions/preview")
      return Promise.resolve(new Response(JSON.stringify(preview)));
    return Promise.resolve(new Response(JSON.stringify({
      id: 1, status: "draft", configuration: JSON.parse(String(init?.body)),
    })));
  });
  vi.stubGlobal("fetch", fetch);
  function Session() {
    const { loadUser } = useRouterState();
    useEffect(() => { void loadUser(); }, [loadUser]);
    return null;
  }
  render(<MemoryRouter><RouterProvider><Session /><Routing /></RouterProvider></MemoryRouter>);
  return fetch;
}

async function editProxies(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByRole("button", { name: "Предпросмотр сохранённого черновика" });
  await user.click(screen.getByRole("tab", { name: "Прокси-выходы" }));
  await user.click(screen.getByRole("button", { name: "Редактировать" }));
}

// Outbound/subscription fields now live inside modal dialogs: open the matching
// dialog first, and close it before reaching page-level controls.
const openOutbound = (user: ReturnType<typeof userEvent.setup>, tag: string) =>
  user.click(screen.getByRole("button", { name: `Изменить выход ${tag}` }));
const closeDialog = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(screen.getByRole("button", { name: "Отмена" }));

function sentProxies(fetch: ReturnType<typeof setup>): ProxySettings {
  const call = fetch.mock.calls.find(([path, init]) =>
    path === "/api/draft" && (init as RequestInit)?.method === "PUT");
  return JSON.parse(String((call![1] as RequestInit).body)).proxies as ProxySettings;
}

const materialized: ProxyOutbound = {
  tag: "sub_node", type: "vless", server: "exit.example.org", port: 443,
  secret: { redacted: true }, method: null, tls: true,
  tls_server_name: "front.example.org", tls_insecure: false,
  transport: { type: "ws", path: "/old" },
  reality_public_key: "public-key", reality_short_id: "a1b2",
  username: null, admin_listen: null,
} as ProxyOutbound;

it("saves edited VLESS transport, TLS and Reality fields in the draft payload", async () => {
  const fetch = setup({ ...emptyConfiguration.proxies, outbounds: [materialized] });
  const user = userEvent.setup();
  await editProxies(user);
  await openOutbound(user, "sub_node");
  fireEvent.change(screen.getByDisplayValue("/old"), { target: { value: "/edge" } });
  fireEvent.change(screen.getByDisplayValue("front.example.org"),
    { target: { value: "sni.example.org" } });
  fireEvent.change(screen.getByDisplayValue("public-key"),
    { target: { value: "next-public-key" } });
  fireEvent.change(screen.getByDisplayValue("a1b2"), { target: { value: "c3d4" } });
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(1));
  expect(sentProxies(fetch).outbounds[0]).toMatchObject({
    type: "vless", transport: { type: "ws", path: "/edge" }, tls: true,
    tls_server_name: "sni.example.org", reality_public_key: "next-public-key",
    reality_short_id: "c3d4", secret: { redacted: true },
  });
});

it("shows VMess transport controls and saves VMess-only fields", async () => {
  const outbound: ProxyOutbound = {
    ...materialized, tag: "vmess_node", type: "vmess", tls: true,
    transport: { type: "grpc", service_name: "old-service" },
    security: "auto", alter_id: 0, reality_public_key: null, reality_short_id: null,
  };
  const fetch = setup({ ...emptyConfiguration.proxies, outbounds: [outbound] });
  const user = userEvent.setup();
  await editProxies(user);
  await openOutbound(user, "vmess_node");
  expect(screen.getByLabelText("Service name gRPC")).toHaveValue("old-service");
  expect(screen.queryByLabelText("Reality public key")).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Service name gRPC"),
    { target: { value: "next-service" } });
  fireEvent.change(screen.getByLabelText("Alter ID"), { target: { value: "2" } });
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(1));
  expect(sentProxies(fetch).outbounds[0]).toMatchObject({
    type: "vmess", transport: { type: "grpc", service_name: "next-service" },
    alter_id: 2, security: "auto", tls: true,
  });
});

it("keeps a materialized subscription outbound editable and saves its protocol details", async () => {
  const fetch = setup({ ...emptyConfiguration.proxies, outbounds: [materialized] });
  const user = userEvent.setup();
  await editProxies(user);
  await openOutbound(user, "sub_node");
  expect(screen.getByDisplayValue("/old")).toBeVisible();
  fireEvent.change(screen.getByDisplayValue("/old"), { target: { value: "/new" } });
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(1));
  expect(sentProxies(fetch).outbounds[0]).toMatchObject({
    tag: "sub_node", type: "vless", tls: true,
    tls_server_name: "front.example.org", transport: { type: "ws", path: "/new" },
    reality_public_key: "public-key", reality_short_id: "a1b2",
    secret: { redacted: true },
  });
});

for (const [type, label] of [
  ["trojan", "Пароль"], ["shadowsocks", "Метод шифрования"],
  ["hysteria2", "Обфускация (тип)"], ["tuic", "UUID:пароль"],
  ["naive", "Пользователь"], ["mieru", "Пользователь"],
] as const) {
  it(`renders ${type} fields and preserves protocol when saving`, async () => {
    const outbound = { ...materialized, tag: `${type}_node`, type, tls: type === "trojan" || type === "hysteria2",
      method: type === "shadowsocks" ? "aes-128-gcm" : null, username: type === "naive" || type === "mieru" ? "user" : null,
      obfs_type: type === "hysteria2" ? "salamander" : null };
    const fetch = setup({ ...emptyConfiguration.proxies, outbounds: [outbound] });
    const user = userEvent.setup();
    await editProxies(user);
    await openOutbound(user, `${type}_node`);
    expect(screen.getByLabelText(label)).toBeVisible();
    expect(screen.queryByDisplayValue("private-stored-secret")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(sentProxies(fetch).outbounds[0].type).toBe(type));
    expect(sentProxies(fetch).outbounds[0]).toMatchObject({ tag: `${type}_node`, type,
      ...(type === "shadowsocks" ? { method: "aes-128-gcm" } : {}),
      ...(type === "naive" || type === "mieru" ? { username: "user" } : {}),
      ...(type === "hysteria2" ? { obfs_type: "salamander" } : {}),
      secret: { redacted: true },
    });
  });
}

it("materializes a preview proposal for editing without exposing its secret", async () => {
  const proposed = { ...materialized, secret: { plaintext: "uuid-private" } };
  const subscription = {
    name: "sub1", url: "https://provider.example.org/feed", format: "auto" as const,
    interval_hours: 24, enabled: false,
  };
  const fetch = setup(
    { ...emptyConfiguration.proxies, subscriptions: [subscription] },
    { members: [{ tag: "sub_node", label: "Узел Европа", protocol: "vless",
      server: "exit.example.org", port: 443, transport: "ws", sni: "front.example.org",
      security: "reality" }], skipped: [{ line: 2, reason: "Неподдерживаемый протокол" }], outbounds: [proposed],
      groups: [{ tag: "sub1", type: "selector", outbounds: ["sub_node"],
        url: null, interval_minutes: null }] },
  );
  const user = userEvent.setup();
  await editProxies(user);
  await user.click(screen.getByRole("button", { name: "Изменить" }));
  await user.click(screen.getByRole("button", { name: "Просмотр" }));
  await screen.findAllByText("Узел Европа");
  await user.click(screen.getByRole("button", { name: "Применить предложение" }));
  expect(screen.getByText(/Строка 2: Неподдерживаемый протокол/)).toBeVisible();
  await closeDialog(user);
  await openOutbound(user, "sub_node");
  expect(screen.getByDisplayValue("sub_node")).toBeVisible();
  expect(screen.queryByText("uuid-private")).not.toBeInTheDocument();
  expect(screen.queryByDisplayValue("uuid-private")).not.toBeInTheDocument();
  fireEvent.change(screen.getByDisplayValue("/old"), { target: { value: "/proposal" } });
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(sentProxies(fetch).outbounds).toHaveLength(1));
  expect(sentProxies(fetch)).toMatchObject({ enabled: true,
    outbounds: [{ tag: "sub_node", transport: { type: "ws", path: "/proposal" },
      reality_public_key: "public-key", reality_short_id: "a1b2",
      secret: { plaintext: "uuid-private" } }],
    groups: [{ tag: "sub1", outbounds: ["sub_node"] }],
  });
});
