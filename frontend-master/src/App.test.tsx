import { afterEach, expect, test, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";

test("login form renders without a session", () => {
  window.history.replaceState({}, "", "/login");
  render(<App />);
  expect(screen.getByRole("button", { name: "Войти" })).toBeEnabled();
});

test("setup form asks for the password twice", () => {
  window.history.replaceState({}, "", "/setup");
  render(<App />);
  expect(screen.getByLabelText("Задайте пароль администратора", { exact: false })).toBeInTheDocument();
  expect(screen.getByLabelText("Повторите пароль", { exact: false })).toBeInTheDocument();
});

afterEach(() => { vi.unstubAllGlobals(); });

test("Telegram proof is cleared from the URL before magic login and opens subscriber cabinet", async () => {
  window.history.replaceState({}, "", "/login#token=one-time-proof");
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/login/magic") {
      expect(window.location.hash).toBe("");
      expect(init?.body).toBe(JSON.stringify({ token: "one-time-proof" }));
      return new Response(JSON.stringify({ id: 1, display_name: "Анна" }), { status: 200 });
    }
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: null,
    }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  expect(await screen.findByText("Подписка пока не активна")).toBeInTheDocument();
  expect(screen.getByText("Анна")).toBeInTheDocument();
  expect(screen.queryByText("Ноды")).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/portal/login/magic", expect.anything());
});

test("invalid magic proof shows an error, not admin password form", async () => {
  window.history.replaceState({}, "", "/login#token=expired");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
    error: { code: "auth.invalid_credentials", message: "auth.invalid_credentials" },
  }), { status: 401 })));
  render(<App />);
  expect(await screen.findByText(/Ссылка недействительна/)).toBeInTheDocument();
  expect(screen.queryByLabelText("Пароль")).not.toBeInTheDocument();
  expect(window.location.hash).toBe("");
});

test("subscriber cabinet without session never mounts admin dashboard", async () => {
  window.history.replaceState({}, "", "/portal");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
    error: { code: "auth.required", message: "auth.required" },
  }), { status: 401 })));
  render(<App />);
  await waitFor(() => expect(screen.getByText(/Откройте ссылку из Telegram-бота/)).toBeInTheDocument());
  expect(screen.queryByText("Ноды")).not.toBeInTheDocument();
});

test("active subscriber can create a device and download only an applied config", async () => {
  window.history.replaceState({}, "", "/portal");
  let devices = [{ id: 7, name: "master_7", label: "Телефон", status: "active",
    allowed_ips: ["10.66.0.7/32"], applied: true, last_handshake: null }];
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" },
      subscription: { status: "active", expires_at: "2026-12-08T00:00:00Z", tariff: { name: "Базовый" } },
    }), { status: 200 });
    if (input === "/api/portal/devices" && !init?.method) return new Response(JSON.stringify({ devices }), { status: 200 });
    if (input === "/api/portal/devices" && init?.method === "POST") {
      expect(init?.body).toBe(JSON.stringify({ label: "Ноутбук" }));
      devices = [...devices, { id: 8, name: "master_8", label: "Ноутбук", status: "active",
        allowed_ips: ["10.66.0.8/32"], applied: true, last_handshake: null }];
      return new Response(JSON.stringify({ status: "applied", operation_id: 8, device_id: 8 }), { status: 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  expect(await screen.findByText(/Телефон/)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Скачать конфигурацию Телефон" })).toHaveAttribute(
    "href", "/api/portal/devices/7/export?format=conf");
  await userEvent.type(screen.getByLabelText("Название устройства", { exact: false }), "Ноутбук");
  await userEvent.click(screen.getByRole("button", { name: "Добавить устройство" }));
  expect(await screen.findByText(/Ноутбук/)).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/portal/devices", expect.objectContaining({ method: "POST" }));
});

test("admin configures a separate master bot without echoing its token", async () => {
  window.history.replaceState({}, "", "/");
  const token = "synthetic-master-token-not-live";
  let configured = false;
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]), { status: 200 });
    if (input === "/api/master-admin/settings/telegram" && !init?.method) {
      return new Response(JSON.stringify({ configured, public_url: configured ? "https://my.poshl9k.ru" : null }), { status: 200 });
    }
    if (input === "/api/master-admin/settings/telegram" && init?.method === "PUT") {
      expect(JSON.parse(String(init.body))).toEqual({ bot_token: token, public_url: "https://my.poshl9k.ru" });
      configured = true;
      return new Response(JSON.stringify({ configured, public_url: "https://my.poshl9k.ru" }), { status: 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  await userEvent.click(await screen.findByRole("tab", { name: "Telegram" }));
  expect(await screen.findByText("Бот не настроен")).toBeInTheDocument();
  await userEvent.type(screen.getByRole("textbox", { name: /Публичный адрес портала/ }), "https://my.poshl9k.ru");
  await userEvent.type(screen.getByLabelText(/Токен отдельного мастер-бота/), token);
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect(await screen.findByText("Бот настроен")).toBeInTheDocument();
  expect(screen.getByLabelText(/Токен отдельного мастер-бота/)).toHaveValue("");
  expect(screen.queryByText(token)).not.toBeInTheDocument();
});

test("admin renders the bare-list responses returned by the master API", async () => {
  window.history.replaceState({}, "", "/");
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (["/api/master-admin/nodes", "/api/master-admin/tariffs", "/api/master-admin/subscribers"].includes(input)) {
      return new Response(JSON.stringify([]), { status: 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  expect(await screen.findByText("Нод пока нет.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Тарифы" }));
  expect(await screen.findByText("Тарифов пока нет.")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("tab", { name: "Абоненты" }));
  expect(await screen.findByText("Абонентов пока нет.")).toBeInTheDocument();
});

test("admin accepts a flat node creation response and shows its one-time token", async () => {
  window.history.replaceState({}, "", "/");
  const node = { id: 5, name: "rg-test", bridge_url: "https://rg-test.example/internal",
    capacity: 20, enabled: true, state: "down", active_peers: 0, last_seen: null };
  let nodes: typeof node[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes" && !init?.method) {
      return new Response(JSON.stringify(nodes), { status: 200 });
    }
    if (input === "/api/master-admin/nodes" && init?.method === "POST") {
      nodes = [node];
      return new Response(JSON.stringify({ ...node, token: "synthetic-one-time-token" }), { status: 201 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Добавить ноду" }));
  await userEvent.type(screen.getByRole("textbox", { name: /Имя ноды/ }), node.name);
  await userEvent.type(screen.getByRole("textbox", { name: /Bridge URL ноды/ }), node.bridge_url);
  await userEvent.click(screen.getByRole("button", { name: "Создать" }));
  expect(await screen.findByText("synthetic-one-time-token")).toBeInTheDocument();
  expect(screen.getByRole("dialog", { name: `Токен ноды ${node.name}` })).toBeInTheDocument();
});

test("admin opens subscriber detail and its tariffs with flat API responses", async () => {
  window.history.replaceState({}, "", "/");
  const subscriber = { id: 2, display_name: "Анна", telegram_chat_id: "test-id", status: "active",
    subscription: null, device_count: 0 };
  const tariff = { id: 3, name: "Базовый", device_limit: 1, term_days: 30,
    price_amount: null, created_at: "2026-11-08T00:00:00Z" };
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]), { status: 200 });
    if (input === "/api/master-admin/subscribers") return new Response(JSON.stringify([subscriber]), { status: 200 });
    if (input === "/api/master-admin/subscribers/2") {
      return new Response(JSON.stringify({ ...subscriber, devices: [] }), { status: 200 });
    }
    if (input === "/api/master-admin/tariffs") return new Response(JSON.stringify([tariff]), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  await userEvent.click(await screen.findByRole("tab", { name: "Абоненты" }));
  await userEvent.click(await screen.findByRole("button", { name: "Открыть" }));
  await userEvent.click(await screen.findByRole("button", { name: "Назначить подписку" }));
  expect(await screen.findByRole("option", { name: "Базовый (30 дн.)" })).toBeInTheDocument();
});

test("tariff create and update send the writable fields expected by the master API", async () => {
  window.history.replaceState({}, "", "/");
  const tariff = { id: 3, name: "Базовый", device_limit: 1, term_days: 30,
    price_amount: null, created_at: "2026-11-08T00:00:00Z" };
  let tariffs: typeof tariff[] = [];
  const writes: Array<{ path: string; method: string; body: unknown }> = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]), { status: 200 });
    if (input === "/api/master-admin/tariffs" && !init?.method) {
      return new Response(JSON.stringify(tariffs), { status: 200 });
    }
    if (input.startsWith("/api/master-admin/tariffs") && init?.method) {
      writes.push({ path: input, method: init.method, body: JSON.parse(String(init.body)) });
      tariffs = [tariff];
      return new Response(JSON.stringify(tariff), { status: init.method === "POST" ? 201 : 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  await userEvent.click(await screen.findByRole("tab", { name: "Тарифы" }));
  await userEvent.click(await screen.findByRole("button", { name: "Добавить тариф" }));
  await userEvent.type(screen.getByRole("textbox", { name: /Название/ }), tariff.name);
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  expect(await screen.findByText(tariff.name)).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Новый тариф" })).not.toBeInTheDocument());
  await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
  await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(writes).toEqual([
    { path: "/api/master-admin/tariffs", method: "POST", body: {
      name: tariff.name, device_limit: 1, term_days: 30, price_amount: null } },
    { path: "/api/master-admin/tariffs/3", method: "PUT", body: {
      name: tariff.name, device_limit: 1, term_days: 30, price_amount: null } },
  ]);
});
