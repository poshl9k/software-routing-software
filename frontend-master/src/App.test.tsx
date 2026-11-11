import { afterEach, expect, test, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
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
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [] }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  expect(await screen.findByText("Подписка пока не активна")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Здравствуйте, Анна" })).toBeInTheDocument();
  expect(screen.queryByText("Ноды")).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/portal/login/magic", expect.anything());
});

test("a stable cabinet link signs in through the non-single-use endpoint", async () => {
  window.history.replaceState({}, "", "/login#link=stable-token");
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/login/link") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" } }), { status: 200 });
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: null }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [] }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  expect(await screen.findByText("Здравствуйте, Анна")).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/portal/login/link", expect.anything());
  expect(fetcher).not.toHaveBeenCalledWith("/api/portal/login/magic", expect.anything());
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

test("active subscriber can create a device and download its config", async () => {
  window.history.replaceState({}, "", "/portal");
  let devices = [{ id: 7, name: "master_7", label: "Телефон", status: "active",
    allowed_ips: ["10.66.0.7/32"], applied: true, last_handshake: null }];
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" },
      subscription: { status: "active", expires_at: "2026-12-08T00:00:00Z",
        tariff: { name: "Базовый", device_limit: 2, term_days: 30 } },
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
  expect(screen.getByRole("button", { name: "Скачать .conf" })).toBeEnabled();
  await userEvent.click(screen.getByRole("button", { name: "Добавить устройство" }));
  await userEvent.type(screen.getByRole("textbox", { name: "Метка устройства" }), "Ноутбук");
  await userEvent.click(screen.getByRole("button", { name: "Добавить" }));
  expect(await screen.findByText(/Ноутбук/)).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/portal/devices", expect.objectContaining({ method: "POST" }));
});

test("subscriber cabinet matches the node's subscription and device layout", async () => {
  window.history.replaceState({}, "", "/portal");
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" },
      subscription: { status: "active", expires_at: "2099-12-08T00:00:00Z",
        tariff: { name: "Базовый", device_limit: 3, term_days: 30 } },
    }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null },
      { id: 8, name: "master_8", label: "Ноутбук", status: "inactive", applied: false, last_handshake: null },
    ] }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Здравствуйте, Анна" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /VS PORTAL/ })).toHaveAttribute("href", "/portal");
  expect(screen.getByText(/На этом тарифе разрешено 3 устройства/)).toBeInTheDocument();
  expect(screen.getByText(/Используется: 2/)).toBeInTheDocument();
  expect(screen.getByText("Включено")).toBeInTheDocument();
  expect(screen.getByText("Отключено")).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "QR" })[0]).toBeEnabled();
  expect(screen.getAllByRole("button", { name: "QR" })[1]).toBeEnabled();
  expect(screen.getAllByRole("button", { name: "Amnezia" })[0]).toBeEnabled();
  expect(screen.getByRole("button", { name: "Деактивировать" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Активировать" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Добавить устройство" })).toBeEnabled();
});

test("subscriber can view QR, deactivate and remove a device through the master API", async () => {
  window.history.replaceState({}, "", "/portal");
  const objectUrl = vi.fn(() => "blob:synthetic-qr");
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: objectUrl });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  let devices = [{ id: 7, name: "master_7", label: "Телефон", status: "active",
    applied: true, last_handshake: null }];
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } },
    }), { status: 200 });
    if (input === "/api/portal/devices" && !init?.method) return new Response(JSON.stringify({ devices }), { status: 200 });
    if (input === "/api/portal/devices/7/export?format=qr") {
      return new Response(new Uint8Array([137, 80, 78, 71]), { status: 200, headers: { "Content-Type": "image/png" } });
    }
    if (input === "/api/portal/devices/7/deactivate") {
      devices = [{ ...devices[0], status: "inactive", applied: false }];
      return new Response(JSON.stringify({ status: "applied", operation_id: 9, device_id: 7 }), { status: 200 });
    }
    if (input === "/api/portal/devices/7" && init?.method === "DELETE") {
      devices = [];
      return new Response(JSON.stringify({ status: "applied", operation_id: 10, device_id: 7 }), { status: 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "QR" }));
    expect(await screen.findByRole("dialog", { name: "QR: Телефон" })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /QR-код конфигурации/ })).toHaveAttribute("src", "blob:synthetic-qr");
    await userEvent.click(screen.getByRole("button", { name: "Закрыть" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Деактивировать" }));
    expect(await screen.findByText("Отключено")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Удалить устройство Телефон" }));
    expect(await screen.findByRole("dialog", { name: "Удалить устройство?" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Удалить устройство" }));
    expect(await screen.findByText("Устройств пока нет")).toBeInTheDocument();
    expect(fetcher).toHaveBeenCalledWith("/api/portal/devices/7/deactivate", expect.objectContaining({ method: "POST" }));
    expect(fetcher).toHaveBeenCalledWith("/api/portal/devices/7", expect.objectContaining({ method: "DELETE" }));
  } finally {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  }
});

test("clash export downloads a mihomo yaml profile from the master API", async () => {
  window.history.replaceState({}, "", "/portal");
  const objectUrl = vi.fn(() => "blob:synthetic-yaml");
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: objectUrl });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } } }),
      { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null }] }),
      { status: 200 });
    if (input === "/api/portal/devices/7/export?format=mihomo") return new Response(
      'mode: "rule"\n', { status: 200, headers: { "Content-Type": "application/yaml" } });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Clash / mihomo" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
      "/api/portal/devices/7/export?format=mihomo", expect.anything()));
    expect(objectUrl).toHaveBeenCalled();
  } finally {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  }
});

test("vless export downloads the iOS link from the master API", async () => {
  window.history.replaceState({}, "", "/portal");
  const objectUrl = vi.fn(() => "blob:synthetic-link");
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: objectUrl });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } } }),
      { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null }] }),
      { status: 200 });
    if (input === "/api/portal/devices/7/export?format=vless") return new Response(
      "vless://uuid@203.0.113.9:443?security=reality", { status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" } });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "VLESS / iOS" }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
      "/api/portal/devices/7/export?format=vless", expect.anything()));
    expect(objectUrl).toHaveBeenCalled();
  } finally {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  }
});

test("subscriber issues a revocable subscription link and can open it in Clash", async () => {
  window.history.replaceState({}, "", "/portal");
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } } }),
      { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null }] }),
      { status: 200 });
    if (input === "/api/portal/devices/7/subscription" && !init?.method) return new Response(
      JSON.stringify({ active: false, created_at: null, last_used_at: null }), { status: 200 });
    if (input === "/api/portal/devices/7/subscription" && init?.method === "POST") return new Response(
      JSON.stringify({ url: "https://master.test/api/portal/sub/token-abc", created_at: "2026-11-10T00:00:00Z",
        qr: "data:image/png;base64,AAA",
        clash_url: "clash://install-config?url=https://master.test/api/portal/sub/token-abc" }),
      { status: 201 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Ссылка-подписка" }));
  expect(await screen.findByRole("dialog", { name: /Ссылка-подписка: Телефон/ })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Создать ссылку" }));
  const field = await screen.findByLabelText("Ссылка");
  expect(field).toHaveValue("https://master.test/api/portal/sub/token-abc");
  expect(screen.getByRole("img", { name: "QR-код ссылки-подписки" }))
    .toHaveAttribute("src", "data:image/png;base64,AAA");
  expect(screen.getByRole("link", { name: "Добавить в Clash" })).toHaveAttribute(
    "href", "clash://install-config?url=https://master.test/api/portal/sub/token-abc");
});

test("amnezia connection is added by button or by scanning its QR code", async () => {
  window.history.replaceState({}, "", "/portal");
  const objectUrl = vi.fn((blob: Blob) => `blob:${blob.type}`);
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: objectUrl });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } } }),
      { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null }] }),
      { status: 200 });
    if (input === "/api/portal/devices/7/export?format=amnezia") return new Response(
      "vpn://container", { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } });
    if (input === "/api/portal/devices/7/export?format=amnezia-qr") return new Response(
      new Uint8Array([137, 80, 78, 71]), { status: 200, headers: { "Content-Type": "image/png" } });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  try {
    render(<App />);
    await userEvent.click(await screen.findByRole("button", { name: "Amnezia" }));
    expect(await screen.findByRole("dialog", { name: /Подключение в Amnezia: Телефон/ })).toBeInTheDocument();
    expect(await screen.findByRole("img", { name: /QR-код подключения Amnezia/ }))
      .toHaveAttribute("src", "blob:image/png");
    expect(screen.getByRole("link", { name: "Открыть в Amnezia" })).toHaveAttribute("href", "vpn://container");
    // Close while the URL stubs still exist: the dialog revokes its blob on unmount.
    await userEvent.click(screen.getByRole("button", { name: "Закрыть" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  } finally {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  }
});

test("an existing subscription link is shown as-is and rotates only on request", async () => {
  window.history.replaceState({}, "", "/portal");
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 2, term_days: 30 } } }),
      { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null }] }),
      { status: 200 });
    if (input === "/api/portal/devices/7/subscription") return new Response(JSON.stringify({
      active: true, created_at: "2026-11-10T00:00:00Z", last_used_at: null,
      url: "https://master.test/api/portal/sub/stable-token",
      qr: "data:image/png;base64,STABLE",
      clash_url: "clash://install-config?url=https://master.test/api/portal/sub/stable-token" }),
      { status: 200 });
    if (input === "/api/portal/devices/7/subscription/rotate") return new Response(JSON.stringify({
      created: true, created_at: "2026-11-11T00:00:00Z", last_used_at: null,
      url: "https://master.test/api/portal/sub/rotated-token",
      qr: "data:image/png;base64,ROTATED",
      clash_url: "clash://install-config?url=https://master.test/api/portal/sub/rotated-token" }),
      { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "Ссылка-подписка" }));
  const field = await screen.findByLabelText("Ссылка");
  expect(field).toHaveValue("https://master.test/api/portal/sub/stable-token");
  expect(screen.getByRole("img", { name: "QR-код ссылки-подписки" })).toHaveAttribute("src", "data:image/png;base64,STABLE");
  // Opening the dialog must not rotate anything.
  expect(fetcher).not.toHaveBeenCalledWith("/api/portal/devices/7/subscription/rotate", expect.anything());
  await userEvent.click(screen.getByRole("button", { name: "Перевыпустить" }));
  expect(screen.getByText(/Перевыпуск сделает текущую ссылку недействительной/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Подтвердить перевыпуск" }));
  await waitFor(() => expect(field).toHaveValue("https://master.test/api/portal/sub/rotated-token"));
});

test("no subscription never claims access or enables new devices", async () => {
  window.history.replaceState({}, "", "/portal");
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: null,
    }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [] }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  expect(await screen.findByText("Подписка пока не активна")).toBeInTheDocument();
  expect(screen.queryByText("Активна")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Добавить устройство" })).toBeDisabled();
});

test("admin lists and publishes rule-set versions", async () => {
  window.history.replaceState({}, "", "/");
  let listing = { rulesets: [{ id: 1, kind: "domain", version: "ru-2026-11-01", entries: 2,
    sha256: "a".repeat(64), created_at: "2026-11-10T00:00:00Z" }],
    current: { domain: { kind: "domain", version: "ru-2026-11-01", entries: 2, sha256: "a".repeat(64) },
      ipcidr: null } };
  const published: unknown[] = [];
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]), { status: 200 });
    if (input === "/api/master-admin/rulesets" && !init?.method) return new Response(
      JSON.stringify(listing), { status: 200 });
    if (input === "/api/master-admin/rulesets" && init?.method === "POST") {
      published.push(JSON.parse(String(init.body)));
      listing = { ...listing, rulesets: [
        { id: 2, kind: "ipcidr", version: "ru-ips-1", entries: 1, sha256: "b".repeat(64),
          created_at: "2026-11-10T00:00:00Z" }, ...listing.rulesets] };
      return new Response(JSON.stringify({ id: 2 }), { status: 201 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  await userEvent.click(await screen.findByRole("tab", { name: "Правила" }));
  expect(await screen.findByText(/ru-2026-11-01 · 2 записей/)).toBeInTheDocument();
  await userEvent.type(screen.getByRole("textbox", { name: "Версия" }), "ru-ips-1");
  await userEvent.type(screen.getByRole("textbox", { name: "Содержимое" }), "5.5.5.0/24");
  await userEvent.click(screen.getByRole("button", { name: "Опубликовать" }));
  await waitFor(() => expect(published).toHaveLength(1));
  expect(published[0]).toEqual({ kind: "domain", version: "ru-ips-1",
    content: "5.5.5.0/24", source: "ru-domains" });
});

test("inactive devices still use a tariff slot; expired entitlement blocks exports", async () => {
  window.history.replaceState({}, "", "/portal");
  let expired = false;
  const fetcher = vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: {
        status: expired ? "expired" : "active", expires_at: "2099-12-08T00:00:00Z",
        tariff: { name: "Базовый", device_limit: 2, term_days: 30 },
      },
    }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true },
      { id: 8, name: "master_8", label: "Ноутбук", status: "inactive", applied: false },
    ] }), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const view = render(<App />);
  expect(await screen.findByText(/Используется: 2/)).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Добавить устройство" })).toBeDisabled();
  expect(screen.getAllByRole("button", { name: "QR" })[1]).toBeEnabled();
  expired = true;
  view.unmount();
  render(<App />);
  expect(await screen.findByText(/Подписка истекла/)).toBeInTheDocument();
  expect(screen.getAllByRole("button", { name: "QR" })[1]).toBeDisabled();
  expect(fetcher).not.toHaveBeenCalledWith("/api/portal/devices/8/export?format=qr", expect.anything());
});

test("device load failure shows a safe error and allows refresh", async () => {
  window.history.replaceState({}, "", "/portal");
  let attempts = 0;
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: null,
    }), { status: 200 });
    if (input === "/api/portal/devices") {
      attempts += 1;
      if (attempts === 1) return new Response(JSON.stringify({
        error: { code: "portal.internal_unavailable", message: "secret-detail-do-not-show" },
      }), { status: 503 });
      return new Response(JSON.stringify({ devices: [] }), { status: 200 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  expect(await screen.findByRole("button", { name: "Обновить" })).toBeInTheDocument();
  expect(screen.queryByText("secret-detail-do-not-show")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Обновить" }));
  expect(await screen.findByText("Устройств пока нет")).toBeInTheDocument();
});

test("failed configuration export never renders raw network exception details", async () => {
  window.history.replaceState({}, "", "/portal");
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" }, subscription: { status: "active",
        expires_at: "2099-12-08T00:00:00Z", tariff: { name: "Базовый", device_limit: 1, term_days: 30 } },
    }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true },
    ] }), { status: 200 });
    if (input === "/api/portal/devices/7/export?format=qr") throw new Error("secret-private");
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  await userEvent.click(await screen.findByRole("button", { name: "QR" }));
  expect(await screen.findByText(/Не удалось скачать конфигурацию/)).toBeInTheDocument();
  expect(screen.queryByText("secret-private")).not.toBeInTheDocument();
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
  const node = { id: 5, name: "rg3", bridge_url: "https://rg3.poshl9k.ru",
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
  const bridgeUrlField = screen.getByRole("textbox", { name: /Bridge URL ноды/ });
  expect(bridgeUrlField).toHaveAttribute("name", "node-bridge-url");
  expect(bridgeUrlField).toHaveAttribute("autocomplete", "off");
  expect(screen.getByText(/Например, https:\/\/rg3\.poshl9k\.ru/)).toBeVisible();
  await userEvent.type(screen.getByRole("textbox", { name: /Имя ноды/ }), node.name);
  await userEvent.type(bridgeUrlField, node.bridge_url);
  await userEvent.click(screen.getByRole("button", { name: "Создать" }));
  expect(await screen.findByText("synthetic-one-time-token")).toBeInTheDocument();
  expect(screen.getByRole("dialog", { name: `Токен ноды ${node.name}` })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Открыть панель ноды" })).toHaveAttribute("href", node.bridge_url);
  expect(screen.getByText(/без SSH/i)).toBeInTheDocument();
  expect(screen.queryByText(/ssh -i/i)).not.toBeInTheDocument();
});

test("node creation blocks insecure and path-prefixed bridge URLs before submitting", async () => {
  window.history.replaceState({}, "", "/");
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]), { status: 200 });
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Добавить ноду" }));
  await user.type(screen.getByRole("textbox", { name: /Имя ноды/ }), "rg4");
  const bridgeUrl = screen.getByRole("textbox", { name: /Bridge URL ноды/ });
  await user.type(bridgeUrl, "http://rg4.example");
  expect(screen.getByRole("button", { name: "Создать" })).toBeDisabled();
  await user.clear(bridgeUrl);
  await user.type(bridgeUrl, "https://rg4.example/internal");
  expect(screen.getByRole("button", { name: "Создать" })).toBeDisabled();
  await user.clear(bridgeUrl);
  await user.type(bridgeUrl, "https://rg4.example");
  expect(screen.getByRole("button", { name: "Создать" })).toBeEnabled();
});

test("admin can reissue a lost token only through the unseen-node recovery action", async () => {
  window.history.replaceState({}, "", "/");
  const node = { id: 5, name: "rg3", bridge_url: "https://rg3.poshl9k.ru",
    capacity: 20, enabled: true, state: "down", active_peers: 0, last_seen: null };
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes" && !init?.method) return new Response(JSON.stringify([node]));
    if (input === "/api/master-admin/nodes/5/reissue-token" && init?.method === "POST") {
      return new Response(JSON.stringify({ token: "synthetic-reissued-token" }));
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Переиздать токен для rg3" }));
  const confirmation = screen.getByRole("dialog", { name: "Переиздать токен?" });
  expect(confirmation).toHaveTextContent("нода ещё не связывалась с мастером");
  await user.click(within(confirmation).getByRole("button", { name: "Переиздать токен" }));
  expect(await screen.findByText("synthetic-reissued-token")).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/master-admin/nodes/5/reissue-token", expect.objectContaining({ method: "POST" }));
});

test("explains why a token cannot be reissued after node use or device assignment", async () => {
  window.history.replaceState({}, "", "/");
  const node = { id: 5, name: "rg3", bridge_url: "https://rg3.poshl9k.ru",
    capacity: 20, enabled: true, state: "down", active_peers: 0, last_seen: null };
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes" && !init?.method) return new Response(JSON.stringify([node]));
    if (input === "/api/master-admin/nodes/5/reissue-token") {
      return new Response(JSON.stringify({ error: { code: "master.node_reissue_not_allowed" } }), { status: 409 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("button", { name: "Переиздать токен для rg3" }));
  const confirmation = screen.getByRole("dialog", { name: "Переиздать токен?" });
  await user.click(within(confirmation).getByRole("button", { name: "Переиздать токен" }));
  expect(await screen.findByText(/Переиздание недоступно/)).toBeInTheDocument();
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

test("admin can create an unlinked subscriber by Telegram ID", async () => {
  window.history.replaceState({}, "", "/");
  const subscriber = { id: 8, display_name: "Тестовый абонент", telegram_chat_id: "987654321",
    status: "active", subscription: null, device_count: 0 };
  let subscribers: typeof subscriber[] = [];
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]));
    if (input === "/api/master-admin/subscribers" && !init?.method) {
      return new Response(JSON.stringify(subscribers));
    }
    if (input === "/api/master-admin/subscribers" && init?.method === "POST") {
      expect(JSON.parse(String(init.body))).toEqual({
        display_name: "Тестовый абонент", telegram_chat_id: "987654321",
      });
      subscribers = [subscriber];
      return new Response(JSON.stringify(subscriber), { status: 201 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("tab", { name: "Абоненты" }));
  expect(await screen.findByText("Абонентов пока нет.")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Добавить абонента" }));
  const dialog = screen.getByRole("dialog", { name: "Новый абонент" });
  await user.type(within(dialog).getByRole("textbox", { name: "Имя абонента" }), subscriber.display_name);
  await user.type(within(dialog).getByRole("textbox", { name: "Telegram ID" }), subscriber.telegram_chat_id);
  await user.click(within(dialog).getByRole("button", { name: "Создать" }));
  expect(await screen.findByText("Тестовый абонент")).toBeInTheDocument();
  expect(screen.getByText(/Подписка не назначена/)).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith("/api/master-admin/subscribers", expect.objectContaining({ method: "POST" }));
});

test("subscriber duplicate error clears when the Telegram ID is corrected", async () => {
  window.history.replaceState({}, "", "/");
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/master-admin/nodes") return new Response(JSON.stringify([]));
    if (input === "/api/master-admin/subscribers" && !init?.method) return new Response(JSON.stringify([]));
    if (input === "/api/master-admin/subscribers" && init?.method === "POST") {
      return new Response(JSON.stringify({ error: { code: "master.subscriber_exists" } }), { status: 409 });
    }
    throw new Error(`Unexpected request ${input}`);
  }));
  render(<App />);
  const user = userEvent.setup();
  await user.click(await screen.findByRole("tab", { name: "Абоненты" }));
  await user.click(screen.getByRole("button", { name: "Добавить абонента" }));
  const dialog = screen.getByRole("dialog", { name: "Новый абонент" });
  await user.type(within(dialog).getByRole("textbox", { name: "Имя абонента" }), "Тестовый");
  const telegramId = within(dialog).getByRole("textbox", { name: "Telegram ID" });
  await user.type(telegramId, "987654321");
  await user.click(within(dialog).getByRole("button", { name: "Создать" }));
  expect(await within(dialog).findByText(/Абонент с таким Telegram ID уже существует/)).toBeInTheDocument();
  expect(telegramId).toHaveFocus();
  await user.clear(telegramId);
  await user.type(telegramId, "987654322");
  expect(within(dialog).queryByText(/Абонент с таким Telegram ID уже существует/)).not.toBeInTheDocument();
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

test("cabinet offers the sing-box profile of the same subscription link", async () => {
  window.history.replaceState({}, "", "/portal");
  let issued: { url: string; singbox_url: string; qr: string | null; clash_url: string;
    created_at: string } | null = null;
  const fetcher = vi.fn(async (input: string, init?: RequestInit) => {
    if (input === "/api/portal/me") return new Response(JSON.stringify({
      account: { id: 1, display_name: "Анна" },
      subscription: { status: "active", expires_at: "2099-12-08T00:00:00Z",
        tariff: { name: "Базовый", device_limit: 3, term_days: 30 } },
    }), { status: 200 });
    if (input === "/api/portal/devices") return new Response(JSON.stringify({ devices: [
      { id: 7, name: "master_7", label: "Телефон", status: "active", applied: true, last_handshake: null },
    ] }), { status: 200 });
    if (input === "/api/portal/devices/7/subscription" && !init?.method) {
      return new Response(JSON.stringify(issued ?? { active: false, created_at: null,
        last_used_at: null, url: null, qr: null, clash_url: null, singbox_url: null }),
      { status: 200 });
    }
    if (input === "/api/portal/devices/7/subscription" && init?.method === "POST") {
      issued = { url: "https://master.test/api/portal/sub/token", qr: null,
        clash_url: "clash://install-config?url=https://master.test/api/portal/sub/token",
        singbox_url: "https://master.test/api/portal/sub/token?format=singbox",
        created_at: "2026-11-11T00:00:00Z" };
      return new Response(JSON.stringify({ created: true, ...issued }), { status: 201 });
    }
    throw new Error(`Unexpected request ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<App />);
  await userEvent.click((await screen.findAllByRole("button", { name: "Ссылка-подписка" }))[0]);
  await userEvent.click(await screen.findByRole("button", { name: "Создать ссылку" }));
  // One credential, two profiles: the sing-box URL is the same token with
  // ?format=singbox, so rotation and revocation cover both at once.
  const singbox = await screen.findByRole("textbox", { name: "Ссылка для sing-box" });
  expect(singbox).toHaveValue("https://master.test/api/portal/sub/token?format=singbox");
  expect(screen.getByRole("button", { name: "Скопировать sing-box" })).toBeEnabled();
  expect(screen.getByRole("textbox", { name: "Ссылка" })).toHaveValue(
    "https://master.test/api/portal/sub/token");
});
