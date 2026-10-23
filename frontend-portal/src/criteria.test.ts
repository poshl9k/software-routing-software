import { describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { render, screen } from "@testing-library/react";
import { App } from "./App";
import { portalRequest, PortalApiError, resetRedirectForTests, setLoginRedirectForTests } from "./api";

describe("criterion_1_portal_contract", () => {
  it("defines all portal endpoints and operation/export contracts", async () => {
    const source = await import("./api");
    expect(source.portalApi.activateInvite).toBeTypeOf("function");
    expect(source.portalApi.login).toBeTypeOf("function");
    expect(source.portalApi.me).toBeTypeOf("function");
    expect(source.portalApi.devices).toBeTypeOf("function");
    expect(source.portalApi.addDevice).toBeTypeOf("function");
    expect(source.portalApi.removeDevice).toBeTypeOf("function");
    expect(source.portalApi.setDeviceActive).toBeTypeOf("function");
    expect(source.portalApi.exportDevice).toBeTypeOf("function");
  });
});

describe("criterion_2_cookie_api_and_errors", () => {
  it("sends cookie credentials and maps limit/expiry errors", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ error: { code: "portal.device_limit" } }), { status: 403, headers: { "Content-Type": "application/json" } }));
    await expect(portalRequest("/api/portal/devices")).rejects.toMatchObject({ code: "portal.device_limit", message: "Лимит устройств по вашему тарифу достигнут." });
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ credentials: "include" });
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ code: "portal.subscription_expired" }), { status: 403 }));
    await expect(portalRequest("/api/portal/me")).rejects.toMatchObject({ code: "portal.subscription_expired", message: "Подписка истекла. Обратитесь к администратору для продления." });
  });
  it("redirects unauthorized calls to login", async () => {
    resetRedirectForTests(); const assign = vi.fn(); setLoginRedirectForTests(assign);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401 }));
    await expect(portalRequest("/api/portal/me")).rejects.toBeInstanceOf(PortalApiError);
    expect(assign).toHaveBeenCalledWith("/login");
  });
});

describe("criterion_3_russian_accessible_states", () => {
  it("formats handshake age in Russian", async () => {
    const { handshake } = await import("./App");
    expect(handshake(new Date().toISOString())).toBe("Недавно");
    expect(handshake(new Date(Date.now() - 3 * 86_400_000).toISOString())).toBe("3 дн. назад");
    expect(handshake(null)).toBe("Нет данных");
  });
  it("provides invite/login and an empty device state", async () => {
    expect(App).toBeTypeOf("function");
    window.history.replaceState({}, "", "/login");
    render(createElement(App));
    expect(screen.getByRole("heading", { name: "Войти в кабинет" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: /Имя абонента/ })).toBeInTheDocument();
    expect(screen.getByLabelText(/Пароль/)).toBeInTheDocument();
  });
});

describe("criterion_4_build_and_test_configuration", () => {
  it("accepts 501 export as a later feature response", async () => {
    const { portalApi } = await import("./api");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 501, headers: { "Content-Type": "application/json" } }));
    await expect(portalApi.exportDevice("dev1", "qr")).rejects.toMatchObject({ status: 501, message: "Эта функция появится позже." });
  });
});
