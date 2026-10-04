import { describe, expect, it, vi } from "vitest";
import { api, request } from "../api";
describe("API client", () => {
  it("sends backup password in POST body, never URL", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response('{"versions":[]}'));
    vi.stubGlobal("fetch", fetch);
    await api.backupExport(true, "sample-password");
    expect(fetch).toHaveBeenCalledWith("/api/backup/export", expect.objectContaining({
      method: "POST", body: '{"include_secrets":true,"password":"sample-password"}',
    }));
  });
  it("sends cookies and the exact apply contract", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({ version_id: 7, status: "pending", phases: {} }),
        ),
      );
    vi.stubGlobal("fetch", fetch);
    await api.apply({
      version_id: 7,
      safe_mode: true,
      confirmation_timeout: 180,
    });
    expect(fetch).toHaveBeenCalledWith(
      "/api/apply",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        body: '{"version_id":7,"safe_mode":true,"confirmation_timeout":180}',
        headers: { "Content-Type": "application/json" },
      }),
    );
  });
  it("preserves structured errors and details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "configuration.invalid",
            message: "Неверная конфигурация",
            details: [{ path: ["interfaces"] }],
          }),
          { status: 422 },
        ),
      ),
    );
    await expect(api.versions()).rejects.toMatchObject({
      status: 422,
      code: "configuration.invalid",
      message: "Неверная конфигурация",
      details: [{ path: ["interfaces"] }],
    });
  });
  it("handles non-JSON errors, network failures and empty responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          new Response("proxy unavailable", { status: 502 }),
        )
        .mockRejectedValueOnce(new TypeError("offline"))
        .mockResolvedValueOnce(new Response(null, { status: 204 })),
    );
    await expect(api.versions()).rejects.toMatchObject({ code: "http.502" });
    await expect(api.versions()).rejects.toMatchObject({
      code: "network.unavailable",
    });
    await expect(api.logout()).resolves.toBeUndefined();
  });
  it("rejects malformed success JSON", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("<html/>")));
    await expect(request("/api/versions")).rejects.toMatchObject({
      code: "response.invalid",
    });
  });
  it("uses actual setup, confirm and rollback payloads", async () => {
    const fetch = vi
      .fn()
      .mockImplementation(() => Promise.resolve(new Response("{}")));
    vi.stubGlobal("fetch", fetch);
    await api.setup({ username: "admin", password: "testpassword" });
    await api.confirm(8);
    await api.rollback();
    expect(
      fetch.mock.calls.map(([path, init]) => [path, JSON.parse(init.body)]),
    ).toEqual([
      ["/api/setup", { username: "admin", password: "testpassword" }],
      ["/api/confirm", { version_id: 8 }],
      ["/api/rollback", {}],
    ]);
  });
});
