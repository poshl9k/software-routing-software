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
  it("fetches the structured diff with credentials", async () => {
    const payload = {
      changes: [{ op: "replace", path: "/dhcp_subnets/0/valid_lifetime", before: 3600, after: 7200 }],
      summary: [{ area: "dhcp", title: "DHCP", added: 0, removed: 0, changed: 1, consequences: ["Клиенты получат новый срок аренды"] }],
    };
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    vi.stubGlobal("fetch", fetch);
    await expect(api.diff(3, 4)).resolves.toEqual(payload);
    expect(fetch).toHaveBeenCalledWith("/api/diff/3/4", expect.objectContaining({ credentials: "include" }));
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
  it("subscription calls use typed routes without tokenized URLs in paths", async () => {
    const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response("{}")));
    vi.stubGlobal("fetch", fetch);
    const subscription = { name: "demo", url: "https://example.org/?token=private", format: "auto" as const,
      interval_hours: 24, enabled: true };
    await api.previewSubscription(subscription);
    await api.refreshSubscription("demo");
    await api.subscriptionMembers("demo");
    await api.patchSubscription("demo", { mode: "selector" });
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([
      "/api/proxy/subscriptions/preview", "/api/proxy/subscriptions/demo/refresh",
      "/api/proxy/subscriptions/demo/members", "/api/proxy/subscriptions/demo",
    ]);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ subscription, authorized: true });
    expect(JSON.parse(fetch.mock.calls[1][1].body)).toEqual({ authorized: true });
    expect(fetch.mock.calls[3][1].method).toBe("PATCH");
  });
});
