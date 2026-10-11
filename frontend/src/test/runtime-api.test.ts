import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";

afterEach(() => vi.unstubAllGlobals());

it("uses authenticated runtime GET endpoints and bounded log query", async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response("{}")));
  vi.stubGlobal("fetch", fetch);
  await api.runtimeEngine();
  await api.runtimeConnections();
  await api.runtimeLogs("warning", 200);
  await api.runtimeProxies();
  await api.runtimeProxyDelay("my-group", "https://example.com/204", 1500);
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    "/api/runtime/engine", "/api/runtime/connections", "/api/runtime/logs?level=warning&limit=200",
    "/api/runtime/proxies", "/api/runtime/proxies/my-group/delay?url=https%3A%2F%2Fexample.com%2F204&timeout_ms=1500",
  ]);
  expect(fetch.mock.calls.every(([, init]) => init.credentials === "include")).toBe(true);
});

it("encodes path segments and sends explicit POST bodies for runtime controls", async () => {
  const fetch = vi.fn().mockImplementation(() => Promise.resolve(new Response("{}")));
  vi.stubGlobal("fetch", fetch);
  await api.runtimeEngineControl("restart");
  await api.runtimeCloseConnection("a/b");
  await api.runtimeSelectProxy("group/name", "proxy-a");
  expect(fetch.mock.calls.map(([url, init]) => [url, init.method, JSON.parse(init.body)])).toEqual([
    ["/api/runtime/engine/restart", "POST", {}],
    ["/api/runtime/connections/a%2Fb/close", "POST", {}],
    ["/api/runtime/proxies/group%2Fname/select", "POST", { name: "proxy-a" }],
  ]);
});
