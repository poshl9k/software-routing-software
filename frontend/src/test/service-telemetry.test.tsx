import { render, screen } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api";
import { makeQueryClient } from "../query";
import { RuntimeServiceInline, useServiceTelemetry } from "../pages/Services";

function Status({ name }: { name: string }) {
  const telemetry = useServiceTelemetry();
  return <RuntimeServiceInline name={name} telemetry={telemetry} />;
}
function mount(name: string) {
  const client = makeQueryClient();
  client.setDefaultOptions({ queries: { retry: false, refetchOnWindowFocus: false } });
  const result = render(<QueryClientProvider client={client}><Status name={name} /></QueryClientProvider>);
  return { ...result, client };
}
afterEach(() => vi.restoreAllMocks());

it("shows loading, then actual state and server timestamp", async () => {
  let resolve!: (value: Awaited<ReturnType<typeof api.serviceStatus>>) => void;
  vi.spyOn(api, "serviceStatus").mockImplementation(() => new Promise((done) => { resolve = done; }));
  const { client } = mount("kea");
  expect(screen.getByText("Статус загружается…")).toBeVisible();
  resolve({ generated_at: "2026-10-10T10:00:00Z", services: [{ name: "kea", state: "stopped", detail: null }] });
  expect(await screen.findByText("Остановлена")).toBeVisible();
  expect(screen.getByText("2026-10-10T10:00:00Z")).toBeVisible();
  client.clear();
});
it("does not show success when service is absent or endpoint fails", async () => {
  vi.spyOn(api, "serviceStatus").mockResolvedValueOnce({ generated_at: "2026-10-10T10:00:00Z", services: [] });
  const first = mount("tunnel:wg0");
  expect(await screen.findByText("Состояние неизвестно")).toBeVisible();
  first.unmount();
  first.client.clear();
  vi.spyOn(api, "serviceStatus").mockRejectedValue(new Error("503"));
  const second = mount("ddns");
  expect(await screen.findByText("Статус недоступен")).toBeVisible();
  expect(screen.queryByText("Работает")).not.toBeInTheDocument();
  second.client.clear();
});
