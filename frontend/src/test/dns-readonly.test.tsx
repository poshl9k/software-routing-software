import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { emptyConfiguration } from "../fixtures";
import { DNS } from "../pages/Services";
import { RouterProvider } from "../state";
import type { Configuration, DNSUpstream } from "../types";

function mount(dns: Configuration["dns"] = emptyConfiguration.dns) {
  vi.stubGlobal("fetch", vi.fn((path: string) => Promise.resolve(new Response(JSON.stringify(
    path === "/api/versions"
      ? [{ id: 1, status: "draft", configuration: { ...emptyConfiguration, dns } }]
      : { generated_at: "2026-10-14T10:00:00Z", services: [] },
  )))));
  render(<MemoryRouter><RouterProvider><DNS /></RouterProvider></MemoryRouter>);
}

function card(title: string) {
  const element = screen.getByRole("heading", { name: title }).closest(".card");
  if (!element) throw new Error(`Card missing: ${title}`);
  return within(element as HTMLElement);
}

it("names both empty DNS tables specifically", async () => {
  mount();
  expect(await card("Локальные имена").findByText("Локальных имён нет.")).toBeVisible();
  expect(card("Домены с отдельным DNS").getByText("Доменов с отдельным DNS нет.")).toBeVisible();
  expect(screen.queryByText("Нет записей")).not.toBeInTheDocument();
});

it("labels UDP, DoT and DoH in both DNS server lists", async () => {
  const upstreams: DNSUpstream[] = [
    { address: "192.0.2.53", port: 53, mode: "udp", tls_name: null, doh_server: null },
    { address: "1.1.1.1", port: 853, mode: "tls", tls_name: "cloudflare-dns.com", doh_server: null },
    { address: "", port: 443, mode: "https", tls_name: null, doh_server: "https://dns.google/dns-query" },
  ];
  mount({ ...emptyConfiguration.dns, upstreams, forwards: [{ domain: "corp.example", upstreams }] });
  const expected = "DNS (UDP) · 192.0.2.53:53, DoT · cloudflare-dns.com (1.1.1.1:853), DoH · https://dns.google/dns-query";
  expect(await card("Домены с отдельным DNS").findByText(expected)).toBeVisible();
  expect(card("Режим и доступ").getByText(expected)).toBeVisible();
});

it("shows DoT address without TLS name when none is configured", async () => {
  mount({ ...emptyConfiguration.dns, upstreams: [
    { address: "9.9.9.9", port: 853, mode: "tls", tls_name: null, doh_server: null },
  ] });
  expect(await card("Режим и доступ").findByText("DoT · 9.9.9.9:853")).toBeVisible();
});

it("places the only query-log message in its own card", async () => {
  mount();
  const text = "Просмотр DNS-запросов пока не подключён к API.";
  expect(await card("Журнал запросов DNS").findByText(text)).toBeVisible();
  expect(card("Журнал запросов DNS").getAllByText(text)).toHaveLength(1);
  expect(card("Режим и доступ").queryByText(text)).not.toBeInTheDocument();
  expect(card("Режим и доступ").queryByText("Просмотр DNS-запросов здесь пока недоступен.")).not.toBeInTheDocument();
});
