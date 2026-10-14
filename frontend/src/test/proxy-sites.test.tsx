import { render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { emptyConfiguration } from "../fixtures";
import { DDNS, Sites } from "../pages/ConnectionEditors";
import { RouterProvider } from "../state";
import type { Configuration } from "../types";

function mount(page: React.ReactNode, configuration: Configuration = emptyConfiguration) {
  vi.stubGlobal("fetch", vi.fn(async (path: string) => new Response(JSON.stringify(
    path === "/api/versions" ? [{ id: 1, status: "confirmed", configuration }] : {},
  ))));
  render(<RouterProvider>{page}</RouterProvider>);
}

it("shows a specific empty state for incoming sites", async () => {
  mount(<Sites />);
  expect(await screen.findByText("Сайтов нет. Добавьте сайт.")).toBeVisible();
  expect(screen.queryByText("Нет записей")).not.toBeInTheDocument();
});

it("shows a specific empty state for DDNS", async () => {
  mount(<DDNS />);
  expect(await screen.findByText("Доменов DDNS нет. Добавьте домен.")).toBeVisible();
  expect(screen.queryByText("Нет записей")).not.toBeInTheDocument();
});

it("explains certificate status only once for a configured site", async () => {
  mount(<Sites />, { ...emptyConfiguration, sites: [{
    name: "web", hostname: "home.example.org", upstream: "192.0.2.10:443",
    certificate_mode: "http01", wan_address: null, certificate: null,
    private_key: null, dns_api_token: null,
  }] });
  expect(await screen.findByText("Статус недоступен")).toBeVisible();
  expect(screen.getAllByText(/Состояние сертификата на устройстве панель пока не читает:/)).toHaveLength(1);
  expect(screen.getByText(/выпуск произойдёт при применении/)).toBeVisible();
});
