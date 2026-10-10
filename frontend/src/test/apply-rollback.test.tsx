import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import App from "../App";
import { emptyConfiguration } from "../fixtures";

const versions = [
  { id: 2, status: "draft", configuration: emptyConfiguration },
  { id: 1, status: "confirmed", configuration: emptyConfiguration },
];
const marker = {
  version_id: 1,
  status: "rolled_back",
  applied_at: Date.now() / 1000,
  deadline: null,
  reason: "agent.reload_failed",
  reason_service: "wireguard",
  phases: { rollback: "rolled_back" },
};

it("shows why a rolled-back apply failed and which service broke", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (path: string) =>
        new Response(
          JSON.stringify(
            path === "/api/versions"
              ? versions
              : path === "/api/auth/me"
                ? { id: 1, username: "admin", role: "admin" }
                : path === "/api/apply/status"
                  ? marker
                  : path === "/api/host/interfaces"
                    ? []
                    : path.startsWith("/api/diff")
                      ? { changes: [], summary: [] }
                    : {},
          ),
        ),
    ),
  );
  render(
    <MemoryRouter initialEntries={["/apply"]}>
      <App />
    </MemoryRouter>,
  );
  // The rolled-back marker alone must surface a warning with the reason and the
  // failing service — not a neutral "Откачено" info line.
  expect(await screen.findByText(/Откачено/)).toBeVisible();
  expect(
    await screen.findByText(/не удалось применить конфигурацию сервиса \(wireguard\)/),
  ).toBeVisible();
});
