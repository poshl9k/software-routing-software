import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { emptyConfiguration } from "../fixtures";

it("clears a previously entered static address when the interface is switched to DHCP", async () => {
  const draft = {
    ...emptyConfiguration,
    interfaces: [
      {
        name: "eth0",
        type: "physical",
        zone: "lan",
        description: null,
        addressing: "static",
        addresses: ["192.168.10.5/24"],
        parent: null,
        vlan_id: null,
        members: [],
      },
    ],
  };
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const configuration = init?.body ? JSON.parse(String(init.body)) : draft;
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions"
        ? [version]
        : path === "/api/host/interfaces"
          ? [{ name: "eth0", kind: "physical", parent: null, operstate: "UP" }]
          : version,
    )));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));

  const row = screen.getByDisplayValue("192.168.10.5/24").closest("tr")!;
  // Physical row comboboxes: name, type, zone, mode.
  const mode = within(row).getAllByRole("combobox")[3];
  await user.selectOptions(mode, "DHCP");

  // The address field is emptied and locked while in DHCP mode.
  const address = within(row).getByPlaceholderText("адрес по DHCP");
  expect(address).toBeDisabled();
  expect(address).toHaveValue("");

  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() =>
    expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true),
  );
  const saved = JSON.parse(
    String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body),
  );
  expect(saved.interfaces).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ name: "eth0", addressing: "dhcp", addresses: [] }),
    ]),
  );
});
