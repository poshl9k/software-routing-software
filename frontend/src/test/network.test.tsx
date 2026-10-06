import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { expect, it, vi } from "vitest";
import { RouterProvider } from "../state";
import Network from "../pages/Network";
import { emptyConfiguration } from "../fixtures";

it("selects OS links, creates a VLAN and saves bridge members with draft references", async () => {
  const fetch = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    const configuration = init?.body ? JSON.parse(String(init.body)) : emptyConfiguration;
    const version = { id: 1, status: "draft", configuration };
    return Promise.resolve(new Response(JSON.stringify(
      path === "/api/versions" ? [version] : path === "/api/host/interfaces" ? [
        { name: "eth0", kind: "physical", parent: null, operstate: "UP" },
        { name: "eth1", kind: "physical", parent: null, operstate: "DOWN" },
        { name: "bond0", kind: "bond", parent: null, operstate: "UP" },
      ] : version,
    )));
  });
  vi.stubGlobal("fetch", fetch);
  const user = userEvent.setup();
  render(<MemoryRouter><RouterProvider><Network /></RouterProvider></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Редактировать" }));
  await user.click(await screen.findByRole("button", { name: "+ VLAN на eth0" }));
  const vlanRow = screen.getByDisplayValue("vlan1 (в черновике)").closest("tr")!;
  const parent = within(vlanRow).getAllByRole("combobox")[4];
  expect(within(parent).getByRole("option", { name: "eth1" })).toBeVisible();
  expect(within(parent).queryByRole("option", { name: "bond0" })).toBeNull();
  await user.selectOptions(parent, "eth1");
  await user.type(
    within(vlanRow).getByPlaceholderText("напр. «оптика провайдера»"),
    "гостевая сеть",
  );
  await user.click(screen.getByRole("button", { name: "+ Мост" }));
  await user.click(screen.getByRole("button", { name: "+ участник" }));
  const bridgeRow = screen.getByDisplayValue("br1 (в черновике)").closest("tr")!;
  const member = within(bridgeRow).getAllByRole("combobox")[4];
  await user.selectOptions(member, "bond0");
  await user.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(fetch.mock.calls.some(([, init]) => init?.method === "PUT")).toBe(true));
  const saved = JSON.parse(String(fetch.mock.calls.find(([, init]) => init?.method === "PUT")![1].body));
  expect(saved.interfaces).toEqual(expect.arrayContaining([
    expect.objectContaining({ name: "vlan1", type: "vlan", parent: "eth1", vlan_id: 1,
      description: "гостевая сеть" }),
    expect.objectContaining({ name: "br1", type: "bridge", members: ["bond0"] }),
    expect.objectContaining({ name: "eth1", zone: null }),
    expect.objectContaining({ name: "bond0", zone: null }),
  ]));
});
