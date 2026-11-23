import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { DataTable } from "../components/DataTable";

it("renders a group gap and a styled row without losing cells", () => {
  render(<DataTable heads={["A", "B"]} rows={[
    ["parent", "one"],
    null,
    { className: "vlan-child-row", cells: ["child", "two"] },
  ]} />);

  const rows = document.querySelectorAll("tbody tr");
  expect(rows).toHaveLength(3);
  expect(rows[1]).toHaveAttribute("aria-hidden", "true");
  expect(rows[1].querySelector("td")).toHaveAttribute("colspan", "2");
  expect(rows[2]).toHaveClass("vlan-child-row");
  expect(screen.getByText("child")).toBeInTheDocument();
});
