import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ChipToggle } from "./ChipToggle";

describe("ChipToggle", () => {
  it("exposes selection state and toggles on click", async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();
    render(<ChipToggle label="blocked_domains" selected={false} title="srs · https://example.org/b.srs" onClick={onClick} />);
    const chip = screen.getByRole("button", { name: "blocked_domains" });
    expect(chip).toHaveAttribute("aria-pressed", "false");
    expect(chip).toHaveAttribute("title", "srs · https://example.org/b.srs");
    await user.click(chip);
    expect(onClick).toHaveBeenCalledOnce();
  });
});
