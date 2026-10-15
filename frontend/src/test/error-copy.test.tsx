import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "../api";
import { ErrorNotice } from "../components/ErrorNotice";
import { applyErrorText } from "../pages/ApplyScreen";

/** Guard code the operator hit on a first apply: the backend sends the code as the message. */
describe("error copy", () => {
  it("explains a management guard code instead of echoing it twice", () => {
    const text = applyErrorText({
      code: "management.endpoint_required",
      message: "management.endpoint_required",
    });
    expect(text).toContain("адрес панели");
    expect(text.match(/management\.endpoint_required/g)).toHaveLength(1);
  });

  it("explains every management guard the backend can raise", () => {
    for (const code of [
      "management.endpoint_required",
      "management.dhcp_forbidden",
      "management.address_conflict",
      "management.identity_mismatch",
      "management.invalid_address",
      "management.port_reserved",
      "management.site_binding_conflict",
    ]) {
      const text = applyErrorText({ code, message: code });
      expect(text, code).not.toBe(code);
      expect(text, code).toContain(code);
    }
  });

  it("shows an unknown code once, with the server message when it says more", () => {
    expect(applyErrorText({ code: "agent.some_new_code", message: "agent.some_new_code" }))
      .toBe("agent.some_new_code");
    expect(applyErrorText({ code: "agent.some_new_code", message: "сервис не ответил" }))
      .toBe("сервис не ответил · agent.some_new_code");
  });

  it("does not repeat the code in ErrorNotice when it carries no extra text", () => {
    render(
      <MemoryRouter>
        <ErrorNotice error={new ApiError(400, "management.endpoint_required", "management.endpoint_required")} />
      </MemoryRouter>,
    );
    expect(screen.getByText(/management\.endpoint_required/)).toBeVisible();
    expect(screen.getAllByText(/management\.endpoint_required/)).toHaveLength(1);
  });

  it("keeps the raw code when the message explains it", () => {
    render(
      <MemoryRouter>
        <ErrorNotice error={new ApiError(503, "agent.unavailable", "агент недоступен")} />
      </MemoryRouter>,
    );
    expect(screen.getByText(/агент недоступен/)).toBeVisible();
    expect(screen.getByText(/agent\.unavailable/)).toBeVisible();
  });
});
