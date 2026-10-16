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

  it("explains an unresolved client tunnel endpoint with a next step and one code", () => {
    const code = "wireguard.endpoint_unresolved";
    const text = applyErrorText({ code, message: code });
    expect(text).toContain("проверьте имя сервера, DNS и доступ к сети");
    expect(text.match(/wireguard\.endpoint_unresolved/g)).toHaveLength(1);
  });

  it("explains an agent command timeout with a next step and one code", () => {
    const code = "agent.command_timeout";
    const text = applyErrorText({ code, message: code });
    expect(text).toContain("проверьте состояние агента и сервисов");
    expect(text.match(/agent\.command_timeout/g)).toHaveLength(1);
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
      "management.state_missing",
      "management.domain_unresolved",
      "management.domain_unverified",
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

  it("surfaces the host reason for an unexpected agent failure", () => {
    // agent.apply_failed used to be a dead end: the marker dropped the reason.
    const text = applyErrorText({
      code: "agent.apply_failed",
      message: "agent.apply_failed",
      details: ["FileNotFoundError: [Errno 2] /etc/kea/kea-api-password"],
    });
    expect(text).toContain("внутренней ошибкой агента");
    expect(text).toContain("/etc/kea/kea-api-password");
    expect(text.match(/agent\.apply_failed/g)).toHaveLength(1);
  });

  it("explains a missing Kea API credential as an installation gap", () => {
    const code = "kea.api_password_missing";
    const text = applyErrorText({ code, message: code });
    expect(text).toContain("kea-api-password");
    expect(text).toContain(code);
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
