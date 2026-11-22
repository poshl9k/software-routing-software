import { StrictMode } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const account = { id: 1, display_name: "Анна", email: null };
const hiddenDetail = "synthetic-private-server-detail";
const failure = (status = 400) => json({ error: { code: "auth.invalid_credentials", message: hiddenDetail } }, status);

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

function mount(path: string, fetcher: (input: string, init?: RequestInit) => Promise<Response>, strict = false) {
  window.history.replaceState({}, "", path);
  const mock = vi.fn(fetcher);
  vi.stubGlobal("fetch", mock);
  const view = render(strict ? <StrictMode><App /></StrictMode> : <App />);
  return { mock, ...view };
}

test.each(["known@example.test", "unknown@example.test"])("forgot password gives a generic receipt for %s", async email => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/login?method=password", async () => json({ accepted: true }, 202));
  await user.click(screen.getByRole("link", { name: "Забыли пароль?" }));
  expect(window.location.pathname).toBe("/portal/password/forgot");
  await user.type(screen.getByRole("textbox", { name: /Электронная почта/ }), email);
  await user.click(screen.getByRole("button", { name: "Отправить ссылку" }));
  expect(await screen.findByRole("status")).toHaveTextContent(/Если адрес привязан к аккаунту/);
  expect(mock).toHaveBeenCalledWith("/api/portal/password/forgot", expect.objectContaining({
    method: "POST", credentials: "include", body: JSON.stringify({ email }),
  }));
  expect(screen.getByRole("link", { name: "Вернуться ко входу" })).toHaveAttribute("href", "/portal/login?method=password");
});

test("forgot password fails safely and permits retry without claiming delivery", async () => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/password/forgot", async () => failure(503));
  await user.type(screen.getByRole("textbox", { name: /Электронная почта/ }), "synthetic@example.test");
  await user.click(screen.getByRole("button", { name: "Отправить ссылку" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/Не удалось отправить запрос/);
  expect(screen.queryByRole("status")).not.toBeInTheDocument();
  expect(screen.queryByText(hiddenDetail)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Отправить ссылку" })).toBeEnabled();
  expect(mock).toHaveBeenCalledTimes(1);
});

test.each([null, "verified@example.test"])("email binding keeps verified state %s until confirmation", async email => {
  const user = userEvent.setup();
  const { mock } = mount("/portal", async input => {
    if (input === "/api/portal/me") return json({ account: { ...account, email }, subscription: null });
    if (input === "/api/portal/devices") return json({ devices: [] });
    if (input === "/api/portal/email/request") return json({ accepted: true }, 202);
    throw new Error("Unexpected request");
  });
  const field = await screen.findByRole("textbox", { name: /Электронная почта/ });
  const initial = email ? `Подтверждённая почта: ${email}` : "Почта не привязана";
  expect(screen.getByText(initial)).toBeVisible();
  await user.type(field, "new@example.test");
  await user.click(screen.getByRole("button", { name: "Подтвердить почту" }));
  expect(await screen.findByRole("status")).toHaveTextContent(/Если адрес доступен/);
  expect(screen.getByText(initial)).toBeVisible();
  expect(mock).toHaveBeenCalledWith("/api/portal/email/request", expect.objectContaining({
    method: "POST", credentials: "include", body: JSON.stringify({ email: "new@example.test" }),
  }));
});

test.each([401, 503])("email binding handles HTTP %s safely", async status => {
  const user = userEvent.setup();
  mount("/portal", async input => {
    if (input === "/api/portal/me") return json({ account, subscription: null });
    if (input === "/api/portal/devices") return json({ devices: [] });
    return failure(status);
  });
  await user.type(await screen.findByRole("textbox", { name: /Электронная почта/ }), "new@example.test");
  await user.click(screen.getByRole("button", { name: "Подтвердить почту" }));
  if (status === 401) {
    await waitFor(() => expect(window.location.pathname).toBe("/portal/login"));
    expect(screen.queryByRole("button", { name: "Подтвердить почту" })).not.toBeInTheDocument();
  } else {
    expect(await screen.findByText(/Не удалось отправить запрос/)).toBeVisible();
    expect(screen.getByRole("textbox", { name: /Электронная почта/ })).toHaveValue("new@example.test");
  }
  expect(screen.queryByText(hiddenDetail)).not.toBeInTheDocument();
});

test("email confirmation scrubs the URL before a single unauthenticated JSON POST in StrictMode", async () => {
  const { mock, rerender } = mount("/portal/email/confirm#token=synthetic-email-proof", async () => {
    expect(window.location.hash).toBe("");
    return new Response(null, { status: 204 });
  }, true);
  expect(window.location.hash).toBe("");
  expect(await screen.findByRole("status")).toHaveTextContent("Почта подтверждена");
  rerender(<StrictMode><App /></StrictMode>);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith("/api/portal/email/confirm", expect.objectContaining({
    method: "POST", body: JSON.stringify({ token: "synthetic-email-proof" }),
  }));
  expect(screen.queryByText("synthetic-email-proof")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Открыть кабинет" })).toHaveAttribute("href", "/portal");
});

test.each(["", "#token=", "#token=one&token=two", "?token=not-a-fragment"])("email confirmation rejects missing or ambiguous fragment %s without requesting", async suffix => {
  const { mock } = mount(`/portal/email/confirm${suffix}`, async () => failure());
  expect(await screen.findByRole("alert")).toHaveTextContent(/Ссылка недействительна/);
  expect(mock).not.toHaveBeenCalled();
  expect(window.location.hash).toBe("");
  expect(window.location.search).toBe("");
});

test("email confirmation failure is generic, does not sign in, and never renders backend details", async () => {
  const { mock } = mount("/portal/email/confirm#token=synthetic-expired-proof", async () => failure(401));
  expect(await screen.findByRole("alert")).toHaveTextContent(/Не удалось подтвердить почту/);
  expect(screen.queryByText(hiddenDetail)).not.toBeInTheDocument();
  expect(window.location.pathname).toBe("/portal/email/confirm");
  expect(mock).toHaveBeenCalledTimes(1);
});

test("password option and direct query route log in using the subscriber API", async () => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/login", async input => {
    if (input === "/api/portal/login") return json(account);
    if (input === "/api/portal/me") return json({ account, subscription: null });
    if (input === "/api/portal/devices") return json({ devices: [] });
    throw new Error("Unexpected request");
  });
  expect(screen.getByText(/Откройте ссылку из Telegram-бота/)).toBeVisible();
  await user.click(screen.getByRole("link", { name: "Войти по паролю" }));
  expect(window.location.pathname + window.location.search).toBe("/portal/login?method=password");
  const username = screen.getByRole("textbox", { name: /Имя абонента/ });
  const password = screen.getByLabelText(/^Пароль/);
  expect(username).toHaveAttribute("autocomplete", "username");
  expect(password).toHaveAttribute("autocomplete", "current-password");
  await user.type(username, "Анна");
  await user.type(password, " synthetic-password ");
  await user.click(screen.getByRole("button", { name: "Войти" }));
  expect(await screen.findByRole("heading", { name: "Здравствуйте, Анна" })).toBeVisible();
  expect(mock).toHaveBeenCalledWith("/api/portal/login", expect.objectContaining({
    method: "POST", credentials: "include", body: JSON.stringify({ username: "Анна", password: " synthetic-password " }),
  }));
  expect(window.location.pathname).toBe("/portal");
});

test("failed password login stays in subscriber login and clears the password without exposing details", async () => {
  const user = userEvent.setup();
  mount("/portal/login?method=password", async () => failure(401));
  await user.type(screen.getByRole("textbox", { name: /Имя абонента/ }), "Анна");
  await user.type(screen.getByLabelText(/^Пароль/), "synthetic-password");
  await user.click(screen.getByRole("button", { name: "Войти" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/Не удалось войти/);
  expect(screen.getByLabelText(/^Пароль/)).toHaveValue("");
  expect(screen.queryByText(hiddenDetail)).not.toBeInTheDocument();
  expect(window.location.pathname + window.location.search).toBe("/portal/login?method=password");
});

test("password reset scrubs the token, posts it once and warns about other credentials", async () => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/password/reset#token=one-time-reset-proof", async () => new Response(null, { status: 204 }));
  expect(window.location.hash).toBe("");
  const password = "replacement-test-password";
  await user.type(screen.getByLabelText(/^Новый пароль/), password);
  await user.type(screen.getByLabelText(/^Повторите новый пароль/), password);
  await user.click(screen.getByRole("button", { name: "Сохранить пароль" }));
  expect(await screen.findByRole("status")).toHaveTextContent(/Пароль изменён/);
  expect(screen.getByRole("note")).toHaveTextContent(/сохранённые ссылки доступа.*остаются действительными/i);
  expect(mock).toHaveBeenCalledTimes(1);
  expect(mock).toHaveBeenCalledWith("/api/portal/password/reset", expect.objectContaining({
    method: "POST", credentials: "include",
    body: JSON.stringify({ token: "one-time-reset-proof", password }),
  }));
  expect(screen.queryByText("one-time-reset-proof")).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/^Новый пароль/)).not.toBeInTheDocument();
});

test("password reset mismatch makes no request", async () => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/password/reset#token=synthetic-proof", async () => new Response(null, { status: 204 }));
  await user.type(screen.getByLabelText(/^Новый пароль/), "first-passphrase-123");
  await user.type(screen.getByLabelText(/^Повторите новый пароль/), "second-passphrase-123");
  await user.click(screen.getByRole("button", { name: "Сохранить пароль" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Пароли не совпадают");
  expect(mock).not.toHaveBeenCalled();
});

test("password reset failure is generic, permits retry and hides server details", async () => {
  const user = userEvent.setup();
  const { mock } = mount("/portal/password/reset#token=expired-proof", async () => failure(400));
  await user.type(screen.getByLabelText(/^Новый пароль/), "replacement-test-password");
  await user.type(screen.getByLabelText(/^Повторите новый пароль/), "replacement-test-password");
  await user.click(screen.getByRole("button", { name: "Сохранить пароль" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/Ссылка могла истечь/);
  expect(screen.queryByText(hiddenDetail)).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Сохранить пароль" })).toBeEnabled();
  expect(mock).toHaveBeenCalledTimes(1);
});

test.each(["", "#token=", "#token=first&token=second", "?token=not-a-fragment"])(
  "password reset rejects invalid proof location %s without a request",
  async suffix => {
    const { mock } = mount(`/portal/password/reset${suffix}`, async () => new Response(null, { status: 204 }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Ссылка недействительна/);
    expect(mock).not.toHaveBeenCalled();
    expect(window.location.hash).toBe("");
    expect(window.location.search).toBe("");
  });
