import { expect, test } from "vitest";
import { render, screen } from "@testing-library/react";
import { App } from "./App";

test("login form renders without a session", () => {
  window.history.replaceState({}, "", "/login");
  render(<App />);
  expect(screen.getByRole("button", { name: "Войти" })).toBeEnabled();
});

test("setup form asks for the password twice", () => {
  window.history.replaceState({}, "", "/setup");
  render(<App />);
  expect(screen.getByLabelText("Задайте пароль администратора", { exact: false })).toBeInTheDocument();
  expect(screen.getByLabelText("Повторите пароль", { exact: false })).toBeInTheDocument();
});
