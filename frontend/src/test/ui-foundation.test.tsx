import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { Button } from "@mui/material";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { PageSection } from "../components/PageSection";
import { StatTile } from "../components/StatTile";
import { InlineStatus } from "../components/InlineStatus";
import { StatusHero } from "../components/StatusHero";
import { ApplyStatusRail } from "../components/ApplyStatusRail";
import { ServiceStatusHeader } from "../components/ServiceStatusHeader";
import { WizardProgress } from "../components/WizardProgress";
import { LoadingSkeleton } from "../components/LoadingSkeleton";
import { ExpertDisclosure } from "../components/ExpertDisclosure";
import { ConfirmDialog } from "../components/ConfirmDialog";

const rail = (props: Parameters<typeof ApplyStatusRail>[0]) => render(<MemoryRouter><ApplyStatusRail {...props} /></MemoryRouter>);

describe("shared P1 primitives", () => {
  it("PageSection uses h2, subtitle and action, never h1", () => {
    const { container } = render(<PageSection title="Сеть" subtitle="Параметры" action={<Button>Открыть</Button>}>Содержимое</PageSection>);
    expect(screen.getByRole("heading", { level: 2, name: "Сеть" })).toBeInTheDocument();
    expect(container.querySelector("h1")).toBeNull();
    expect(screen.getByText("Параметры")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Открыть" })).toBeInTheDocument();
  });
  it("StatTile distinguishes unknown from a real zero and shows timestamp", () => {
    const { rerender } = render(<StatTile label="Аренды" value={null} tone="green" />);
    expect(screen.getByText("Нет данных")).toBeInTheDocument();
    rerender(<StatTile label="Аренды" value={0} hint="За сутки" tone="green" asOf="2026-10-10T10:00:00Z" />);
    expect(screen.queryByText("Нет данных")).not.toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("За сутки")).toBeInTheDocument();
    expect(screen.getByText("2026-10-10T10:00:00Z")).toHaveAttribute("dateTime", "2026-10-10T10:00:00Z");
  });
  it("InlineStatus unknown stays grey, never success; other tones render", () => {
    const { container, rerender } = render(<InlineStatus tone="unknown" text="Состояние неизвестно" />);
    expect(screen.getByText("Состояние неизвестно")).toBeInTheDocument();
    expect(container.querySelector('[aria-hidden="true"]')).toHaveStyle({ backgroundColor: "rgb(138, 143, 152)" });
    for (const tone of ["green", "amber", "red", "blue", "neutral"] as const) {
      rerender(<InlineStatus tone={tone} text="Данные получены" asOf="сегодня" />);
      expect(screen.getByText("Данные получены")).toBeInTheDocument();
    }
  });
  it("StatusHero exposes primary, facts and action without h1", () => {
    const { container } = render(<StatusHero title="Интернет" tone="unknown" primary={null} facts={[{ label: "Порт", value: "wan0" }]} action={<Button>Проверить</Button>} />);
    expect(screen.getByRole("heading", { level: 2, name: "Интернет" })).toBeInTheDocument();
    expect(screen.getByText("Нет данных")).toBeInTheDocument();
    expect(screen.getByText("wan0")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Проверить" })).toBeInTheDocument();
    expect(container.querySelector("h1")).toBeNull();
  });
  it("ApplyStatusRail renders draft, pending timer, running, uncertain, applied and error honestly", () => {
    const { rerender } = rail({ state: "draft", draftVersion: 8, stableVersion: 7 });
    expect(screen.getByText("Черновик v8 не применён")).toBeInTheDocument();
    expect(screen.getByText("Стабильная v7")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Проверить изменения" })).toHaveAttribute("href", "/apply");
    const wrap = (props: Parameters<typeof ApplyStatusRail>[0]) => rerender(<MemoryRouter><ApplyStatusRail {...props} /></MemoryRouter>);
    wrap({ state: "pending", seconds: 65 });
    expect(screen.getByText("Осталось 01:05")).toBeInTheDocument();
    expect(screen.getByText("Ожидается подтверждение").closest('[aria-live="polite"]')).toBeInTheDocument();
    expect(screen.getByText("Осталось 01:05").closest('[aria-live]')).toBeNull();
    wrap({ state: "pending", seconds: 64 });
    expect(screen.getByText("Осталось 01:04")).toBeInTheDocument();
    wrap({ state: "pending", seconds: null });
    expect(screen.getByText("Время до подтверждения недоступно")).toBeInTheDocument();
    wrap({ state: "running" });
    expect(screen.getByText("Применение выполняется")).toBeInTheDocument();
    wrap({ state: "uncertain" });
    expect(screen.getByText("Состояние агента неизвестно")).toBeInTheDocument();
    wrap({ state: "applied", confirmedVersion: 7 });
    expect(screen.getByText("Время подтверждения недоступно")).toBeInTheDocument();
    wrap({ state: "applied", confirmedVersion: 7, confirmedAt: "2026-10-10T10:00:00Z" });
    expect(screen.getByText(/Подтверждена: 2026/)).toBeInTheDocument();
    wrap({ state: "error", message: "Нет ответа" });
    expect(screen.getByText("Нет ответа")).toBeInTheDocument();
  });
  it("ServiceStatusHeader shows unknown, error, metrics and last error link", () => {
    const { rerender } = render(<ServiceStatusHeader name="DNS" state="unknown" />);
    expect(screen.getByText("Состояние неизвестно")).toBeInTheDocument();
    rerender(<ServiceStatusHeader name="DNS" state="error" metrics={[{ label: "Запросы", value: 0 }]} lastErrorLink={{ href: "/events" }} />);
    expect(screen.getByText("Ошибка службы")).toBeInTheDocument();
    expect(screen.getByText("Запросы: 0")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Последняя ошибка" })).toHaveAttribute("href", "/events");
    rerender(<ServiceStatusHeader name="DNS" state="stopped" />);
    expect(screen.getByText("Остановлена")).toBeInTheDocument();
    rerender(<ServiceStatusHeader name="DNS" state="running" asOf="сейчас" />);
    expect(screen.getByText("Работает")).toBeInTheDocument();
  });
  it("WizardProgress names current and next tasks and each step", () => {
    render(<WizardProgress steps={["Учётная запись", "Сеть", "Проверка"]} current={1} />);
    expect(screen.getByText("Сейчас: Сеть")).toBeInTheDocument();
    expect(screen.getByText("Далее: Проверка")).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByText("Сеть", { selector: "li" })).toHaveAttribute("aria-current", "step");
  });
  it("LoadingSkeleton marks loading rather than empty", () => {
    render(<LoadingSkeleton height={180} />);
    expect(screen.getByRole("status", { name: "Загрузка" })).toBeInTheDocument();
    expect(screen.queryByText("Нет данных")).not.toBeInTheDocument();
  });
  it("ExpertDisclosure reveals keyboard-reachable fields", () => {
    render(<ExpertDisclosure><Button>Экспертное поле</Button></ExpertDisclosure>);
    const toggle = screen.getByRole("button", { name: "Показать дополнительные настройки" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    toggle.focus();
    fireEvent.keyDown(toggle, { key: "Enter" });
    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: "Экспертное поле" })).toBeVisible();
  });
  it("ConfirmDialog traps focus and restores trigger after cancel", async () => {
    const cancel = vi.fn();
    const confirm = vi.fn();
    const { rerender } = render(<><button>Открыть</button><ConfirmDialog open={false} title="Удалить интерфейс?" body="Доступ может пропасть" confirmLabel="Удалить" cancelLabel="Отмена" onConfirm={confirm} onCancel={cancel} danger /></>);
    const trigger = screen.getByRole("button", { name: "Открыть" });
    trigger.focus();
    rerender(<><button>Открыть</button><ConfirmDialog open title="Удалить интерфейс?" body="Доступ может пропасть" confirmLabel="Удалить" cancelLabel="Отмена" onConfirm={confirm} onCancel={cancel} danger /></>);
    const dialog = screen.getByRole("dialog", { name: "Удалить интерфейс?" });
    expect(within(dialog).getByText("Доступ может пропасть")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Отмена" })).toHaveFocus();
    fireEvent.click(within(dialog).getByRole("button", { name: "Удалить" }));
    expect(confirm).toHaveBeenCalledOnce();
    fireEvent.click(within(dialog).getByRole("button", { name: "Отмена" }));
    expect(cancel).toHaveBeenCalledOnce();
    rerender(<><button>Открыть</button><ConfirmDialog open={false} title="Удалить интерфейс?" body="Доступ может пропасть" confirmLabel="Удалить" cancelLabel="Отмена" onConfirm={confirm} onCancel={cancel} danger /></>);
    await waitFor(() => expect(trigger).toHaveFocus());
  });
});
