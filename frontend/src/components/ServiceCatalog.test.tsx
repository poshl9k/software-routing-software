import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { ServiceCatalog } from "./ServiceCatalog";

const { presetCatalog } = vi.hoisted(() => ({ presetCatalog: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, presetCatalog } };
});

const catalog = {
  categories: [{ key: "video", title: "Видео", count: 2 }, { key: "social", title: "Соцсети", count: 1 }],
  services: [
    { id: "video", name: "Видеосервисы", category: "video", icon_slug: "video", notice: "Группа видео", covers: ["youtube"], dns_domains: [], rule_sets: [{ tag: "video-set", url: "https://example.test/video", format: "srs" }], action: "route", declared: false },
    { id: "youtube", name: "YouTube", category: "video", icon_slug: "youtube", notice: "Видеохостинг", covers: [], dns_domains: [], rule_sets: [{ tag: "youtube-set", url: "https://example.test/youtube", format: "srs" }], action: "route", declared: false },
    { id: "telegram", name: "Telegram", category: "social", icon_slug: "telegram", notice: "Мессенджер", covers: [], dns_domains: [], rule_sets: [{ tag: "telegram-set", url: "https://example.test/telegram", format: "srs" }], action: "route", declared: false },
  ],
};

function setup(declaredTags: string[] = []) {
  const onSelect = vi.fn();
  const onClose = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><ServiceCatalog open onClose={onClose} onSelect={onSelect} declaredTags={declaredTags} /></QueryClientProvider>);
  return { onSelect, onClose };
}

beforeEach(() => { presetCatalog.mockReset(); presetCatalog.mockResolvedValue(catalog); });

it("searches live and filters category chips with server counts", async () => {
  setup();
  expect(await screen.findByRole("checkbox", { name: "YouTube" })).toBeInTheDocument();
  fireEvent.click(screen.getByText("Соцсети (1)"));
  expect(screen.getByRole("checkbox", { name: "Telegram" })).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: "YouTube" })).not.toBeInTheDocument();
  fireEvent.click(screen.getByText("Все (3)"));
  fireEvent.change(screen.getByRole("textbox", { name: "Поиск сервисов" }), { target: { value: "youtube" } });
  expect(screen.getByRole("checkbox", { name: "YouTube" })).toBeInTheDocument();
  expect(screen.queryByRole("checkbox", { name: "Telegram" })).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole("textbox", { name: "Поиск сервисов" }), { target: { value: "несуществующий" } });
  expect(screen.getByText("Сервисы не найдены")).toBeInTheDocument();
});

it("selects several services and reports their IDs", async () => {
  const { onSelect, onClose } = setup();
  fireEvent.click(await screen.findByRole("checkbox", { name: "YouTube" }));
  fireEvent.click(screen.getByRole("checkbox", { name: "Telegram" }));
  fireEvent.click(screen.getByRole("button", { name: "Выбрать (2)" }));
  expect(onSelect).toHaveBeenCalledWith(["youtube", "telegram"]);
  expect(onClose).toHaveBeenCalledOnce();
});

it("shows existing and meta-set coverage badges", async () => {
  setup(["telegram-set"]);
  await screen.findByRole("checkbox", { name: "Telegram" });
  expect(screen.getByText("набор уже есть")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("checkbox", { name: "Видеосервисы" }));
  expect(screen.getByText("входит в Видеосервисы")).toBeInTheDocument();
  expect(screen.getAllByText("набор уже есть")).toHaveLength(2);
});

it("surfaces catalog errors", async () => {
  presetCatalog.mockRejectedValue(new Error("Каталог недоступен"));
  setup();
  expect(await screen.findByText("Каталог недоступен")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Выбрать (0)" })).toBeDisabled();
});
