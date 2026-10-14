import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Typography } from "@mui/material";
import { api } from "../api";
import type { RuntimeConnection, RuntimeLogEntry } from "../types";
import { tokens } from "../theme";
import { useRouterState } from "../state";
import { PageHeader } from "../components/PageHeader";
import { PageSection } from "../components/PageSection";
import { DataTable } from "../components/DataTable";
import { Field } from "../components/Field";
import { Select } from "../components/Select";
import { StatTile } from "../components/StatTile";
import { InlineStatus } from "../components/InlineStatus";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ValueTabs } from "../components/Tabs";

type Tab = "engine" | "connections" | "logs";
type Level = "debug" | "info" | "warning" | "error";
const tabs: { value: Tab; label: string }[] = [
  { value: "engine", label: "Движок" },
  { value: "connections", label: "Соединения" },
  { value: "logs", label: "Журнал" },
];
// Never render/export raw log payloads: Clash redacts known fields, not arbitrary log text.
export function maskLog(value: string): string {
  return value
    .replace(/\b(?:password|secret|token|authorization|uuid|key)\s*[:=]\s*[^\s,;]+/gi, "[скрыто]")
    .replace(/\b(?:https?:\/\/)[^\s]+/gi, "[адрес скрыт]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[адрес скрыт]")
    .replace(/\b(?:[a-f\d]{0,4}:){2,}[a-f\d:]*\b/gi, "[адрес скрыт]")
    .replace(/\b(?:[a-z\d-]+\.)+[a-z]{2,}\b/gi, "[адрес скрыт]");
}
const safeError = (error: unknown) => error ? new Error("Не удалось получить данные или выполнить команду. Проверьте доступность движка и повторите запрос.") : null;
const bytes = (n?: number) => n === undefined ? "Нет данных" : `${(n / 1024).toFixed(1)} КиБ`;
const address = (value?: string | number) => value === undefined || value === "" ? "—" : String(value);

function Engine() {
  const { user } = useRouterState();
  const client = useQueryClient();
  const [confirmRestart, setConfirmRestart] = useState(false);
  const status = useQuery({ queryKey: ["runtime", "engine"], queryFn: api.runtimeEngine, refetchInterval: 15000, retry: false });
  const action = useMutation({
    mutationFn: api.runtimeEngineControl,
    onSuccess: (result) => client.setQueryData(["runtime", "engine"], result),
    onSettled: () => void client.invalidateQueries({ queryKey: ["runtime", "engine"] }),
  });
  const engine = status.isError ? null : status.data;
  const submit = (command: "start" | "stop" | "restart") => {
    setConfirmRestart(false);
    action.mutate(command);
  };
  return <PageSection title="Движок sing-box" subtitle="Состояние агента; обновляется каждые 15 секунд. Управление доступно администратору."
    action={<Button onClick={() => void status.refetch()} disabled={status.isFetching}>Обновить</Button>}>
    <ErrorNotice error={safeError(status.error)} />
    <ErrorNotice error={safeError(action.error)} />
    <div className="form-grid stats">
      <StatTile label="Установлен" value={engine ? engine.installed ? "Да" : "Нет" : null} />
      <StatTile label="Версия" value={engine?.version ?? null} />
      <StatTile label="PID" value={engine?.pid ?? null} />
      <StatTile label="Clash API" value={engine ? engine.clash_api ? "Доступен" : "Недоступен" : null} />
    </div>
    <div className="diag-controls">
      <InlineStatus tone={!engine ? "unknown" : engine.running ? "green" : "neutral"}
        text={!engine ? "Состояние неизвестно" : engine.running ? "Работает" : "Остановлен"} />
      {user?.role === "admin" && <>
        <Button variant="contained" disabled={!engine || !engine.installed || engine.running || action.isPending} onClick={() => submit("start")}>Запустить</Button>
        <Button variant="outlined" disabled={!engine?.running || action.isPending} onClick={() => submit("stop")}>Остановить</Button>
        <Button variant="outlined" disabled={!engine?.running || action.isPending} onClick={() => setConfirmRestart(true)}>Перезапустить</Button>
      </>}
    </div>
    <ConfirmDialog open={confirmRestart} title="Перезапустить движок?"
      body="Активные соединения могут прерваться." confirmLabel="Перезапустить" cancelLabel="Отмена"
      onConfirm={() => submit("restart")} onCancel={() => setConfirmRestart(false)} danger />
  </PageSection>;
}

function Connections() {
  const { user } = useRouterState();
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [closing, setClosing] = useState<RuntimeConnection | null>(null);
  const query = useQuery({ queryKey: ["runtime", "connections"], queryFn: api.runtimeConnections, refetchInterval: 10000, retry: false });
  const close = useMutation({
    mutationFn: api.runtimeCloseConnection,
    onSuccess: () => void client.invalidateQueries({ queryKey: ["runtime", "connections"] }),
  });
  const rows = query.isError ? [] : query.data?.connections ?? [];
  const protocols = [...new Set(rows.map((row) => row.metadata?.network ?? "неизвестно"))];
  const visible = rows.filter((row) => {
    const m = row.metadata;
    return (protocol === "all" || (m?.network ?? "неизвестно") === protocol) &&
      [m?.network, m?.sourceIP, m?.destinationIP, m?.host, row.rule, ...(row.chains ?? [])]
        .some((part) => (part ?? "").toLowerCase().includes(search.toLowerCase().trim()));
  });
  return <PageSection title="Активные соединения" subtitle="Снимок Clash API; обновление каждые 10 секунд, не поток событий."
    action={<Button onClick={() => void query.refetch()} disabled={query.isFetching}>Обновить</Button>}>
    <ErrorNotice error={safeError(query.error)} />
    <ErrorNotice error={safeError(close.error)} />
    <div className="diag-controls">
      <Field className="grow" label="Поиск соединений" value={search} onChange={setSearch} fullWidth={false} />
      <Select label="Протокол" value={protocol} onChange={setProtocol} fullWidth={false} sx={{ minWidth: 180 }}
        options={[{ value: "all", label: "Все" }, ...protocols.map((item) => ({ value: item, label: item }))]} />
    </div>
    {query.isPending ? <Typography>Загрузка соединений…</Typography> : query.isError ?
      <EmptyState title="Соединения недоступны">Состояние неизвестно.</EmptyState> : visible.length === 0 ?
      <EmptyState title="Нет соединений">Снимок пуст или ничего не найдено.</EmptyState> :
      <div className="table-wide"><DataTable
        heads={["Протокол", "Источник", "Назначение", "Правило", "Выход", "Трафик", "Состояние", "Действие"]}
        rows={visible.map((row) => {
          const m = row.metadata;
          return [
            address(m?.network),
            <>{address(m?.sourceIP)}:{address(m?.sourcePort)}</>,
            <>{address(m?.host ?? m?.destinationIP)}:{address(m?.destinationPort)}</>,
            address(row.rule),
            address(row.chains?.join(" → ")),
            <>↑ {bytes(row.upload)} · ↓ {bytes(row.download)}</>,
            <InlineStatus tone="green" text="Активно" />,
            user?.role === "admin" && <Button size="small" color="error" disabled={close.isPending} onClick={() => setClosing(row)}>Закрыть</Button>,
          ];
        })} /></div>}
    <ConfirmDialog open={closing !== null} title="Закрыть соединение?" body="Это прервёт выбранное соединение."
      confirmLabel="Закрыть" cancelLabel="Отмена" danger onCancel={() => setClosing(null)}
      onConfirm={() => { if (closing) close.mutate(closing.id); setClosing(null); }} />
  </PageSection>;
}

function Logs() {
  const [level, setLevel] = useState<Level>("info");
  const [source, setSource] = useState("all");
  const [search, setSearch] = useState("");
  const [paused, setPaused] = useState(false);
  const [cleared, setCleared] = useState(false);
  const [operationError, setOperationError] = useState<unknown>(null);
  const query = useQuery({ queryKey: ["runtime", "logs", level], queryFn: () => api.runtimeLogs(level, 100),
    enabled: !paused && !cleared, refetchInterval: paused ? false : 15000, retry: false });
  const entries = query.isError || cleared ? [] : query.data ?? [];
  const sources = [...new Set(entries.map((entry) => entry.source ?? "sing-box"))];
  const visible = entries.filter((entry) => (source === "all" || (entry.source ?? "sing-box") === source) &&
    maskLog(`${entry.type ?? ""} ${entry.payload ?? ""} ${entry.source ?? ""}`).toLowerCase().includes(search.toLowerCase().trim()));
  const lines = visible.map((entry: RuntimeLogEntry) =>
    `[${maskLog(entry.type ?? "info")}] [${maskLog(entry.source ?? "sing-box")}] ${maskLog(entry.payload ?? "")}`).join("\n");
  const refresh = () => { setCleared(false); void query.refetch(); };
  const copy = async () => {
    try { await navigator.clipboard.writeText(lines); setOperationError(null); }
    catch { setOperationError(new Error("Не удалось скопировать журнал")); }
  };
  const download = () => {
    try {
      const url = URL.createObjectURL(new Blob([lines], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = "sing-box-log.txt";
      link.click(); URL.revokeObjectURL(url); setOperationError(null);
    } catch { setOperationError(new Error("Не удалось скачать журнал")); }
  };
  return <PageSection title="Журнал sing-box" subtitle="Последние 100 строк ответа API. Обновление каждые 15 секунд; не поток событий. Адреса скрыты."
    action={<Button onClick={refresh} disabled={query.isFetching}>Обновить</Button>}>
    <ErrorNotice error={safeError(query.error)} /><ErrorNotice error={operationError} />
    <div className="diag-controls">
      <Select label="Уровень" value={level} fullWidth={false} sx={{ minWidth: 150 }} onChange={(value) => { setLevel(value as Level); setCleared(false); }}
        options={[{ value: "debug", label: "Отладка" }, { value: "info", label: "Информация" },
          { value: "warning", label: "Предупреждения" }, { value: "error", label: "Ошибки" }]} />
      <Select label="Источник" value={sources.includes(source) ? source : "all"} fullWidth={false} sx={{ minWidth: 150 }} onChange={setSource}
        options={[{ value: "all", label: "Все" }, ...sources.map((item) => ({ value: item, label: maskLog(item) }))]} />
      <Field className="grow" label="Поиск в журнале" value={search} onChange={setSearch} fullWidth={false} />
      <Button variant="outlined" onClick={() => { if (paused) setCleared(false); setPaused(!paused); }}>{paused ? "Продолжить" : "Пауза"}</Button>
      <Button disabled={!visible.length} onClick={() => void copy()}>Копировать</Button>
      <Button disabled={!visible.length} onClick={download}>Скачать</Button>
      <Button disabled={!entries.length} onClick={() => setCleared(true)}>Очистить</Button>
    </div>
    {query.isPending && !cleared ? <Typography>Загрузка журнала…</Typography> : query.isError ?
      <EmptyState title="Журнал недоступен">Состояние неизвестно.</EmptyState> : visible.length === 0 ?
      <EmptyState title="Нет записей">Хвост пуст или записи скрыты фильтром.</EmptyState> :
      <Typography component="pre" sx={{ p: 2, bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, borderRadius: 1,
        whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 520, overflow: "auto", fontSize: 13 }}>
        {lines}
      </Typography>}
  </PageSection>;
}

export default function Diagnostics() {
  const [tab, setTab] = useState<Tab>("engine");
  return <div className="page"><PageHeader>Диагностика</PageHeader>
    <ValueTabs tabs={tabs} value={tab} change={setTab} />
    {tab === "engine" ? <Engine /> : tab === "connections" ? <Connections /> : <Logs />}
  </div>;
}
