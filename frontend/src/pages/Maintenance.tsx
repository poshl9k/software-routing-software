import { useState } from "react";
import { Alert, Button, Checkbox, FormControlLabel } from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { InterfaceSelect } from "../components/Select";
import { PageTabs } from "../components/Tabs";
import type { UpdateStatus } from "../types";

const tabs = ["Резервные копии", "Диагностика", "Выпуск установки"];
const tabKeys = ["backup", "diagnostics", "release"];
type Backup = { schema_version: number; versions: unknown[]; users: unknown[] };

function download(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function Maintenance() {
  const { configuration, versions, refresh, user } = useConfiguration();
  const admin = user?.role === "admin";
  const [params, setParams] = useSearchParams();
  const tab = Math.max(0, tabKeys.indexOf(params.get("tab") ?? "backup"));
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [secrets, setSecrets] = useState(false);
  const [password, setPassword] = useState("");
  const [backup, setBackup] = useState<Backup | null>(null);
  const [restorePassword, setRestorePassword] = useState("");
  const [allowPartial, setAllowPartial] = useState(false);
  const [restored, setRestored] = useState(false);
  const [host, setHost] = useState("");
  const [count, setCount] = useState(4);
  const [iface, setIface] = useState("");
  const [ping, setPing] = useState<{ sent: number; received: number; loss_pct: number; min_avg_max_ms: number[] } | null>(null);
  const [trace, setTrace] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const [confirmRelease, setConfirmRelease] = useState(false);
  const perform = async (fn: () => Promise<void>) => {
    setError(null);
    setNotice("");
    setBusy(true);
    try { await fn(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  const counters = useQuery({ queryKey: queryKeys.rulesCounters(), queryFn: () => api.rulesCounters(), enabled: admin && tab === 1 });
  const restoreFile = async (file?: File) => {
    if (!file) return;
    void perform(async () => {
      const parsed = JSON.parse(await file.text());
      if (!parsed || parsed.schema_version !== 1 || !Array.isArray(parsed.versions) || !parsed.versions.length || !Array.isArray(parsed.users)) {
        throw new Error("Некорректный файл резервной копии");
      }
      setAllowPartial(false);
      setRestorePassword("");
      setRestored(false);
      setBackup(parsed);
    });
  };
  const latest = backup?.versions.at(-1);
  const snapshot = latest && typeof latest === "object" && !Array.isArray(latest) ? latest as Record<string, unknown> : null;
  const config = snapshot?.configuration;
  const contents = config && typeof config === "object" && !Array.isArray(config) ? config as Record<string, unknown> : null;
  const protectedArchive = Boolean(snapshot?.secret_blob);
  const missingSecrets = !protectedArchive && contents && (["tunnels", "ddns", "sites"] as const).some((key) =>
    Array.isArray(contents[key]) && (contents[key] as unknown[]).some((item) => {
      if (!item || typeof item !== "object") return false;
      const row = item as Record<string, unknown>;
      return key === "tunnels" ? !row.private_key : key === "ddns" ? !row.api_token : row.certificate_mode === "manual" && (!row.certificate || !row.private_key);
    }));

  return <>
    <PageHeader>Обслуживание</PageHeader>
    <PageTabs values={tabs} value={tab} change={(value) => setParams(value === 0 ? {} : { tab: tabKeys[value] })} />
    <ErrorNotice error={error} />{notice && <Alert severity="success">{notice}</Alert>}
    {tab === 0 && <Card title="Резервная копия">
      <Alert severity="info">Импорт создаёт черновик, не применяет конфигурацию. Из архива берётся только последняя версия. Новые парольные архивы перешифровываются для этого хоста; старым архивам нужен прежний ключ.</Alert>
      {versions.some(v => v.status === "draft") && <Alert severity="warning">Перед импортом сбросьте текущий черновик на странице «Применение».</Alert>}
      <FormControlLabel control={<Checkbox checked={secrets} onChange={e => setSecrets(e.target.checked)} />} label="Включая секреты" />
      {secrets && <Field label="Пароль шифрования" type="password" value={password} onChange={setPassword} fullWidth={false} />}
      <div className="footer-actions"><Button disabled={!admin || busy || (secrets && !password)} onClick={() => void perform(async () => { const b = await api.backupExport(secrets, secrets ? password : undefined); download(new Blob([JSON.stringify(b, null, 2)], { type: "application/json" }), "vs-router-backup.json"); })}>Экспорт</Button>
        <Button component="label" disabled={!admin || busy}>Выбрать файл импорта<input hidden disabled={!admin || busy} type="file" accept="application/json,.json" onChange={e => void restoreFile(e.target.files?.[0])} /></Button></div>
      {backup && <>
        <InfoNote>Проверьте архив перед созданием черновика. Восстановится последняя конфигурация; история и пользователи этого хоста не заменяются.</InfoNote>
        <DataTable heads={["Из архива", "Что произойдёт"]} rows={[
          ["Схема", backup.schema_version],
          ["Версии конфигурации", `${backup.versions.length}: последняя → черновик, остальные (${backup.versions.length - 1}) → пропущены`],
          ["Пользователи", `${backup.users.length}: пропущены, учётные записи хоста сохраняются`],
          ["Секреты", protectedArchive ? "Пароль обязателен; восстановление проверит и перешифрует секреты" : "Без пароля архива: записи без нужных секретов будут пропущены"],
        ]} />
        {missingSecrets && <InfoNote severity="warning">В последней конфигурации есть записи без обязательных секретов. Туннели, DDNS и сайты с ручными сертификатами без секретов будут пропущены.</InfoNote>}
        {protectedArchive && <Field label="Пароль архива" type="password" value={restorePassword} onChange={setRestorePassword} fullWidth={false} />}
        <Alert severity="warning">Если в архиве нет секретов, туннели, DDNS и сайты с ручными сертификатами могут быть пропущены. Проверьте черновик перед применением.</Alert>
        <FormControlLabel control={<Checkbox checked={allowPartial} onChange={e => setAllowPartial(e.target.checked)} />} label="Разрешить пропуск записей без секретов" />
        <Button disabled={!admin || busy || restored || (protectedArchive && !restorePassword) || versions.some(v => v.status === "draft")} onClick={() => void perform(async () => {
          const result = await api.backupRestore({ ...backup, allow_partial: allowPartial, ...(restorePassword ? { password: restorePassword } : {}) });
          setRestored(true);
          await refresh();
          setNotice(`Создан черновик из последней версии; пропущено версий: ${result.skipped}. Примените его отдельно.`);
        })}>Импортировать в черновик</Button>
        {restored && <InfoNote>Черновик создан. Проверьте изменения перед применением. <Link to="/apply">Открыть применение</Link></InfoNote>}
      </>}
    </Card>}
    {tab === 1 && <>
      <Card title="Диагностика ping">
        <div className="diag-controls">
          <Field className="grow" label="Узел" value={host} valid={!!host.trim()} hint={!host.trim() ? "Укажите узел" : undefined} onChange={setHost} fullWidth={false} />
          <Field label="Количество" hint="1–5" type="number" inputProps={{ min: 1, max: 5 }} sx={{ width: 130 }} value={count} onChange={(v) => setCount(Number(v))} fullWidth={false} />
          <InterfaceSelect label="Интерфейс" value={iface} interfaces={configuration.interfaces} emptyLabel="Автоматически" sx={{ width: 200 }} onChange={setIface} />
          <Button disabled={!admin || busy || !host.trim() || count < 1 || count > 5} onClick={() => void perform(async () => setPing(await api.ping({ host: host.trim(), count, ...(iface ? { source_interface: iface } : {}) })))}>Ping</Button>
        </div>
        {ping && <p>Отправлено: {ping.sent} · Получено: {ping.received} · Потери: {ping.loss_pct}% · min/avg/max: {ping.min_avg_max_ms.join(" / ")} мс</p>}
      </Card>
      <Card title="Traceroute">
        <div className="diag-controls">
          <Field className="grow" label="Узел" value={host} onChange={setHost} fullWidth={false} />
          <Button disabled={!admin || busy || !host.trim()} onClick={() => void perform(async () => setTrace(await api.traceroute(host.trim())))}>Запустить</Button>
        </div>
        {trace.map((line, i) => <div key={i}>{line}</div>)}
      </Card>
      <Card title="Счётчики правил" action={<Button onClick={() => void counters.refetch()} disabled={!admin || counters.isFetching}>Обновить</Button>}>
        {counters.error ? <ErrorNotice error={counters.error} /> : counters.isPending ? <InfoNote>Загрузка счётчиков…</InfoNote> : Object.keys(counters.data ?? {}).length === 0 ? <EmptyState title="Нет данных счётчиков" /> : <DataTable heads={["Правило", "Пакеты", "Байты"]} rows={Object.entries(counters.data ?? {}).map(([name, value]) => [name, value.packets, value.bytes])} />}
      </Card>
    </>}
    {tab === 2 && <Card title="Выпуск установки" action={<Button disabled={!admin || busy} onClick={() => void perform(async () => setUpdate(await api.updateStatus()))}>Проверить выпуск</Button>}>
      <InfoNote>Выпуск установки — версия продукта (semver и commit id), не версия конфигурации. Устанавливается только зафиксированный выпуск (манифест + SHA-256), не ветка. Установка перезапустит сервисы: текущая сессия завершится, потребуется повторный вход.</InfoNote>
      {update && <>
        <DataTable heads={["Параметр", "Значение"]} rows={[
          ["Установленный выпуск", update.current.commit ? `${update.current.semver ?? "?"} · ${update.current.commit}` : "неизвестно"],
          ["Источник", { iso: "установка с ISO", online: "онлайн-обновление", unknown: "неизвестно" }[update.current.source]],
          ["Манифест", update.configured ? update.manifest_url ?? "" : "не настроен"],
          ["Доступный выпуск", update.available ? `${update.available.semver} · ${update.available.commit}` : "—"],
          ["Состояние", update.running ? "установка выполняется" : update.last ? `последнее: ${update.last.status}` : "—"],
        ]} />
        {update.error && <InfoNote severity="warning">Не удалось проверить выпуск: {update.error}</InfoNote>}
        {!update.configured && <InfoNote severity="warning">URL манифеста не задан на хосте (/etc/vs-router/update.json или VS_ROUTER_UPDATE_MANIFEST_URL).</InfoNote>}
        {update.configured && !update.error && (update.update_available ? <div className="footer-actions">
          <Badge tone="amber">Доступен новый выпуск</Badge>
          <Button disabled={!admin || busy || update.running || !update.available} onClick={() => setConfirmRelease(true)}>Установить выпуск</Button>
        </div> : <Badge tone="green">Установлен актуальный выпуск</Badge>)}
      </>}
      <ConfirmDialog open={confirmRelease} title="Установить выпуск?" body={<>Будет установлен выпуск {update?.available?.semver} ({update?.available?.commit}). Сервисы и панель перезапустятся; сессия завершится, потребуется войти заново. Это не применение версии конфигурации.</>} confirmLabel="Установить выпуск" cancelLabel="Отмена" onCancel={() => setConfirmRelease(false)} onConfirm={() => {
        setConfirmRelease(false);
        const target = update?.available;
        if (!target) return;
        void perform(async () => {
          await api.applyUpdate(target.commit);
          setNotice("Установка выпуска запущена; панель перезапустится и потребует входа.");
          setUpdate(await api.updateStatus());
        });
      }} />
    </Card>}
  </>;
}
