import { useEffect, useState } from "react";
import { Alert, Button, Checkbox, FormControlLabel } from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api, ApiError } from "../api";
import { applyErrorText } from "./ApplyScreen";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { FormActions, FormGrid, FormWide } from "../components/Form";
import type { MasterBridgeStatus, UpdateStatus } from "../types";

const tabs = ["Резервные копии", "Диагностика", "Выпуск установки", "Домен панели", "Мастер"];
const tabKeys = ["backup", "diagnostics", "release", "domain", "master"];
type Backup = { schema_version: number; versions: unknown[]; users: unknown[] };

/** A public panel name: labels separated by dots, no leading/trailing dot or hyphen. */
const hostnamePattern = /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;
/** Attach the guard's plain-language explanation, keeping the raw code (ADR-0025). */
function friendlyPanelError(error: unknown) {
  return error instanceof ApiError
    ? new ApiError(error.status, error.code, applyErrorText(error), error.details)
    : error;
}

function masterBridgeMessage(status: MasterBridgeStatus) {
  const credential = {
    not_installed: "Токен ещё не установлен.",
    pending_verification: "Токен сохранён. Ожидается подтверждение мастера.",
    verified: "Мастер подтвердил токен.",
    unknown: "Состояние токена неизвестно; повторная установка недоступна.",
  }[status.credential_state];
  const publication = {
    absent: "Маршрут Caddy ещё не опубликован.",
    configured_on_disk: "Конфигурация Caddy содержит ожидаемый маршрут.",
    drift: "Обнаружено расхождение конфигурации Caddy.",
    invalid_marker: "Маркер маршрута Caddy повреждён.",
    incompatible: "Маршрут не совместим с текущей конфигурацией панели.",
    unavailable: "Не удалось прочитать состояние маршрута Caddy.",
  }[status.publication_state];
  return `${credential} ${publication}`;
}

function masterBridgeFieldIssue(error: unknown) {
  if (!(error instanceof ApiError) || error.code !== "request.invalid") return null;
  const fields: Record<string, { field: "token" | "hostname" | "source_ip"; inputName: string; summary: string; message: string }> = {
    token: {
      field: "token", inputName: "master-bridge-token",
      summary: "Мастер не принял токен. Проверьте поле ниже.",
      message: "Мастер не принял токен. Убедитесь, что он выдан для этой ноды и скопирован полностью.",
    },
    hostname: {
      field: "hostname", inputName: "master-bridge-hostname",
      summary: "Имя мастера не принято. Проверьте поле ниже.",
      message: "Укажите доменное имя мастера без https://, порта и пути.",
    },
    source_ip: {
      field: "source_ip", inputName: "master-bridge-source-ip",
      summary: "Адрес мастера не принят. Проверьте поле ниже.",
      message: "Введите внешний IPv4- или IPv6-адрес мастера без порта и маски сети.",
    },
  };
  for (const detail of error.details) {
    if (!detail || typeof detail !== "object") continue;
    const validation = detail as { path?: unknown; message?: unknown };
    if (!Array.isArray(validation.path) || typeof validation.path[validation.path.length - 1] !== "string") continue;
    const field = validation.path[validation.path.length - 1] as string;
    if (field === "token") return fields.token;
    if (field === "source_ip") return fields.source_ip;
    if (field === "hostname") return fields.hostname;
  }
  return null;
}

function masterBridgeError(error: unknown) {
  if (!(error instanceof ApiError)) return error;
  const fieldIssue = masterBridgeFieldIssue(error);
  const messages: Record<string, string> = {
    "master_bridge.already_configured": "Токен уже подтверждён. Для его замены используйте ротацию на мастере.",
    "master_bridge.publication_unavailable": "Токен сохранён, но маршрут не настроен. Проверьте состояние службы и повторите попытку с тем же токеном.",
    "agent.unavailable": "Токен сохранён, но служба управления нодой недоступна. Проверьте её состояние и повторите попытку с тем же токеном.",
    "request.cross_origin": "Запрос отклонён. Откройте панель ноды по её HTTPS-адресу и повторите действие.",
  };
  const message = fieldIssue?.summary ?? messages[error.code];
  return message ? new ApiError(error.status, error.code, message, fieldIssue ? [] : error.details) : error;
}

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
  const queryClient = useQueryClient();
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
  const [domain, setDomain] = useState("");
  const [bridgeToken, setBridgeToken] = useState("");
  const [masterHostname, setMasterHostname] = useState("");
  const [masterSourceIp, setMasterSourceIp] = useState("");
  const perform = async (fn: () => Promise<void>) => {
    setError(null);
    setNotice("");
    setBusy(true);
    try { await fn(); } catch (e) { setError(e); } finally { setBusy(false); }
  };
  const counters = useQuery({ queryKey: queryKeys.rulesCounters(), queryFn: () => api.rulesCounters(), enabled: admin && tab === 1 });
  const panel = useQuery({ queryKey: queryKeys.hostManagement(), queryFn: api.hostManagement, enabled: admin && tab === 3 });
  const masterBridge = useQuery({ queryKey: queryKeys.masterBridge(), queryFn: api.masterBridgeStatus,
    enabled: admin && tab === 4, retry: false });
  const setupMasterBridge = useMutation({
    mutationFn: api.setupMasterBridge,
    onSuccess: async () => {
      setBridgeToken("");
      setNotice("Токен сохранён. Подтверждение появится после первого запроса мастера.");
      await queryClient.invalidateQueries({ queryKey: queryKeys.masterBridge() });
    },
  });
  const bridgeFieldIssue = masterBridgeFieldIssue(setupMasterBridge.error);
  useEffect(() => {
    if (masterBridge.data && !["not_installed", "pending_verification"].includes(masterBridge.data.credential_state)) {
      setBridgeToken("");
    }
  }, [masterBridge.data]);
  useEffect(() => {
    if (bridgeFieldIssue) {
      document.querySelector<HTMLInputElement>(`[name="${bridgeFieldIssue.inputName}"]`)?.focus();
    }
  }, [bridgeFieldIssue?.inputName, setupMasterBridge.error]);
  const panelRecord = panel.data ?? null;
  const domainValid = hostnamePattern.test(domain);
  const masterHostnameValid = hostnamePattern.test(masterHostname);
  const bridgeTokenValid = /^[A-Za-z0-9_-]{43}$/.test(bridgeToken);
  const tokenIssue = bridgeFieldIssue?.field === "token" ? bridgeFieldIssue : null;
  const sourceIpIssue = bridgeFieldIssue?.field === "source_ip" ? bridgeFieldIssue : null;
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
    {tab === 3 && <Card title="Домен панели" action={panelRecord?.custom_hostname ? <Badge tone="green">{panelRecord.custom_hostname}</Badge> : <Badge tone="amber">Свой домен не задан</Badge>}>
      <InfoNote>
        Укажите свой домен: он должен уже указывать в DNS на публичный адрес этого
        хоста. Панель выпустит для него сертификат Let's Encrypt (HTTP-01, порт 80)
        и начнёт отвечать и по нему, и по резервному адресу. Изменение применяется
        сразу, отдельного «Применения» не требует; при неудаче остаётся прежний
        адрес панели.
      </InfoNote>
      {panel.error ? <ErrorNotice error={panel.error} /> : panel.isPending ? <InfoNote>Чтение записи управления…</InfoNote> : !panelRecord ? <InfoNote severity="warning">Запись управления не найдена — панель не провизионирована. Восстановите её из консоли.</InfoNote> : (
        <DataTable heads={["Параметр", "Значение"]} rows={[
          ["Резервный адрес", panelRecord.hostname ?? "не задан"],
          ["Свой домен", panelRecord.custom_hostname ?? "не задан"],
          ["Интерфейс", `${panelRecord.interface} · ${panelRecord.mac}`],
          ["Режим", panelRecord.mode === "single-uplink" ? "один аплинк (VPS)" : "отдельный LAN"],
        ]} />
      )}
      <div className="fields">
        <Field className="grow" label="Свой домен" value={domain}
          valid={!domain || domainValid}
          placeholder="panel.example.ru"
          hint={!domain ? "Латинские буквы, цифры, дефис и точка" : !domainValid ? "Некорректное имя домена" : "A-запись домена должна указывать на публичный адрес хоста"}
          fullWidth={false}
          onChange={setDomain} />
      </div>
      <div className="footer-actions">
        <Button disabled={!admin || busy || !domainValid} onClick={() => void perform(async () => {
          try {
            await api.setPanelDomain(domain);
          } catch (e) { throw friendlyPanelError(e); }
          setDomain("");
          await panel.refetch();
          setNotice(`Свой домен панели: ${domain}`);
        })}>Привязать домен</Button>
        <Button disabled={!admin || busy || !panelRecord?.custom_hostname} onClick={() => void perform(async () => {
          try {
            await api.setPanelDomain(null);
          } catch (e) { throw friendlyPanelError(e); }
          await panel.refetch();
          setNotice("Свой домен снят — панель отвечает по резервному адресу.");
        })}>Убрать свой домен</Button>
      </div>
    </Card>}
    {tab === 4 && (!admin ? <InfoNote severity="warning">Подключение к мастер-порталу доступно только администратору ноды.</InfoNote> : <Card title="Подключение к мастер-порталу"
      action={<Button onClick={() => void masterBridge.refetch()} disabled={masterBridge.isFetching}>Обновить статус</Button>}>
      <InfoNote>Токен выдаётся в админке мастера и вводится здесь по HTTPS. Он хранится зашифрованным; после успешной проверки мастера поле токена исчезнет.</InfoNote>
      {masterBridge.error && <ErrorNotice error={masterBridge.error} />}
      {masterBridge.data && <InfoNote severity={masterBridge.data.credential_state === "verified"
        && masterBridge.data.publication_state === "configured_on_disk" ? "info" : "warning"}>
        {masterBridgeMessage(masterBridge.data)}
      </InfoNote>}
      {masterBridge.isPending && <InfoNote>Чтение состояния подключения…</InfoNote>}
      {setupMasterBridge.error && <ErrorNotice error={masterBridgeError(setupMasterBridge.error)} />}
      {masterBridge.data && !masterBridge.error
        && ["not_installed", "pending_verification"].includes(masterBridge.data.credential_state) && <form onSubmit={(event) => {
          event.preventDefault();
          setNotice("");
          setupMasterBridge.mutate({ token: bridgeToken, hostname: masterHostname, source_ip: masterSourceIp });
        }}>
        <FormGrid>
          <Field label="Токен из мастер-портала" type="password" autoComplete="off"
            maxLength={43} value={bridgeToken} onChange={value => { setBridgeToken(value); setupMasterBridge.reset(); }}
            valid={!tokenIssue && (!bridgeToken || bridgeTokenValid)}
            inputProps={{ name: "master-bridge-token", spellCheck: false, translate: "no", pattern: "[A-Za-z0-9_-]{43}" }}
            hint={tokenIssue?.message ?? (bridgeToken && !bridgeTokenValid ? "Токен должен содержать 43 символа без пробелов" : "Вставьте одноразовый токен из админки мастера")} required />
          <Field label="Домен мастера" value={masterHostname} onChange={value => { setMasterHostname(value); setupMasterBridge.reset(); }} autoComplete="off"
            inputProps={{ name: "master-bridge-hostname", spellCheck: false, pattern: "[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?" }}
            valid={!masterHostname || masterHostnameValid} hint="Имя хоста мастера без https:// и пути" required />
          <Field label="Исходящий IP мастера" value={masterSourceIp} onChange={value => { setMasterSourceIp(value); setupMasterBridge.reset(); }} autoComplete="off"
            inputProps={{ name: "master-bridge-source-ip", spellCheck: false }} valid={!sourceIpIssue}
            hint={sourceIpIssue?.message ?? "Публичный IPv4 или IPv6, с которого мастер обращается к этой ноде"} required />
          <FormWide><InfoNote>Если токен введён неверно, его можно заменить до первого успешного запроса мастера. После подтверждения повторная установка будет заблокирована.</InfoNote></FormWide>
          <FormWide><FormActions><Button type="submit" variant="contained" disabled={setupMasterBridge.isPending}>
            {setupMasterBridge.isPending ? "Подключаем…" : "Сохранить и подключить"}
          </Button></FormActions></FormWide>
        </FormGrid>
      </form>}
    </Card>)}
  </>;
}
