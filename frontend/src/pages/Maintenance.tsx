import { useState } from "react";
import { Alert, Button, Checkbox, FormControlLabel, TextField } from "@mui/material";
import { useConfiguration } from "../state";
import { api } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import { Card } from "../components/Card";
import { Badge } from "../components/Badge";
import { DataTable } from "../components/DataTable";
import { ErrorNotice } from "../components/ErrorNotice";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { InterfaceSelect } from "../components/Select";
import type { UpdateStatus } from "../types";

function download(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url);
}
export default function Maintenance() {
  const { configuration, versions, refresh, user } = useConfiguration();
  const admin = user?.role === "admin";
  const [error, setError] = useState<unknown>(null); const [notice, setNotice] = useState("");
  const [secrets, setSecrets] = useState(false); const [password, setPassword] = useState("");
  const [backup, setBackup] = useState<{schema_version:number; versions:unknown[]; users:unknown[]}|null>(null);
  const [restorePassword, setRestorePassword] = useState("");
  const [allowPartial, setAllowPartial] = useState(false);
  const [host, setHost] = useState(""); const [count, setCount] = useState(4); const [iface, setIface] = useState("");
  const [ping, setPing] = useState<{sent:number;received:number;loss_pct:number;min_avg_max_ms:number[]}|null>(null);
  const [trace, setTrace] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [update, setUpdate] = useState<UpdateStatus | null>(null);
  const perform = async (fn:()=>Promise<void>) => { setError(null); setNotice(""); setBusy(true); try { await fn(); } catch(e) { setError(e); } finally { setBusy(false); } };
  const counters = useQuery({ queryKey: queryKeys.rulesCounters(), queryFn: () => api.rulesCounters(), enabled: admin });
  const restoreFile = async (file?: File) => { if (!file) return; void perform(async()=>{ const parsed=JSON.parse(await file.text()); if (!parsed || typeof parsed.schema_version!=="number" || !Array.isArray(parsed.versions) || !Array.isArray(parsed.users)) throw new Error("Некорректный файл резервной копии"); setAllowPartial(false); setBackup(parsed); }); };
  return <>
    <PageHeader>Обслуживание</PageHeader>
    <ErrorNotice error={error}/>{notice&&<Alert severity="success">{notice}</Alert>}
    <Card title="Резервная копия">
      <Alert severity="info">Импорт создаёт черновик, не применяет конфигурацию. Из архива берётся только последняя версия. Новые парольные архивы перешифровываются для этого хоста; старым архивам нужен прежний ключ.</Alert>
      {versions.some(v=>v.status==="draft")&&<Alert severity="warning">Перед импортом сбросьте текущий черновик на странице «Применение».</Alert>}
      <FormControlLabel control={<Checkbox checked={secrets} onChange={e=>setSecrets(e.target.checked)}/>} label="Включая секреты"/>
      {secrets&&<TextField size="small" label="Пароль шифрования" type="password" value={password} onChange={e=>setPassword(e.target.value)}/>}
      <div className="footer-actions"><Button disabled={!admin||busy||(secrets&&!password)} onClick={()=>void perform(async()=>{const b=await api.backupExport(secrets,secrets?password:undefined); download(new Blob([JSON.stringify(b,null,2)],{type:"application/json"}),"vs-router-backup.json");})}>Экспорт</Button>
      <Button component="label" disabled={!admin}>Выбрать файл импорта<input hidden disabled={!admin} type="file" accept="application/json,.json" onChange={e=>void restoreFile(e.target.files?.[0])}/></Button></div>
      {backup&&<><DataTable heads={["Параметр","Значение"]} rows={[["Версия схемы",backup.schema_version],["Версий конфигурации",backup.versions.length],["Пользователей",backup.users.length]]}/>
        <TextField size="small" label="Пароль (если требуется)" type="password" value={restorePassword} onChange={e=>setRestorePassword(e.target.value)}/>
        <Alert severity="warning">Если в архиве нет секретов, туннели, DDNS и сайты с ручными сертификатами могут быть пропущены. Проверьте черновик перед применением.</Alert>
        <FormControlLabel control={<Checkbox checked={allowPartial} onChange={e=>setAllowPartial(e.target.checked)}/>} label="Разрешить пропуск записей без секретов"/>
        <Button disabled={!admin||busy||versions.some(v=>v.status==="draft")} onClick={()=>void perform(async()=>{const result=await api.backupRestore({...backup,allow_partial:allowPartial,...(restorePassword?{password:restorePassword}:{})});await refresh();setNotice(`Создан черновик из последней версии; пропущено версий: ${result.skipped}. Примените его отдельно.`);})}>Импортировать в черновик</Button></>}
    </Card>
    <Card
      title="Обновление продукта"
      action={
        <Button
          disabled={!admin || busy}
          onClick={() => void perform(async () => setUpdate(await api.updateStatus()))}
        >
          Проверить обновление
        </Button>
      }
    >
      <InfoNote>
        Обновление ставит зафиксированный выпуск (манифест + SHA-256), не ветку.
        Применение перезапустит сервисы — текущая сессия завершится, войдите заново.
      </InfoNote>
      {update && (
        <>
          <DataTable
            heads={["Параметр", "Значение"]}
            rows={[
              ["Установленный выпуск", update.current.commit ? `${update.current.semver ?? "?"} · ${update.current.commit.slice(0, 7)}` : "неизвестно"],
              ["Источник", update.current.source],
              ["Манифест", update.configured ? update.manifest_url ?? "" : "не настроен"],
              ["Доступный выпуск", update.available ? `${update.available.semver} · ${update.available.commit.slice(0, 7)}` : "—"],
              ["Состояние", update.running ? "обновление выполняется" : update.last ? `последнее: ${update.last.status}` : "—"],
            ]}
          />
          {update.error && (
            <InfoNote severity="warning">Не удалось проверить выпуск: {update.error}</InfoNote>
          )}
          {!update.configured && (
            <InfoNote severity="warning">
              URL манифеста не задан на хосте (/etc/vs-router/update.json или VS_ROUTER_UPDATE_MANIFEST_URL).
            </InfoNote>
          )}
          {update.configured && !update.error && (
            update.update_available ? (
              <div className="footer-actions">
                <Badge tone="amber">Доступен новый выпуск</Badge>
                <Button
                  disabled={!admin || busy || update.running || !update.available}
                  onClick={() =>
                    void perform(async () => {
                      const target = update.available;
                      if (!target) return;
                      if (!window.confirm(`Применить выпуск ${target.semver} (${target.commit.slice(0, 7)})? Панель перезапустится.`)) return;
                      await api.applyUpdate(target.commit);
                      setNotice("Обновление запущено; панель перезапустится и потребует входа.");
                      setUpdate(await api.updateStatus());
                    })
                  }
                >
                  Применить обновление
                </Button>
              </div>
            ) : (
              <Badge tone="green">Установлен актуальный выпуск</Badge>
            )
          )}
        </>
      )}
    </Card>
    <Card title="Диагностика ping">
      <div className="diag-controls">
        <TextField
          className="grow"
          size="small"
          label="Узел"
          value={host}
          error={!host.trim()}
          helperText={!host.trim() ? "Укажите узел" : ""}
          onChange={(e) => setHost(e.target.value)}
        />
        <TextField
          size="small"
          label="Количество"
          helperText="1–5"
          type="number"
          slotProps={{ htmlInput: { min: 1, max: 5 } }}
          sx={{ width: 130 }}
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
        />
        <InterfaceSelect
          label="Интерфейс"
          value={iface}
          interfaces={configuration.interfaces}
          emptyLabel="Автоматически"
          sx={{ width: 200 }}
          onChange={setIface}
        />
        <Button
          disabled={!admin || busy || !host.trim() || count < 1 || count > 5}
          onClick={() =>
            void perform(async () =>
              setPing(
                await api.ping({
                  host: host.trim(),
                  count,
                  ...(iface ? { source_interface: iface } : {}),
                }),
              )
            )
          }
        >
          Ping
        </Button>
      </div>
      {ping && (
        <p>
          Отправлено: {ping.sent} · Получено: {ping.received} · Потери:{" "}
          {ping.loss_pct}% · min/avg/max: {ping.min_avg_max_ms.join(" / ")} мс
        </p>
      )}
    </Card>
    <Card title="Traceroute">
      <div className="diag-controls">
        <TextField
          className="grow"
          size="small"
          label="Узел"
          value={host}
          onChange={(e) => setHost(e.target.value)}
        />
        <Button
          disabled={!admin || busy || !host.trim()}
          onClick={() =>
            void perform(async () =>
              setTrace(await api.traceroute(host.trim())),
            )
          }
        >
          Запустить
        </Button>
      </div>
      {trace.map((line, i) => (
        <div key={i}>{line}</div>
      ))}
    </Card>
    <Card title="Счётчики правил" action={<Button onClick={()=>void counters.refetch()} disabled={!admin||counters.isFetching}>Обновить</Button>}><DataTable heads={["Правило","Пакеты","Байты"]} rows={Object.entries(counters.data??{}).map(([name,value])=>[name,value.packets,value.bytes])}/></Card>
  </>;
}