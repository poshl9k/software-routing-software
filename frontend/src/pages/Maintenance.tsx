import { useEffect, useState } from "react";
import { Alert, Button, Checkbox, FormControlLabel, TextField, Typography } from "@mui/material";
import { useConfiguration } from "../state";
import { api } from "../api";
import { Card, DataTable, ErrorNotice } from "../ui";

function download(data: Blob, filename: string) {
  const url = URL.createObjectURL(data);
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url);
}
export default function Maintenance() {
  const { configuration } = useConfiguration();
  const [error, setError] = useState<unknown>(null); const [notice, setNotice] = useState("");
  const [secrets, setSecrets] = useState(false); const [password, setPassword] = useState("");
  const [backup, setBackup] = useState<{schema_version:number; versions:unknown[]; users:unknown[]}|null>(null);
  const [restorePassword, setRestorePassword] = useState("");
  const [host, setHost] = useState(""); const [count, setCount] = useState(4); const [iface, setIface] = useState("");
  const [ping, setPing] = useState<{sent:number;received:number;loss_pct:number;min_avg_max_ms:number[]}|null>(null);
  const [trace, setTrace] = useState<string[]>([]); const [counters, setCounters] = useState<Record<string,{packets:number;bytes:number}>>({});
  const [busy, setBusy] = useState(false);
  const perform = async (fn:()=>Promise<void>) => { setError(null); setNotice(""); setBusy(true); try { await fn(); } catch(e) { setError(e); } finally { setBusy(false); } };
  const refreshCounters = () => perform(async()=>setCounters(await api.rulesCounters()));
  useEffect(()=>{void refreshCounters();},[]);
  const restoreFile = async (file?: File) => { if (!file) return; void perform(async()=>{ const parsed=JSON.parse(await file.text()); if (!parsed || typeof parsed.schema_version!=="number" || !Array.isArray(parsed.versions) || !Array.isArray(parsed.users)) throw new Error("Некорректный файл резервной копии"); setBackup(parsed); }); };
  return <>
    <Typography component="h1" variant="h1" className="page-title">Обслуживание</Typography>
    <ErrorNotice error={error}/>{notice&&<Alert severity="success">{notice}</Alert>}
    <Card title="Резервная копия">
      <FormControlLabel control={<Checkbox checked={secrets} onChange={e=>setSecrets(e.target.checked)}/>} label="Включая секреты"/>
      {secrets&&<TextField size="small" label="Пароль шифрования" type="password" value={password} onChange={e=>setPassword(e.target.value)}/>}
      <div className="footer-actions"><Button disabled={busy||(secrets&&!password)} onClick={()=>void perform(async()=>{const b=await api.backupExport(secrets,secrets?password:undefined); download(new Blob([JSON.stringify(b,null,2)],{type:"application/json"}),"vs-router-backup.json");})}>Экспорт</Button>
      <Button component="label">Выбрать файл импорта<input hidden type="file" accept="application/json,.json" onChange={e=>void restoreFile(e.target.files?.[0])}/></Button></div>
      {backup&&<><DataTable heads={["Параметр","Значение"]} rows={[["Версия схемы",backup.schema_version],["Версий конфигурации",backup.versions.length],["Пользователей",backup.users.length]]}/>
        <TextField size="small" label="Пароль (если требуется)" type="password" value={restorePassword} onChange={e=>setRestorePassword(e.target.value)}/>
        <Button disabled={busy} onClick={()=>void perform(async()=>{const result=await api.backupRestore({...backup,...(restorePassword?{password:restorePassword}:{})});setNotice(`Восстановлено: ${result.restored}`);})}>Восстановить</Button></>}
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
          inputProps={{ min: 1, max: 5 }}
          sx={{ width: 130 }}
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
        />
        <TextField
          select
          SelectProps={{ native: true }}
          size="small"
          label="Интерфейс"
          InputLabelProps={{ shrink: true }}
          sx={{ width: 200 }}
          value={iface}
          onChange={(e) => setIface(e.target.value)}
        >
          <option value="">Автоматически</option>
          {configuration.interfaces.map((i) => (
            <option key={i.name} value={i.name}>
              {i.name}
            </option>
          ))}
        </TextField>
        <Button
          disabled={busy || !host.trim() || count < 1 || count > 5}
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
          disabled={busy || !host.trim()}
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
    <Card title="Счётчики правил" action={<Button onClick={()=>void refreshCounters()} disabled={busy}>Обновить</Button>}><DataTable heads={["Правило","Пакеты","Байты"]} rows={Object.entries(counters).map(([name,value])=>[name,value.packets,value.bytes])}/></Card>
  </>;
}
