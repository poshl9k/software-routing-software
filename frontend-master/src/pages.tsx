import { Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { masterApi, type MasterNode, type MasterSubscriber, type MasterTariff } from "./api";

export function ErrorNotice({ error }: { error: unknown }) {
  return error ? <Alert severity="error" sx={{ mb: 2 }}>{error instanceof Error ? error.message : "Ошибка"}</Alert> : null;
}

function StateChip({ state }: { state: MasterNode["state"] }) {
  const label = state === "ok" ? "Доступна" : state === "stale" ? "Нет ответа" : "Недоступна";
  return <Chip size="small" label={label} color={state === "ok" ? "success" : state === "stale" ? "warning" : "error"} variant="outlined" />;
}

function Row({ children }: { children: ReactNode }) {
  return <Box className="device"><Box className="device-main"><Box>{children}</Box></Box><Box className="device-actions">{null}</Box></Box>;
}

export function NodesPage() {
  const [nodes, setNodes] = useState<MasterNode[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [working, setWorking] = useState<number | "create" | null>(null);
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [capacity, setCapacity] = useState("20");
  const [issuedToken, setIssuedToken] = useState<{ name: string; token: string } | null>(null);

  async function load() {
    setBusy(true); setError(null);
    try { setNodes((await masterApi.nodes()).nodes); } catch (reason) { setError(reason); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);

  async function add(event?: FormEvent) {
    event?.preventDefault(); setWorking("create"); setError(null);
    try {
      const created = await masterApi.addNode({ name: name.trim(), bridge_url: url.trim(), capacity: Number(capacity) || 1 });
      setIssuedToken({ name: created.node.name, token: created.token });
      setAdding(false); setName(""); setUrl(""); setCapacity("20");
      await load();
    } catch (reason) { setError(reason); } finally { setWorking(null); }
  }
  async function rotate(node: MasterNode) {
    setWorking(node.id); setError(null);
    try {
      await masterApi.rotateNodeToken(node.id);
      await load();
    } catch (reason) { setError(reason); } finally { setWorking(null); }
  }
  async function toggle(node: MasterNode) {
    setWorking(node.id); setError(null);
    try { await masterApi.updateNode(node.id, { enabled: !node.enabled }); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }
  async function remove(node: MasterNode) {
    setWorking(node.id); setError(null);
    try { await masterApi.removeNode(node.id); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }

  return <Box>
    <Box className="section-head"><Typography variant="h2">Ноды</Typography>
      <Button variant="contained" onClick={() => setAdding(true)}>Добавить ноду</Button></Box>
    <ErrorNotice error={error} />
    {busy && !nodes.length ? <Box className="loading"><CircularProgress /></Box> :
      nodes.length === 0 ? <Typography color="text.secondary">Нод пока нет.</Typography> :
        <Stack spacing={1.2} sx={{ mt: 2 }}>
          {nodes.map(node => <Box className="device" key={node.id}>
            <Box className="device-main">
              <Box>
                <Typography fontWeight={600}>{node.name} <StateChip state={node.state} /></Typography>
                <Typography variant="body2" color="text.secondary">{node.bridge_url}</Typography>
                <Typography variant="body2" color="text.secondary">
                  Ёмкость {node.capacity} · Активных устройств {node.active_peers}
                  {node.last_seen ? ` · Отзыв ${new Date(node.last_seen).toLocaleString("ru-RU")}` : " · Опроса ещё не было"}
                  {!node.enabled && " · Отключена"}
                </Typography>
              </Box>
            </Box>
            <Box className="device-actions">
              <Button variant="outlined" size="small" disabled={working !== null} onClick={() => void rotate(node)}>
                {working === node.id ? <CircularProgress size={16} /> : "Сменить токен"}</Button>
              <Button variant="outlined" size="small" disabled={working !== null} onClick={() => void toggle(node)}>
                {node.enabled ? "Отключить" : "Включить"}</Button>
              <Button variant="outlined" size="small" color="error" disabled={working !== null}
                onClick={() => void remove(node)}>Удалить</Button>
            </Box>
          </Box>)}
        </Stack>}
    <Dialog open={adding} onClose={() => setAdding(false)} aria-labelledby="add-node-title" fullWidth maxWidth="sm">
      <DialogTitle id="add-node-title">Добавить ноду</DialogTitle>
      <DialogContent>
        <Box component="form" onSubmit={add} className="form" sx={{ mt: 1 }}>
          <TextField label="Имя ноды" value={name} onChange={e => setName(e.target.value)} required fullWidth autoFocus />
          <TextField label="Bridge URL ноды" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://rg2.example/internal" required fullWidth />
          <TextField label="Ёмкость (активных устройств)" type="number" value={capacity} onChange={e => setCapacity(e.target.value)} inputProps={{ min: 1 }} required fullWidth />
        </Box>
      </DialogContent>
      <DialogActions><Button onClick={() => setAdding(false)}>Отмена</Button>
        <Button variant="contained" disabled={!name.trim() || !url.trim() || working === "create"} onClick={() => void add()}>
          {working === "create" ? <CircularProgress size={16} /> : "Создать"}</Button></DialogActions>
    </Dialog>
    <Dialog open={issuedToken !== null} onClose={() => setIssuedToken(null)} aria-labelledby="token-title" fullWidth maxWidth="sm">
      <DialogTitle id="token-title">Токен ноды {issuedToken?.name}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>Токен показывается один раз. Запишите его — он нужен для онбординга ноды.</Alert>
        <Typography sx={{ wordBreak: "break-all", fontFamily: "monospace" }}>{issuedToken?.token}</Typography>
      </DialogContent>
      <DialogActions><Button variant="contained" onClick={() => setIssuedToken(null)}>Записал</Button></DialogActions>
    </Dialog>
  </Box>;
}

export function TariffsPage() {
  const [tariffs, setTariffs] = useState<MasterTariff[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<(Partial<MasterTariff> & { id?: number }) | null>(null);
  const [working, setWorking] = useState<number | "save" | null>(null);

  async function load() { setBusy(true); try { setTariffs((await masterApi.tariffs()).tariffs); } catch (reason) { setError(reason); } finally { setBusy(false); } }
  useEffect(() => { void load(); }, []);

  async function save(event?: FormEvent) {
    event?.preventDefault(); if (!editing) return;
    setWorking("save"); setError(null);
    try { await masterApi.saveTariff(editing); setEditing(null); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }
  async function remove(tariff: MasterTariff) {
    setWorking(tariff.id); setError(null);
    try { await masterApi.removeTariff(tariff.id); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }

  return <Box>
    <Box className="section-head"><Typography variant="h2">Тарифы</Typography>
      <Button variant="contained" onClick={() => setEditing({})}>Добавить тариф</Button></Box>
    <ErrorNotice error={error} />
    {busy && !tariffs.length ? <Box className="loading"><CircularProgress /></Box> :
      tariffs.length === 0 ? <Typography color="text.secondary">Тарифов пока нет.</Typography> :
        <Stack spacing={1.2} sx={{ mt: 2 }}>
          {tariffs.map(tariff => <Box className="device" key={tariff.id}>
            <Box className="device-main"><Box>
              <Typography fontWeight={600}>{tariff.name}</Typography>
              <Typography variant="body2" color="text.secondary">
                Лимит {tariff.device_limit} устройств · Срок {tariff.term_days} дн.
                {tariff.price_amount !== null ? ` · ${tariff.price_amount}` : ""}
              </Typography>
            </Box></Box>
            <Box className="device-actions">
              <Button variant="outlined" size="small" onClick={() => setEditing(tariff)}>Изменить</Button>
              <Button variant="outlined" size="small" color="error" disabled={working !== null} onClick={() => void remove(tariff)}>Удалить</Button>
            </Box>
          </Box>)}
        </Stack>}
    <Dialog open={editing !== null} onClose={() => setEditing(null)} aria-labelledby="tariff-title" fullWidth maxWidth="sm">
      <DialogTitle id="tariff-title">{editing?.id ? `Тариф ${editing.name}` : "Новый тариф"}</DialogTitle>
      <DialogContent>
        <Box component="form" onSubmit={save} className="form" sx={{ mt: 1 }}>
          <TextField label="Название" value={editing?.name ?? ""} onChange={e => setEditing(v => ({ ...v, name: e.target.value }))} required fullWidth autoFocus />
          <TextField label="Лимит устройств" type="number" value={editing?.device_limit ?? 1}
            onChange={e => setEditing(v => ({ ...v, device_limit: Number(e.target.value) }))} inputProps={{ min: 1 }} required fullWidth />
          <TextField label="Срок, дней" type="number" value={editing?.term_days ?? 30}
            onChange={e => setEditing(v => ({ ...v, term_days: Number(e.target.value) }))} inputProps={{ min: 1 }} required fullWidth />
          <TextField label="Цена (необязательно)" value={editing?.price_amount ?? ""}
            onChange={e => setEditing(v => ({ ...v, price_amount: e.target.value === "" ? undefined : Number(e.target.value) }))} fullWidth />
        </Box>
      </DialogContent>
      <DialogActions><Button onClick={() => setEditing(null)}>Отмена</Button>
        <Button variant="contained" disabled={working === "save"} onClick={() => void save()}>
          {working === "save" ? <CircularProgress size={16} /> : "Сохранить"}</Button></DialogActions>
    </Dialog>
  </Box>;
}

export function SubscribersPage() {
  const [subscribers, setSubscribers] = useState<MasterSubscriber[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<MasterSubscriber | null>(null);
  const [detail, setDetail] = useState<MasterSubscriber | null>(null);
  const [devices, setDevices] = useState<Awaited<ReturnType<typeof masterApi.subscriber>>["devices"]>([]);
  const [tariffs, setTariffs] = useState<MasterTariff[]>([]);
  const [assigning, setAssigning] = useState(false);
  const [tariffId, setTariffId] = useState("");
  const [working, setWorking] = useState<string | null>(null);

  async function load() { setBusy(true); try { setSubscribers((await masterApi.subscribers()).subscribers); } catch (reason) { setError(reason); } finally { setBusy(false); } }
  useEffect(() => { void load(); }, []);

  async function openSubscriber(subscriber: MasterSubscriber) {
    setOpen(subscriber); setError(null);
    try {
      const [d, t] = await Promise.all([masterApi.subscriber(subscriber.id), masterApi.tariffs()]);
      setDetail(d.subscriber); setDevices(d.devices); setTariffs(t.tariffs);
    } catch (reason) { setError(reason); }
  }
  async function assign(event?: FormEvent) {
    event?.preventDefault(); if (!detail) return;
    setWorking("assign"); setError(null);
    try { await masterApi.assignSubscription(detail.id, { tariff_id: Number(tariffId), days: tariffs.find(t => t.id === Number(tariffId))?.term_days }); setAssigning(false); await openSubscriber(detail); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }

  return <Box>
    <Box className="section-head"><Typography variant="h2">Абоненты</Typography></Box>
    <ErrorNotice error={error} />
    {busy && !subscribers.length ? <Box className="loading"><CircularProgress /></Box> :
      subscribers.length === 0 ? <Typography color="text.secondary">Абонентов пока нет.</Typography> :
        <Stack spacing={1.2} sx={{ mt: 2 }}>
          {subscribers.map(subscriber => <Box className="device" key={subscriber.id}>
            <Box className="device-main"><Box>
              <Typography fontWeight={600}>{subscriber.display_name}</Typography>
              <Typography variant="body2" color="text.secondary">
                Устройств: {subscriber.device_count} · {subscriber.subscription
                  ? `${subscriber.subscription.tariff_name}, до ${new Date(subscriber.subscription.expires_at).toLocaleDateString("ru-RU")}`
                  : "Подписка не назначена"}
              </Typography>
            </Box></Box>
            <Box className="device-actions">
              {subscriber.subscription && <Chip size="small" variant="outlined" label={subscriber.subscription.status === "active" ? "Активна" : "Истекла"} color={subscriber.subscription.status === "active" ? "success" : "error"} />}
              <Button variant="outlined" size="small" onClick={() => void openSubscriber(subscriber)}>Открыть</Button>
            </Box>
          </Box>)}
        </Stack>}
    <Dialog open={open !== null} onClose={() => setOpen(null)} aria-labelledby="subscriber-title" fullWidth maxWidth="sm">
      <DialogTitle id="subscriber-title">Абонент {open?.display_name}</DialogTitle>
      <DialogContent>
        <ErrorNotice error={error} />
        {detail?.subscription && <Typography variant="body2" color="text.secondary">
          Подписка: {detail.subscription.tariff_name}, до {new Date(detail.subscription.expires_at).toLocaleDateString("ru-RU")}</Typography>}
        <Button variant="outlined" size="small" sx={{ mt: 1 }} onClick={() => setAssigning(true)}>
          {detail?.subscription ? "Продлить/сменить тариф" : "Назначить подписку"}</Button>
        <Typography variant="h2" sx={{ mt: 3, mb: 1 }}>Устройства</Typography>
        {devices.length === 0 ? <Typography color="text.secondary">Устройств нет.</Typography> :
          devices.map(device => <Row key={device.id}>
            <Typography>{device.label}{device.name ? ` (${device.name})` : ""}</Typography>
            <Typography variant="body2" color="text.secondary">{device.node_name} · {device.status}</Typography>
          </Row>)}
      </DialogContent>
      <DialogActions><Button onClick={() => setOpen(null)}>Закрыть</Button></DialogActions>
    </Dialog>
    <Dialog open={assigning} onClose={() => setAssigning(false)} aria-labelledby="assign-title" fullWidth maxWidth="sm">
      <DialogTitle id="assign-title">Назначить подписку</DialogTitle>
      <DialogContent>
        <Box component="form" onSubmit={assign} className="form" sx={{ mt: 1 }}>
          <TextField select SelectProps={{ native: true }} label="Тариф" value={tariffId}
            onChange={e => setTariffId(e.target.value)} required fullWidth>
            <option value="" disabled>Выберите тариф</option>
            {tariffs.map(tariff => <option key={tariff.id} value={tariff.id}>{tariff.name} ({tariff.term_days} дн.)</option>)}
          </TextField>
        </Box>
      </DialogContent>
      <DialogActions><Button onClick={() => setAssigning(false)}>Отмена</Button>
        <Button variant="contained" disabled={!tariffId || working === "assign"} onClick={() => void assign()}>
          {working === "assign" ? <CircularProgress size={16} /> : "Назначить"}</Button></DialogActions>
    </Dialog>
  </Box>;
}
