import { Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { masterApi, MasterApiError, type MasterNode, type MasterRuleSets, type MasterSubscriber, type MasterTariff } from "./api";

export function ErrorNotice({ error }: { error: unknown }) {
  return error ? <Alert severity="error" sx={{ mb: 2 }}>{error instanceof Error ? error.message : "Ошибка"}</Alert> : null;
}

function StateChip({ state }: { state: MasterNode["state"] }) {
  const label = state === "ok" ? "Доступна" : state === "stale" ? "Нет ответа" : "Недоступна";
  return <Chip size="small" label={label} color={state === "ok" ? "success" : state === "stale" ? "warning" : "error"} variant="outlined" />;
}

function isSecureBridgeUrl(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && !!parsed.hostname && parsed.pathname === "/"
      && !parsed.username && !parsed.password && !parsed.search && !parsed.hash;
  } catch { return false; }
}

function nodeActionError(error: unknown) {
  if (error instanceof MasterApiError && error.code === "master.node_reissue_not_allowed") {
    return new MasterApiError(error.status, error.code,
      "Переиздание недоступно: нода уже связывалась с мастером или у неё есть устройства. Используйте обычную ротацию токена.");
  }
  return error;
}

function subscriberCreateError(error: unknown) {
  if (error instanceof MasterApiError && error.code === "master.subscriber_exists") {
    return new MasterApiError(error.status, error.code, "Абонент с таким Telegram ID уже существует.");
  }
  return error;
}

function isTelegramChatId(value: string) {
  return /^[1-9][0-9]{0,63}$/.test(value);
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
  const [issuedToken, setIssuedToken] = useState<{ name: string; token: string; bridgeUrl: string; masterHostname: string } | null>(null);
  const [reissueTarget, setReissueTarget] = useState<MasterNode | null>(null);

  function showIssuedToken(name: string, token: string, bridgeUrl: string) {
    setIssuedToken({ name, token, bridgeUrl, masterHostname: window.location.hostname });
  }

  async function load() {
    setBusy(true); setError(null);
    try { setNodes(await masterApi.nodes()); } catch (reason) { setError(reason); } finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);

  async function add(event?: FormEvent) {
    event?.preventDefault();
    if (!name.trim() || !isSecureBridgeUrl(url)) return;
    setWorking("create"); setError(null);
    try {
      const created = await masterApi.addNode({ name: name.trim(), bridge_url: url.trim(), capacity: Number(capacity) || 1 });
      showIssuedToken(created.name, created.token, created.bridge_url);
      setAdding(false); setName(""); setUrl(""); setCapacity("20");
      await load();
    } catch (reason) { setError(reason); } finally { setWorking(null); }
  }
  async function reissueToken(node: MasterNode) {
    setWorking(node.id); setError(null);
    try {
      const result = await masterApi.reissueNodeToken(node.id);
      setReissueTarget(null);
      showIssuedToken(node.name, result.token, node.bridge_url);
      await load();
    } catch (reason) { setError(nodeActionError(reason)); } finally { setWorking(null); }
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
                <Typography component="div" fontWeight={600}>{node.name} <StateChip state={node.state} /></Typography>
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
              {node.last_seen === null && <Button variant="outlined" size="small" disabled={working !== null}
                aria-label={`Переиздать токен для ${node.name}`} onClick={() => setReissueTarget(node)}>
                Переиздать токен</Button>}
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
          <TextField label="Имя ноды" name="node-name" autoComplete="off" value={name} onChange={e => setName(e.target.value)} required fullWidth />
          <TextField label="Bridge URL ноды" name="node-bridge-url" autoComplete="off" value={url} onChange={e => setUrl(e.target.value)} type="url" inputProps={{ maxLength: 255, spellCheck: false }} required fullWidth
            error={!!url && !isSecureBridgeUrl(url)} helperText="Например, https://rg3.poshl9k.ru. Только HTTPS; без логина, пароля, пути (кроме /), query-параметров и fragment" />
          <TextField label="Ёмкость (активных устройств)" name="node-capacity" autoComplete="off" type="number" value={capacity} onChange={e => setCapacity(e.target.value)} inputProps={{ min: 1 }} required fullWidth />
        </Box>
      </DialogContent>
      <DialogActions><Button onClick={() => setAdding(false)}>Отмена</Button>
        <Button variant="contained" disabled={!name.trim() || !isSecureBridgeUrl(url) || working === "create"} onClick={() => void add()}>
          {working === "create" ? <CircularProgress size={16} /> : "Создать"}</Button></DialogActions>
    </Dialog>
    <Dialog open={reissueTarget !== null} onClose={() => setReissueTarget(null)} aria-labelledby="reissue-token-title" fullWidth maxWidth="sm">
      <DialogTitle id="reissue-token-title">Переиздать токен?</DialogTitle>
      <DialogContent>
        <Alert severity="warning">Это заменит прежний токен. Действие доступно, пока нода ещё не связывалась с мастером; после подтверждения старый токен перестанет работать.</Alert>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setReissueTarget(null)}>Отмена</Button>
        <Button variant="contained" disabled={working !== null} onClick={() => {
          if (reissueTarget) void reissueToken(reissueTarget);
        }}>{working === reissueTarget?.id ? <CircularProgress size={16} /> : "Переиздать токен"}</Button>
      </DialogActions>
    </Dialog>
    <Dialog open={issuedToken !== null} onClose={() => setIssuedToken(null)} aria-labelledby="token-title" fullWidth maxWidth="sm">
      <DialogTitle id="token-title">Токен ноды {issuedToken?.name}</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>Токен показывается один раз. Не отправляйте его в чат; сразу установите его через админ-панель ноды.</Alert>
        <Typography translate="no" sx={{ wordBreak: "break-all", fontFamily: "monospace" }}>{issuedToken?.token}</Typography>
        <Typography variant="body2" sx={{ mt: 2 }}>Подключение без SSH: откройте админ-панель ноды по HTTPS, затем выберите «Обслуживание» → «Мастер». Вставьте токен и укажите домен мастера <strong>{issuedToken?.masterHostname}</strong> и его внешний IP-адрес для связи с нодой.</Typography>
        {issuedToken?.bridgeUrl && isSecureBridgeUrl(issuedToken.bridgeUrl)
          ? <Button component="a" href={issuedToken.bridgeUrl} target="_blank" rel="noopener noreferrer" sx={{ mt: 1 }}>Открыть панель ноды</Button>
          : <Alert severity="error" sx={{ mt: 1 }}>Сохранённый адрес ноды не использует безопасный HTTPS. Не открывайте его и не вводите там токен; откройте ноду по проверенному HTTPS-адресу. Сохранённую ссылку нужно исправить отдельно.</Alert>}
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

  async function load() { setBusy(true); try { setTariffs(await masterApi.tariffs()); } catch (reason) { setError(reason); } finally { setBusy(false); } }
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
      <Button variant="contained" onClick={() => setEditing({ device_limit: 1, term_days: 30, price_amount: null })}>Добавить тариф</Button></Box>
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
  const [adding, setAdding] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [telegramChatId, setTelegramChatId] = useState("");
  const [createError, setCreateError] = useState<unknown>(null);
  const telegramIdInput = useRef<HTMLInputElement>(null);
  const telegramIdConflict = createError instanceof MasterApiError
    && createError.code === "master.subscriber_exists";

  async function load() { setBusy(true); try { setSubscribers(await masterApi.subscribers()); } catch (reason) { setError(reason); } finally { setBusy(false); } }
  useEffect(() => { void load(); }, []);
  useEffect(() => { if (telegramIdConflict) telegramIdInput.current?.focus(); }, [telegramIdConflict]);

  async function openSubscriber(subscriber: MasterSubscriber) {
    setOpen(subscriber); setError(null);
    try {
      const [d, t] = await Promise.all([masterApi.subscriber(subscriber.id), masterApi.tariffs()]);
      setDetail(d); setDevices(d.devices); setTariffs(t);
    } catch (reason) { setError(reason); }
  }
  async function assign(event?: FormEvent) {
    event?.preventDefault(); if (!detail) return;
    setWorking("assign"); setError(null);
    try { await masterApi.assignSubscription(detail.id, { tariff_id: Number(tariffId), days: tariffs.find(t => t.id === Number(tariffId))?.term_days }); setAssigning(false); await openSubscriber(detail); await load(); }
    catch (reason) { setError(reason); } finally { setWorking(null); }
  }

  async function createSubscriber(event?: FormEvent) {
    event?.preventDefault();
    if (!displayName.trim() || !isTelegramChatId(telegramChatId)) return;
    setWorking("create-subscriber"); setCreateError(null);
    try {
      await masterApi.createSubscriber({ display_name: displayName.trim(), telegram_chat_id: telegramChatId });
      setAdding(false); setDisplayName(""); setTelegramChatId("");
      await load();
    } catch (reason) { setCreateError(subscriberCreateError(reason)); } finally { setWorking(null); }
  }

  function closeCreate() {
    if (working === "create-subscriber") return;
    setAdding(false); setDisplayName(""); setTelegramChatId(""); setCreateError(null);
  }

  return <Box>
    <Box className="section-head"><Typography variant="h2">Абоненты</Typography>
      <Button variant="contained" onClick={() => { setCreateError(null); setAdding(true); }}>Добавить абонента</Button></Box>
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
    <Dialog open={adding} onClose={closeCreate} aria-labelledby="new-subscriber-title" fullWidth maxWidth="sm">
      <Box component="form" onSubmit={createSubscriber}>
        <DialogTitle id="new-subscriber-title">Новый абонент</DialogTitle>
        <DialogContent>
          <ErrorNotice error={telegramIdConflict ? null : createError} />
          <Box className="form" sx={{ mt: 1 }}>
            <TextField label="Имя абонента" name="subscriber-display-name" autoComplete="off"
              value={displayName} onChange={e => setDisplayName(e.target.value)} inputProps={{ maxLength: 64 }}
              required fullWidth disabled={working === "create-subscriber"} />
            <TextField label="Telegram ID" name="subscriber-telegram-id" autoComplete="off"
              inputRef={telegramIdInput}
              value={telegramChatId} onChange={e => { setTelegramChatId(e.target.value); setCreateError(null); }}
              inputProps={{ inputMode: "numeric", maxLength: 64 }} required fullWidth
              error={telegramIdConflict || (!!telegramChatId && !isTelegramChatId(telegramChatId))}
              helperText={telegramIdConflict
                ? "Абонент с таким Telegram ID уже существует. Укажите другой ID."
                : telegramChatId && !isTelegramChatId(telegramChatId)
                  ? "Введите положительный Telegram ID цифрами без пробелов."
                  : "После /start в боте Telegram запись привяжется к чату. Подписку назначьте отдельно."}
              slotProps={{ formHelperText: { "aria-live": "polite" } }}
              disabled={working === "create-subscriber"} />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCreate} disabled={working === "create-subscriber"}>Отмена</Button>
          <Button type="submit" variant="contained"
            disabled={!displayName.trim() || !isTelegramChatId(telegramChatId) || working === "create-subscriber"}>
            {working === "create-subscriber" ? <CircularProgress size={16} /> : "Создать"}</Button>
        </DialogActions>
      </Box>
    </Dialog>
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

export function RuleSetsPage() {
  const [data, setData] = useState<MasterRuleSets | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState<"domain" | "ipcidr">("domain");
  const [version, setVersion] = useState("");
  const [content, setContent] = useState("");

  useEffect(() => {
    masterApi.rulesets().then(setData).catch(setError);
  }, []);

  async function publish(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError(null);
    try {
      await masterApi.publishRuleSet({ kind, version: version.trim(), content });
      setData(await masterApi.rulesets());
      setVersion(""); setContent("");
    } catch (reason) { setError(reason); } finally { setBusy(false); }
  }

  return <Box>
    <Typography component="h2" variant="h5" sx={{ mb: 1 }}>Наборы правил</Typography>
    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
      Версии неизменяемы: исправление — новая версия. Клиент забирает набор по точной версии,
      а сами адреса РФ идут мимо туннеля.
    </Typography>
    <ErrorNotice error={error} />
    {data === null ? <Box className="loading"><CircularProgress /></Box> : <>
      <Stack direction="row" spacing={2} sx={{ mb: 2, flexWrap: "wrap" }}>
        {(["domain", "ipcidr"] as const).map(key => {
          const current = data.current[key];
          return <Box key={key} sx={{ p: 1.5, border: "1px solid", borderColor: "divider",
            borderRadius: 1, minWidth: 240 }}>
            <Typography fontWeight={600}>{key === "domain" ? "Домены" : "IP-сети"}</Typography>
            <Typography variant="body2" color="text.secondary">
              {current ? `${current.version} · ${current.entries} записей` : "не опубликован"}
            </Typography>
            {current && <Typography variant="caption" color="text.secondary">
              {current.sha256.slice(0, 12)}…</Typography>}
          </Box>;
        })}
      </Stack>
      <Box component="form" onSubmit={publish} className="form" sx={{ maxWidth: 640, mb: 3 }}>
        <Typography component="h3" variant="h6">Опубликовать версию</Typography>
        <TextField select label="Тип" value={kind} margin="dense" fullWidth
          onChange={event => setKind(event.target.value as "domain" | "ipcidr")}
          SelectProps={{ native: true }}>
          <option value="domain">Домены</option>
          <option value="ipcidr">IP-сети</option>
        </TextField>
        <TextField label="Версия" value={version} margin="dense" fullWidth
          onChange={event => setVersion(event.target.value)} placeholder="ru-2026-11-01"
          inputProps={{ maxLength: 32 }} />
        <TextField label="Содержимое" value={content} margin="dense" fullWidth multiline minRows={8}
          onChange={event => setContent(event.target.value)}
          placeholder={kind === "domain" ? "example.com\n+.example.net" : "5.5.5.0/24"} />
        <Button type="submit" variant="contained" disabled={busy || !version.trim() || !content.trim()}>
          {busy ? <CircularProgress size={18} /> : "Опубликовать"}</Button>
      </Box>
      <Stack spacing={1}>
        {data.rulesets.map(row => <Box key={row.id} sx={{ display: "flex", gap: 2, alignItems: "center",
          p: 1, borderBottom: "1px solid", borderColor: "divider" }}>
          <Chip size="small" variant="outlined" label={row.kind === "domain" ? "домены" : "IP"} />
          <Typography sx={{ minWidth: 180 }}>{row.version}</Typography>
          <Typography variant="body2" color="text.secondary">{row.entries} записей</Typography>
          <Typography variant="caption" color="text.secondary">{row.sha256.slice(0, 12)}…</Typography>
        </Box>)}
        {data.rulesets.length === 0 && <Typography color="text.secondary">
          Пока нет опубликованных версий.</Typography>}
      </Stack>
    </>}
  </Box>;
}
