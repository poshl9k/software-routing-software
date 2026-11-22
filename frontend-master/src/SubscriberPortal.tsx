import { Alert, Box, Button, Card as MuiCard, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { MasterApiError, portalApi, type PortalDevice, type PortalExportFormat, type PortalMe, type PortalOperation, type PortalSubscription } from "./api";

function Page({ title, children }: { title: string; children: ReactNode }) {
  return <Box className="page">
    <Box component="header" className="topbar">
      <Link className="brand" to="/portal">VS <span>PORTAL</span></Link>
      <Typography color="text.secondary">Защищённый доступ</Typography>
    </Box>
    <Box component="main" className="content">
      <Typography component="h1" variant="h1" sx={{ mb: 3, overflowWrap: "anywhere",
        fontSize: { xs: "2rem", sm: "3rem", md: "3.6rem" } }}>{title}</Typography>
      {children}
    </Box>
    <Box component="footer" className="footer">Портал абонента · vs-master</Box>
  </Box>;
}

export const PASSWORD_LOGIN_PATH = "/portal/login?method=password";

export function PortalLogin() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true); setError(null);
    try {
      await portalApi.login(String(data.get("username") ?? ""), String(data.get("password") ?? ""));
      form.reset();
      navigate("/portal", { replace: true });
    } catch {
      const password = form.elements.namedItem("password") as HTMLInputElement;
      password.value = "";
      setError("Не удалось войти. Проверьте имя и пароль или попробуйте позже.");
    } finally { setBusy(false); }
  }
  return <Page title="Личный кабинет">
    <Alert severity="info" role="note">Откройте ссылку из Telegram-бота, чтобы войти в кабинет.</Alert>
    {params.get("method") === "password" ? <Box component="form" onSubmit={submit}
      className="form" sx={{ maxWidth: 440, mt: 3 }} aria-busy={busy}>
      <TextField label="Имя абонента" name="username" autoComplete="username" required fullWidth
        inputProps={{ maxLength: 64 }} disabled={busy} />
      <TextField label="Пароль" name="password" type="password" autoComplete="current-password"
        required fullWidth inputProps={{ maxLength: 1024 }} disabled={busy} />
      <ErrorNotice error={error} />
      <Button type="submit" variant="contained" disabled={busy}>{busy ? "Вход…" : "Войти"}</Button>
      <Button component={Link} to="/portal/password/forgot">Забыли пароль?</Button>
    </Box> : <Button component={Link} to={PASSWORD_LOGIN_PATH} variant="contained" sx={{ mt: 3 }}>Войти по паролю</Button>}
  </Page>;
}

export function PortalPasswordForgot() {
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const data = new FormData(event.currentTarget);
    setBusy(true); setError(null); setSent(false);
    try {
      await portalApi.forgotPassword(String(data.get("email") ?? "").trim());
      setSent(true);
    } catch { setError("Не удалось отправить запрос. Попробуйте позже."); }
    finally { setBusy(false); }
  }
  return <Page title="Восстановление пароля">
    <Box component="form" onSubmit={submit} className="form" sx={{ maxWidth: 440 }} aria-busy={busy}>
      <Alert severity="info" role="note">Укажите подтверждённую почту, привязанную в личном кабинете.</Alert>
      <TextField label="Электронная почта" name="email" type="email" autoComplete="email"
        required fullWidth inputProps={{ maxLength: 254 }} disabled={busy} />
      <ErrorNotice error={error} />
      {sent && <Alert severity="success" role="status">Если адрес привязан к аккаунту, на него придёт ссылка для восстановления пароля.</Alert>}
      <Button type="submit" variant="contained" disabled={busy}>{busy ? "Отправка…" : "Отправить ссылку"}</Button>
      <Button component={Link} to={PASSWORD_LOGIN_PATH}>Вернуться ко входу</Button>
    </Box>
  </Page>;
}

export function PortalPasswordReset({ token }: { token: string | null }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : "Ссылка недействительна. Запросите новую в форме восстановления пароля.");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !token) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const password = String(data.get("password") ?? "");
    if (password !== String(data.get("confirm") ?? "")) {
      setError("Пароли не совпадают");
      return;
    }
    setBusy(true); setError(null);
    try {
      await portalApi.resetPassword(token, password);
      form.reset();
      setDone(true);
    } catch {
      setError("Не удалось сменить пароль. Ссылка могла истечь; запросите новую.");
    } finally { setBusy(false); }
  }

  return <Page title="Новый пароль">
    {done ? <Stack spacing={2} sx={{ maxWidth: 440 }}>
      <Alert severity="success" role="status">Пароль изменён. Войдите в кабинет с новым паролем.</Alert>
      <Alert severity="info" role="note">Прежние веб-сессии отозваны. Сохранённые ссылки доступа и настройки клиентских приложений остаются действительными.</Alert>
      <Button component={Link} to={PASSWORD_LOGIN_PATH} variant="contained">Войти по паролю</Button>
    </Stack> : <Box component="form" onSubmit={submit} className="form" sx={{ maxWidth: 440 }} aria-busy={busy}>
      <TextField label="Новый пароль" name="password" type="password" autoComplete="new-password"
        required fullWidth inputProps={{ minLength: 12, maxLength: 1024 }} disabled={busy} />
      <TextField label="Повторите новый пароль" name="confirm" type="password" autoComplete="new-password"
        required fullWidth inputProps={{ minLength: 12, maxLength: 1024 }} disabled={busy} />
      <ErrorNotice error={error} />
      <Button type="submit" variant="contained" disabled={busy || !token}>{busy ? "Сохранение…" : "Сохранить пароль"}</Button>
      <Button component={Link} to="/portal/password/forgot">Запросить новую ссылку</Button>
    </Box>}
  </Page>;
}

export function PortalEmailConfirm({ token }: { token: string | null }) {
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : "Ссылка недействительна. Запросите новое письмо в кабинете.");
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    // Match magic sign-in: avoid consuming a one-shot proof in StrictMode replay.
    const timer = window.setTimeout(() => {
      void portalApi.confirmEmail(token).then(() => {
        if (!cancelled) setConfirmed(true);
      }).catch(() => {
        if (!cancelled) setError("Не удалось подтвердить почту. Запросите новое письмо в кабинете.");
      });
    }, 0);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [token]);
  return <Page title="Подтверждение почты">
    <Box sx={{ maxWidth: 440 }}>
      <ErrorNotice error={error} />
      {confirmed && <Alert severity="success" role="status">Почта подтверждена.</Alert>}
      {!confirmed && !error && <CircularProgress aria-label="Подтверждение почты" />}
      <Button component={Link} to="/portal" sx={{ mt: 2 }}>Открыть кабинет</Button>
    </Box>
  </Page>;
}

export function MagicSignIn({ proof, kind = "magic" }: { proof: string; kind?: "magic" | "link" }) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!proof) { setError("Ссылка недействительна. Запросите новую в Telegram-боте."); return; }
    let cancelled = false;
    // Defer the one-shot POST until after StrictMode's development effect replay.
    const timer = window.setTimeout(() => {
      const signIn = kind === "link" ? portalApi.loginLink(proof) : portalApi.magic(proof);
      void signIn.then(() => {
        if (!cancelled) navigate("/portal", { replace: true });
      }).catch((reason: unknown) => {
        if (cancelled) return;
        setError(reason instanceof MasterApiError && reason.status === 401
          ? "Ссылка недействительна. Запросите новую в Telegram-боте."
          : "Не удалось войти. Попробуйте позже или запросите новую ссылку.");
      });
    }, 0);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [kind, navigate, proof]);
  return <Page title="Вход в личный кабинет">
    {error ? <Alert severity="error">{error}</Alert> : <CircularProgress aria-label="Проверка ссылки" />}
  </Page>;
}

function ErrorNotice({ error, onRetry }: { error: string | null; onRetry?: () => void }) {
  return error ? <Alert severity="error" action={onRetry &&
    <Button color="inherit" size="small" onClick={onRetry}>Обновить</Button>}>{error}</Alert> : null;
}

function operationText(result: PortalOperation) {
  return result.status === "applied" ? "Применено" : "Ожидает применения";
}

function handshake(value: number | null) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return "Нет данных";
  const days = Math.floor(Math.max(0, Date.now() - value * 1000) / 86_400_000);
  return days === 0 ? "Недавно" : `${days} дн. назад`;
}

function PortalEmailBinding({ email }: { email: string | null }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const data = new FormData(event.currentTarget);
    setBusy(true); setError(null); setSent(false);
    try {
      await portalApi.requestEmail(String(data.get("email") ?? "").trim());
      setSent(true);
    } catch (reason) {
      if (reason instanceof MasterApiError && reason.status === 401) navigate("/portal/login", { replace: true });
      else setError("Не удалось отправить запрос. Попробуйте позже.");
    } finally { setBusy(false); }
  }
  return <MuiCard className="surface" elevation={0} sx={{ mt: 3 }}>
    <Typography component="h2" variant="h2" sx={{ mb: 2 }}>Почта для восстановления пароля</Typography>
    <Typography sx={{ mb: 2, overflowWrap: "anywhere" }}>
      {email ? `Подтверждённая почта: ${email}` : "Почта не привязана"}
    </Typography>
    <Box component="form" onSubmit={submit} className="form" sx={{ maxWidth: 440 }} aria-busy={busy}>
      <TextField label="Электронная почта" name="email" type="email" autoComplete="email"
        required fullWidth inputProps={{ maxLength: 254 }} disabled={busy}
        helperText="Откройте ссылку из письма, чтобы подтвердить адрес." />
      <ErrorNotice error={error} />
      {sent && <Alert severity="success" role="status">Если адрес доступен, на него придёт письмо. До подтверждения привязанная почта не изменится.</Alert>}
      <Button type="submit" variant="contained" disabled={busy}>{busy ? "Отправка…" : "Подтвердить почту"}</Button>
    </Box>
  </MuiCard>;
}

export function PortalHome() {
  const navigate = useNavigate();
  const [me, setMe] = useState<PortalMe | null>(null);
  const [devices, setDevices] = useState<PortalDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [dialog, setDialog] = useState<"add" | "remove" | "rotate-link" | null>(null);
  const [target, setTarget] = useState<PortalDevice | null>(null);
  const [label, setLabel] = useState("");
  const [working, setWorking] = useState<number | "create" | null>(null);
  const [qr, setQr] = useState<{ title: string; url: string } | null>(null);
  const [amnezia, setAmnezia] = useState<{ title: string; uri: string; qr: string | null } | null>(null);
  const [link, setLink] = useState<{ device: PortalDevice; url: string | null; qr: string | null;
    clashUrl: string | null; singboxUrl: string | null; state: PortalSubscription } | null>(null);
  const [rotateAsk, setRotateAsk] = useState(false);

  function showError(reason: unknown, fallback: string) {
    if (reason instanceof MasterApiError && reason.status === 401) {
      navigate("/portal/login", { replace: true });
      return;
    }
    const known: Record<string, string> = {
      "portal.device_limit": "Достигнут лимит устройств по тарифу.",
      "portal.subscription_expired": "Подписка не активна. Обновите страницу.",
      "portal.export_unavailable": "Конфигурация пока недоступна. Попробуйте позже.",
      "portal.operation_pending": "Операция ещё выполняется. Обновите страницу позже.",
      "master.no_node_available": "Сейчас нет доступной ноды. Попробуйте позже.",
      "amnezia.role_unsupported": "Amnezia недоступна для этого устройства.",
    };
    setError(reason instanceof MasterApiError && reason.status === 0 ? reason.message
      : reason instanceof MasterApiError ? known[reason.code] ?? fallback : fallback);
  }

  async function load() {
    setError(null);
    try {
      const account = await portalApi.me();
      setMe(account);
      const list = await portalApi.devices();
      setDevices(list.devices.filter(device => device.status !== "removed"));
    } catch (reason) {
      setDevices(null);
      showError(reason, "Не удалось загрузить кабинет. Попробуйте позже.");
    }
  }

  useEffect(() => { void load(); }, []);
  useEffect(() => {
    if (!devices?.some(device => device.pending_op)) return;
    const timer = window.setTimeout(() => { void load(); }, 4000);
    return () => window.clearTimeout(timer);
  }, [devices]);
  useEffect(() => () => { if (qr) URL.revokeObjectURL(qr.url); }, [qr]);
  useEffect(() => () => { if (amnezia?.qr) URL.revokeObjectURL(amnezia.qr); }, [amnezia]);

  async function rotateLogin() {
    setError(null);
    try {
      await portalApi.rotateLoginLink();
      setNotice("Ссылка входа обновлена. Откройте бота и нажмите «Личный кабинет», чтобы получить новую.");
      setDialog(null);
    } catch (reason) { showError(reason, "Не удалось обновить ссылку входа."); }
  }

  async function logout() {
    try { await portalApi.logout(); navigate("/portal/login", { replace: true }); }
    catch (reason) { showError(reason, "Не удалось завершить сеанс. Попробуйте ещё раз."); }
  }

  async function add() {
    const name = label.trim();
    if (!name || working !== null) return;
    setWorking("create"); setError(null);
    try {
      const result = await portalApi.createDevice(name);
      setNotice(operationText(result));
      setLabel(""); setDialog(null);
      await load();
    } catch (reason) { showError(reason, "Не удалось добавить устройство. Проверьте состояние подписки и ноды."); }
    finally { setWorking(null); }
  }

  async function change(device: PortalDevice, kind: "delete" | "toggle") {
    if (working !== null) return;
    setWorking(device.id); setError(null);
    try {
      const result = kind === "delete" ? await portalApi.removeDevice(device.id)
        : await portalApi.setDeviceActive(device.id, device.status !== "active");
      setNotice(operationText(result));
      setDialog(null); setTarget(null);
      await load();
    } catch (reason) { showError(reason, "Не удалось изменить устройство. Попробуйте ещё раз."); }
    finally { setWorking(null); }
  }

  async function exportConfig(device: PortalDevice, format: PortalExportFormat) {
    setError(null);
    const title = device.label || device.name || `Устройство ${device.id}`;
    try {
      if (format === "amnezia") {
        const uri = await portalApi.amneziaUri(device.id);
        if (!uri.startsWith("vpn://")) throw new MasterApiError(400, "amnezia.role_unsupported", "Неверный формат");
        // Amnezia adds a connection by scanning the same vpn:// container, so the
        // dialog offers both the deep link and a QR of it.
        let qrUrl: string | null = null;
        try { qrUrl = URL.createObjectURL(await portalApi.exportDevice(device.id, "amnezia-qr")); }
        catch { qrUrl = null; }
        setAmnezia({ title, uri, qr: qrUrl });
        return;
      }
      const blob = await portalApi.exportDevice(device.id, format);
      if (format === "qr") {
        setQr({ title, url: URL.createObjectURL(blob) });
        return;
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const suffix: Record<string, string> = { mihomo: ".yaml", vless: "-vless.txt" };
      a.download = `${title}${suffix[format] ?? ".conf"}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (reason) { showError(reason, "Не удалось скачать конфигурацию."); }
  }

  async function openSubscription(device: PortalDevice) {
    setError(null);
    try {
      const state = await portalApi.subscriptionState(device.id);
      // The link is stable: the cabinet shows the same one (and its QR) on every
      // visit instead of rotating it.
      setLink({ device, url: state.url, qr: state.qr, clashUrl: state.clash_url,
        singboxUrl: state.singbox_url, state });
      setRotateAsk(false);
    } catch (reason) { showError(reason, "Не удалось открыть подписку."); }
  }

  async function issueSubscription() {
    if (!link) return;
    setError(null);
    try {
      const issued = await portalApi.issueSubscription(link.device.id);
      setLink({ ...link, url: issued.url, qr: issued.qr, clashUrl: issued.clash_url,
        singboxUrl: issued.singbox_url,
        state: { ...link.state, active: true, created_at: issued.created_at } });
    } catch (reason) { showError(reason, "Не удалось создать ссылку."); }
  }

  async function rotateSubscription() {
    if (!link) return;
    setError(null);
    try {
      const rotated = await portalApi.rotateSubscription(link.device.id);
      setLink({ ...link, url: rotated.url, qr: rotated.qr, clashUrl: rotated.clash_url,
        singboxUrl: rotated.singbox_url,
        state: { ...link.state, active: true, created_at: rotated.created_at, last_used_at: null } });
      setRotateAsk(false);
      setNotice("Ссылка перевыпущена. Старая ссылка больше не работает — обновите её в клиенте.");
    } catch (reason) { showError(reason, "Не удалось перевыпустить ссылку."); }
  }

  async function revokeSubscription() {
    if (!link) return;
    setError(null);
    try {
      await portalApi.revokeSubscription(link.device.id);
      setLink({ ...link, url: null, qr: null, clashUrl: null, singboxUrl: null,
        state: { active: false, created_at: null, last_used_at: null, url: null, qr: null,
          clash_url: null, singbox_url: null } });
    } catch (reason) { showError(reason, "Не удалось отозвать ссылку."); }
  }

  const subscription = me?.subscription;
  const active = subscription?.status === "active";
  const count = devices?.length ?? 0;
  const limit = subscription?.tariff?.device_limit;
  const canAdd = active && devices !== null && limit !== undefined && count < limit;
  const remaining = subscription ? Math.ceil((new Date(subscription.expires_at).getTime() - Date.now()) / 86_400_000) : null;

  return <Page title={me ? `Здравствуйте, ${me.account.display_name}` : "Личный кабинет"}>
    {me && <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
      <Typography color="text.secondary">Управляйте своими устройствами</Typography>
      <Stack direction="row" spacing={1}>
        <Button onClick={() => setDialog("rotate-link")}>Обновить ссылку входа</Button>
        <Button onClick={() => void logout()} aria-label="Выйти из аккаунта">Выйти</Button>
      </Stack>
    </Stack>}
    {dialog === null && <ErrorNotice error={error} onRetry={() => void load()} />}
    {notice && <Alert severity="info" onClose={() => setNotice("")}>{notice}</Alert>}
    {!me && !error && <Box className="loading"><CircularProgress aria-label="Загрузка кабинета" /></Box>}
    {me && <>
      <MuiCard className="surface subscription" elevation={0}>
        <Typography variant="overline" color="text.secondary">ПОДПИСКА</Typography>
        <Box className="subscription-line">
          <Box>
            <Typography variant="h2">{subscription?.tariff?.name ?? "Тариф не указан"}</Typography>
            <Typography color="text.secondary">{subscription
              ? `Действует до ${new Date(subscription.expires_at).toLocaleDateString("ru-RU")}`
              : "Срок действия не указан"}</Typography>
          </Box>
          <Chip label={active ? "Активна" : subscription ? "Истекла" : "Не назначена"}
            color={active ? "success" : subscription ? "error" : "default"} variant="outlined" />
        </Box>
        {!subscription && <Alert severity="info" sx={{ mt: 2 }}>Подписка пока не активна</Alert>}
        {subscription?.status === "expired" && <Alert severity="error" sx={{ mt: 2 }}>
          Подписка истекла. Обратитесь к администратору для продления.
        </Alert>}
        {active && remaining !== null && remaining <= 7 && <Alert severity="warning" sx={{ mt: 2 }}>
          Подписка истекает через {remaining} дн.
        </Alert>}
        {subscription?.tariff && <Typography className="limit-note" color="text.secondary">
          На этом тарифе разрешено {limit} устройства. Используется: {count}.
        </Typography>}
      </MuiCard>

      <MuiCard className="surface devices" elevation={0}>
        <Box className="section-head">
          <Box><Typography variant="h2">Устройства</Typography>
            <Typography color="text.secondary" variant="body2">Ключи и адреса сохраняются при деактивации</Typography>
          </Box>
          <Button variant="contained" disabled={!canAdd || working !== null} onClick={() => setDialog("add")}>Добавить устройство</Button>
        </Box>
        {active && limit !== undefined && count >= limit && <Alert severity="warning" sx={{ mt: 2 }}>
          Достигнут лимит тарифа. Удалите устройство или обратитесь к администратору.
        </Alert>}
        {devices === null ? !error && <Box className="loading"><CircularProgress aria-label="Загрузка устройств" /></Box>
          : devices.length === 0 ? <Box sx={{ py: 5, textAlign: "center", color: "text.secondary" }}>
            <Typography fontWeight={600} color="text.primary">Устройств пока нет</Typography>
            <Typography sx={{ mt: 1 }}>Добавьте первое устройство, чтобы подключиться к VPN.</Typography>
          </Box> : <Stack spacing={1.2} sx={{ mt: 2 }}>{devices.map(device => {
            const exportReady = active && !!device.name && !device.pending_op;
            return <Box className="device" key={device.id}>
              <Box className="device-main">
                <Box className="device-avatar" aria-hidden="true">
                  {(device.label || device.name || "?").slice(0, 1).toUpperCase()}
                </Box>
                <Box><Typography fontWeight={600}>{device.label || device.name || `Устройство ${device.id}`}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {device.name ?? `#${device.id}`} · {handshake(device.last_handshake)}
                  </Typography>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.7 }}>
                    <Chip size="small" label={device.pending_op ? "Применяется…"
                      : device.status === "active" ? "Включено" : "Отключено"}
                      color={device.pending_op ? "info" : device.status === "active" ? "success" : "default"}
                      variant="outlined" />
                    <Chip size="small" label={device.applied ? "Применено"
                      : device.pending_op ? "Ожидает применения" : "Не применено"} variant="outlined" />
                  </Stack>
                </Box>
              </Box>
              <Box className="device-actions">
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void exportConfig(device, "conf")}>Скачать .conf</Button>
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void exportConfig(device, "qr")}>QR</Button>
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void exportConfig(device, "amnezia")}>Amnezia</Button>
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void exportConfig(device, "mihomo")}>Clash / mihomo</Button>
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void exportConfig(device, "vless")}>VLESS / iOS</Button>
                <Button variant="outlined" size="small" disabled={!exportReady || working !== null}
                  onClick={() => void openSubscription(device)}>Ссылка-подписка</Button>
                <Button variant="outlined" size="small" disabled={!active || !!device.pending_op || working !== null}
                  onClick={() => void change(device, "toggle")}>{working === device.id ? <CircularProgress size={16} />
                    : device.status === "active" ? "Деактивировать" : "Активировать"}</Button>
                <Button variant="outlined" size="small" color="error" aria-label={`Удалить устройство ${device.label || device.name || device.id}`}
                  disabled={!active || !!device.pending_op || working !== null}
                  onClick={() => { setTarget(device); setDialog("remove"); }}>Удалить</Button>
              </Box>
            </Box>;
          })}</Stack>}
      </MuiCard>
      <PortalEmailBinding email={me.account.email ?? null} />
    </>}

    <Dialog open={dialog === "rotate-link"} onClose={() => setDialog(null)} aria-labelledby="rotate-link-title" fullWidth maxWidth="sm">
      <DialogTitle id="rotate-link-title">Обновить ссылку входа?</DialogTitle>
      <DialogContent><Typography>
        Старая ссылка перестанет работать. Новая придёт в боте по кнопке «Личный кабинет»;
        на других устройствах сеанс сохранится до истечения срока.
      </Typography><ErrorNotice error={error} /></DialogContent>
      <DialogActions><Button onClick={() => setDialog(null)}>Отмена</Button>
        <Button variant="contained" onClick={() => void rotateLogin()}>Обновить ссылку</Button></DialogActions>
    </Dialog>
    <Dialog open={dialog === "add"} onClose={() => setDialog(null)} aria-labelledby="add-title" fullWidth maxWidth="sm">
      <DialogTitle id="add-title">Добавить устройство</DialogTitle>
      <DialogContent><TextField autoFocus margin="dense" label="Метка устройства" value={label}
        onChange={event => setLabel(event.target.value)} inputProps={{ maxLength: 128 }} fullWidth />
        <ErrorNotice error={error} /></DialogContent>
      <DialogActions><Button onClick={() => setDialog(null)}>Отмена</Button>
        <Button variant="contained" disabled={!label.trim() || working !== null} onClick={() => void add()}>
          {working === "create" ? <CircularProgress size={16} /> : "Добавить"}</Button></DialogActions>
    </Dialog>
    <Dialog open={dialog === "remove"} onClose={() => setDialog(null)} aria-labelledby="remove-title" fullWidth maxWidth="sm">
      <DialogTitle id="remove-title">Удалить устройство?</DialogTitle>
      <DialogContent><Typography>«{target?.label || target?.name}» будет удалено безвозвратно. Ключи восстановить нельзя.</Typography>
        <ErrorNotice error={error} /></DialogContent>
      <DialogActions><Button onClick={() => setDialog(null)}>Отмена</Button>
        <Button variant="contained" color="error" disabled={working !== null || !target}
          onClick={() => { if (target) void change(target, "delete"); }}>Удалить устройство</Button></DialogActions>
    </Dialog>
    <Dialog open={qr !== null} onClose={() => setQr(null)} aria-labelledby="qr-title" fullWidth maxWidth="sm">
      <DialogTitle id="qr-title">QR: {qr?.title}</DialogTitle>
      <DialogContent sx={{ textAlign: "center" }}>
        {qr && <img src={qr.url} alt={`QR-код конфигурации устройства ${qr.title}`}
          style={{ width: "min(280px, 100%)", height: "auto" }} />}
      </DialogContent>
      <DialogActions><Button onClick={() => {
        if (!qr) return;
        const a = document.createElement("a"); a.href = qr.url; a.download = `${qr.title}.png`; a.click();
      }}>Скачать PNG</Button><Button onClick={() => setQr(null)}>Закрыть</Button></DialogActions>
    </Dialog>
    <Dialog open={link !== null} onClose={() => setLink(null)} aria-labelledby="link-title" fullWidth maxWidth="sm">
      <DialogTitle id="link-title">Ссылка-подписка: {link?.device.label || link?.device.name}</DialogTitle>
      <DialogContent>
        <Typography variant="body2">
          Клиент забирает профиль по этой ссылке сам. Не пересылайте её: она равнозначна паролю устройства.
          Сайты в России идут напрямую через вашего провайдера, в туннель попадает только остальное.
        </Typography>
        {link?.url ? <TextField margin="dense" value={link.url} label="Ссылка" fullWidth multiline minRows={2}
          inputProps={{ readOnly: true }} onFocus={event => event.currentTarget.select()} /> :
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            {link?.state.active
              ? "Ссылка создана, но её значение недоступно. Перевыпустите её, чтобы получить новую."
              : "Ссылка ещё не создана."}
          </Typography>}
        {link?.qr && <Box sx={{ mt: 2, textAlign: "center", display: "grid", gap: 1 }}>
          <img src={link.qr} alt="QR-код ссылки-подписки"
            style={{ width: "min(240px, 100%)", height: "auto", margin: "0 auto" }} />
          <Typography variant="body2" color="text.secondary">
            Отсканируйте код в мобильном Clash — профиль добавится без ввода ссылки.
          </Typography>
        </Box>}
        {link?.singboxUrl && <Box sx={{ mt: 2 }}>
          <TextField margin="dense" value={link.singboxUrl} label="Ссылка для sing-box" fullWidth
            multiline minRows={2} inputProps={{ readOnly: true }}
            onFocus={event => event.currentTarget.select()} />
          <Typography variant="body2" color="text.secondary">
            Тот же профиль в формате sing-box: подходит, пока на вашем сервере включён вход
            VLESS. Ссылка равнозначна паролю устройства и перевыпускается вместе с основной.
          </Typography>
        </Box>}
        {rotateAsk && <Alert severity="warning" sx={{ mt: 2 }}>
          Перевыпуск сделает текущую ссылку недействительной. Клиентам придётся добавить профиль заново.
        </Alert>}
        <ErrorNotice error={error} />
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setLink(null)}>Закрыть</Button>
        {link?.url && <Button component="a" href={link.clashUrl ?? undefined}>Добавить в Clash</Button>}
        {link?.url && <Button onClick={() => {
          const url = link.url ?? "";
          void navigator.clipboard.writeText(url).catch(() => setError("Не удалось скопировать ссылку."));
        }}>Скопировать</Button>}
        {link?.singboxUrl && <Button onClick={() => {
          const url = link.singboxUrl ?? "";
          void navigator.clipboard.writeText(url).catch(() => setError("Не удалось скопировать ссылку."));
        }}>Скопировать sing-box</Button>}
        {!link?.url && <Button variant="contained" onClick={() => void issueSubscription()}>
          Создать ссылку</Button>}
        {link?.url && !rotateAsk && <Button onClick={() => setRotateAsk(true)}>Перевыпустить</Button>}
        {link?.url && rotateAsk && <Button color="warning" onClick={() => void rotateSubscription()}>
          Подтвердить перевыпуск</Button>}
        {link?.state.active && <Button color="error" onClick={() => void revokeSubscription()}>Отозвать</Button>}
      </DialogActions>
    </Dialog>
    <Dialog open={amnezia !== null} onClose={() => setAmnezia(null)} aria-labelledby="amnezia-title" fullWidth maxWidth="sm">
      <DialogTitle id="amnezia-title">Подключение в Amnezia: {amnezia?.title}</DialogTitle>
      <DialogContent><Typography variant="body2">На телефоне отсканируйте код или откройте ссылку в Amnezia. На компьютере скопируйте ссылку и вставьте её в приложении.</Typography>
        {amnezia && <Box sx={{ mt: 2, textAlign: "center", display: "grid", gap: 1.5 }}>
          {amnezia.qr && <img src={amnezia.qr} alt={`QR-код подключения Amnezia для устройства ${amnezia.title}`}
            style={{ width: "min(240px, 100%)", height: "auto", margin: "0 auto" }} />}
          <Button variant="contained" component="a" href={amnezia.uri}>Открыть в Amnezia</Button>
          <Button onClick={() => {
            const blob = new Blob([amnezia.uri], { type: "text/plain" });
            const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
            a.download = `${amnezia.title}-amnezia.txt`; a.click(); URL.revokeObjectURL(a.href);
          }}>Скачать файлом (.txt)</Button>
        </Box>}</DialogContent>
      <DialogActions><Button onClick={() => {
        if (amnezia) void navigator.clipboard.writeText(amnezia.uri).catch(() => setError("Не удалось скопировать ссылку."));
      }}>Скопировать vpn://</Button><Button onClick={() => setAmnezia(null)}>Закрыть</Button></DialogActions>
    </Dialog>
  </Page>;
}
