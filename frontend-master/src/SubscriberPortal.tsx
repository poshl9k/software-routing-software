import { Alert, Box, Button, CircularProgress, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { MasterApiError, portalApi, type PortalDevice, type PortalMe } from "./api";

function Page({ title, children }: { title: string; children: React.ReactNode }) {
  return <Box className="page"><Box component="main" className="content">
    <Typography component="h1" variant="h1" sx={{ mb: 3, fontSize: { xs: "2rem", sm: "3rem" } }}>{title}</Typography>
    {children}
  </Box></Box>;
}

export function PortalLogin() {
  return <Page title="Личный кабинет">
    <Alert severity="info">Откройте ссылку из Telegram-бота, чтобы войти в кабинет.</Alert>
  </Page>;
}

export function MagicSignIn({ proof }: { proof: string }) {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!proof) { setError("Ссылка недействительна. Запросите новую в Telegram-боте."); return; }
    let cancelled = false;
    // Defer the one-shot POST until after StrictMode's development effect replay.
    const timer = window.setTimeout(() => {
      void portalApi.magic(proof).then(() => {
        if (!cancelled) navigate("/portal", { replace: true });
      }).catch((reason: unknown) => {
        if (cancelled) return;
        setError(reason instanceof MasterApiError && reason.status === 401
          ? "Ссылка недействительна. Запросите новую в Telegram-боте."
          : "Не удалось войти. Попробуйте позже или запросите новую ссылку.");
      });
    }, 0);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [navigate, proof]);
  return <Page title="Вход в личный кабинет">
    {error ? <Alert severity="error">{error}</Alert> : <CircularProgress aria-label="Проверка ссылки" />}
  </Page>;
}

export function PortalHome() {
  const navigate = useNavigate();
  const [me, setMe] = useState<PortalMe | null>(null);
  const [devices, setDevices] = useState<PortalDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [creating, setCreating] = useState(false);
  useEffect(() => {
    let mounted = true;
    void portalApi.me().then(async (result) => {
      if (!mounted) return;
      setMe(result);
      if (result.subscription?.status === "active") {
        const data = await portalApi.devices();
        if (mounted) setDevices(data.devices);
      }
    }).catch((reason: unknown) => {
      if (!mounted) return;
      if (reason instanceof MasterApiError && reason.status === 401) navigate("/portal/login", { replace: true });
      else setError("Не удалось загрузить кабинет. Попробуйте позже.");
    });
    return () => { mounted = false; };
  }, [navigate]);
  async function logout() {
    try { await portalApi.logout(); navigate("/portal/login", { replace: true }); }
    catch { setError("Не удалось завершить сеанс. Попробуйте ещё раз."); }
  }
  async function createDevice(event: FormEvent) {
    event.preventDefault();
    const name = label.trim();
    if (!name || creating) return;
    setCreating(true); setError(null);
    try {
      await portalApi.createDevice(name);
      const data = await portalApi.devices();
      setDevices(data.devices);
      setLabel("");
    } catch { setError("Не удалось добавить устройство. Проверьте состояние подписки и ноды."); }
    finally { setCreating(false); }
  }
  return <Page title="Личный кабинет">
    {error && <Alert severity="error">{error}</Alert>}
    {!me && !error && <CircularProgress aria-label="Загрузка кабинета" />}
    {me && <Stack spacing={3}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h6">{me.account.display_name}</Typography>
        <Button onClick={() => void logout()}>Выйти</Button>
      </Stack>
      {me.subscription?.status === "active" ? <>
        <Alert severity="success">Подписка активна: {me.subscription.tariff?.name ?? "тариф не указан"}. До {new Date(me.subscription.expires_at).toLocaleDateString("ru-RU")}.</Alert>
        <Typography component="h2" variant="h5">Устройства</Typography>
        <Box component="form" onSubmit={event => void createDevice(event)} className="form" sx={{ maxWidth: 420 }}>
          <TextField label="Название устройства" value={label} onChange={event => setLabel(event.target.value)}
            inputProps={{ maxLength: 128 }} fullWidth required />
          <Button type="submit" variant="contained" disabled={creating || !label.trim()}>Добавить устройство</Button>
        </Box>
        {devices === null && !error && <CircularProgress aria-label="Загрузка устройств" />}
        {devices?.length === 0 && <Alert severity="info">Устройств пока нет.</Alert>}
        {devices?.map(device => <Box key={device.id}>
          <Typography>{device.label} — {device.status === "active" && device.applied ? "Подключено" : "Не подключено"}</Typography>
          {device.status === "active" && device.applied && <Button component="a" download
            aria-label={`Скачать конфигурацию ${device.label}`}
            href={`/api/portal/devices/${device.id}/export?format=conf`}>Скачать конфигурацию</Button>}
        </Box>)}
      </> : <Alert severity="info">{me.subscription ? "Подписка истекла" : "Подписка пока не активна"}</Alert>}
    </Stack>}
  </Page>;
}
