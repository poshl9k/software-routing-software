import { Alert, Box, Button, CircularProgress, GlobalStyles, Stack, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent } from "react";
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { MasterApiError, masterApi } from "./api";
import { NodesPage, RuleSetsPage, SubscribersPage, TariffsPage } from "./pages";
import { TelegramPage } from "./TelegramPage";
import { MagicSignIn, PortalHome, PortalLogin } from "./SubscriberPortal";
import { takeMagicProof } from "./magic";
import { globalStyles, theme } from "../theme";
import { ThemeProvider } from "@mui/material/styles";

function ErrorNotice({ error }: { error: unknown }) {
  return error ? <Alert severity="error">{error instanceof Error ? error.message : "Ошибка"}</Alert> : null;
}

function AuthForm({ setup = false }: { setup?: boolean }) {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (setup && password !== confirm) { setError(new Error("Пароли не совпадают")); return; }
    setBusy(true); setError(null);
    try {
      if (setup) await masterApi.setup(password); else await masterApi.login(password);
      navigate("/", { replace: true });
    } catch (reason) {
      if (reason instanceof MasterApiError && reason.code === "admin.already_initialized") navigate("/login", { replace: true });
      else setError(reason);
    } finally { setBusy(false); }
  }
  return <Box className="page"><Box component="main" className="content">
    <Typography component="h1" variant="h1" sx={{ mb: 3, fontSize: { xs: "2rem", sm: "3rem" } }}>{setup ? "Первый запуск мастер-портала" : "Вход администратора"}</Typography>
    <Box component="form" onSubmit={submit} className="form" sx={{ maxWidth: 420 }}>
      <TextField label={setup ? "Задайте пароль администратора" : "Пароль"} type="password" value={password}
        onChange={e => setPassword(e.target.value)} autoComplete={setup ? "new-password" : "current-password"} required fullWidth />
      {setup && <TextField label="Повторите пароль" type="password" value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="new-password" required fullWidth />}
      <ErrorNotice error={error} />
      <Button type="submit" variant="contained" disabled={busy}>{busy ? <CircularProgress size={18} /> : setup ? "Создать администратора" : "Войти"}</Button>
    </Box>
  </Box></Box>;
}

function Dashboard() {
  const navigate = useNavigate();
  const [ready, setReady] = useState<boolean | null>(null);
  const [tab, setTab] = useState<"nodes" | "subscribers" | "tariffs" | "telegram" | "rules">("nodes");
  useEffect(() => {
    masterApi.nodes().then(() => { setReady(true); }).catch((reason) => {
      if (reason instanceof MasterApiError && reason.status === 401) navigate("/login", { replace: true });
      else navigate("/login", { replace: true });
    });
  }, [navigate]);
  async function logout() {
    try { await masterApi.logout(); navigate("/login", { replace: true }); } catch { navigate("/login", { replace: true }); }
  }
  if (ready === false) return <Navigate to="/setup" replace />;
  return <Box className="page"><Box component="main" className="content">
    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
      <Typography component="h1" variant="h1" sx={{ fontSize: { xs: "2rem", sm: "3rem", md: "3.6rem" } }}>Мастер-портал</Typography>
      <Button onClick={() => void logout()} aria-label="Выйти из аккаунта">Выйти</Button>
    </Stack>
    <Box role="tablist" aria-label="Разделы" sx={{ mb: 3 }}>
      <Button role="tab" aria-selected={tab === "nodes"} variant={tab === "nodes" ? "contained" : "text"} onClick={() => setTab("nodes")}>Ноды</Button>
      <Button role="tab" aria-selected={tab === "subscribers"} variant={tab === "subscribers" ? "contained" : "text"} onClick={() => setTab("subscribers")}>Абоненты</Button>
      <Button role="tab" aria-selected={tab === "tariffs"} variant={tab === "tariffs" ? "contained" : "text"} onClick={() => setTab("tariffs")}>Тарифы</Button>
      <Button role="tab" aria-selected={tab === "telegram"} variant={tab === "telegram" ? "contained" : "text"} onClick={() => setTab("telegram")}>Telegram</Button>
      <Button role="tab" aria-selected={tab === "rules"} variant={tab === "rules" ? "contained" : "text"} onClick={() => setTab("rules")}>Правила</Button>
    </Box>
    {ready === null && <Box className="loading"><CircularProgress /></Box>}
    {ready === true && (tab === "nodes" ? <NodesPage /> : tab === "subscribers" ? <SubscribersPage /> : tab === "tariffs" ? <TariffsPage /> : tab === "rules" ? <RuleSetsPage /> : <TelegramPage />)}
  </Box></Box>;
}

function AppRoutes({ magicProof }: { magicProof: string | null }) {
  return <Routes>
    <Route path="/login" element={magicProof !== null ? <MagicSignIn proof={magicProof} /> : <AuthForm />} />
    <Route path="/portal/login" element={<PortalLogin />} />
    <Route path="/portal" element={<PortalHome />} />
    <Route path="/setup" element={<AuthForm setup />} />
    <Route path="/" element={<Dashboard />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}

export function App({ magicProof }: { magicProof?: string | null }) {
  const proof = magicProof === undefined ? takeMagicProof() : magicProof;
  return <ThemeProvider theme={theme}><GlobalStyles styles={globalStyles} /><BrowserRouter><AppRoutes magicProof={proof} /></BrowserRouter></ThemeProvider>;
}
