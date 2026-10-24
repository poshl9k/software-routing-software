import { Alert, Box, Button, CircularProgress, GlobalStyles, TextField, Typography } from "@mui/material";
import { useEffect, useState, type FormEvent } from "react";
import { BrowserRouter, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { MasterApiError, masterApi } from "./api";
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
  const [error, setError] = useState<unknown>(null);
  const [ready, setReady] = useState<boolean | null>(null);
  useEffect(() => {
    masterApi.nodes().then(() => { setReady(true); }).catch((reason) => {
      if (reason instanceof MasterApiError && reason.status === 401) navigate("/login", { replace: true });
      else if (reason instanceof MasterApiError && reason.status === 404) setReady(false);
      else setError(reason);
    });
  }, [navigate]);
  if (ready === false) return <Navigate to="/setup" replace />;
  return <Box className="page"><Box component="main" className="content">
    <Typography component="h1" variant="h1" sx={{ mb: 3, fontSize: { xs: "2rem", sm: "3rem", md: "3.6rem" } }}>Мастер-портал</Typography>
    <ErrorNotice error={error} />
    {ready === null && <Box className="loading"><CircularProgress /></Box>}
    {ready === true && <Alert severity="info">Экраны нод, абонентов и тарифов будут добавлены следующим слайсом; API уже отвечает.</Alert>}
  </Box></Box>;
}

function AppRoutes() {
  return <Routes>
    <Route path="/login" element={<AuthForm />} />
    <Route path="/setup" element={<AuthForm setup />} />
    <Route path="/" element={<Dashboard />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}

export function App() {
  return <ThemeProvider theme={theme}><GlobalStyles styles={globalStyles} /><BrowserRouter><AppRoutes /></BrowserRouter></ThemeProvider>;
}
