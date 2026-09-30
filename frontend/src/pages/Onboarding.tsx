import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Alert,
  Button,
  FormControlLabel,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { emptyConfiguration } from "../fixtures";
import { ErrorNotice } from "../ui";
import { readPreferences, savePreferences } from "../preferences";
import { useRouterState } from "../state";
export default function Onboarding() {
  const [step, setStep] = useState(0);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [accountCreated, setAccountCreated] = useState(false);
  const [lan, setLan] = useState("eth1");
  const [address, setAddress] = useState("192.168.10.1/24");
  const [preferences, setPreferences] = useState(readPreferences);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const lock = useRef(false);
  const { refresh, loadUser } = useRouterState();
  async function next(event: FormEvent) {
    event.preventDefault();
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError(null);
    try {
      if (step === 0) {
        if (!accountCreated) {
          await api.setup({ username, password });
          setAccountCreated(true);
        }
        // Setup creates an account but does not establish a session.
        await api.login({ username, password });
        // Populate the session user so the topbar shows "Выйти", not "Вход".
        await loadUser();
        setPassword("");
        setStep(1);
      } else if (step === 1) {
        setStep(2);
      } else if (step === 2) {
        await api.createDraft({
          ...emptyConfiguration,
          interfaces: [
            {
              name: lan,
              type: "physical",
              zone: "lan",
              addresses: [address],
              parent: null,
              vlan_id: null,
              members: [],
            },
          ],
        });
        savePreferences(preferences);
        await refresh();
        setStep(3);
      }
    } catch (err) {
      setError(err);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  return (
    <div className="onb">
      <div className="logo">
        <span className="logo-mark" />
        VS-ROUTER
      </div>
      <div className="steps" aria-label={`Шаг ${step + 1} из 4`}>
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={i < step ? "done" : i === step ? "now" : ""}
          />
        ))}
      </div>
      <p className="sub">
        Шаг {step + 1} из 4 ·{" "}
        {["Учётка", "Сеть", "Безопасная настройка", "Готово"][step]}
      </p>
      <ErrorNotice error={error} />
      <form onSubmit={next}>
        {step === 0 && (
          <>
            <Typography variant="h1" component="h1">
              Учётная запись администратора
            </Typography>
            <div className="fields">
              <TextField
                required
                label="Логин администратора"
                value={username}
                disabled={busy || accountCreated}
                autoComplete="username"
                slotProps={{
                  htmlInput: { pattern: "[a-zA-Z0-9_.-]+", maxLength: 64 },
                }}
                onChange={(e) => setUsername(e.target.value)}
              />
              <TextField
                required
                type="password"
                label="Пароль"
                value={password}
                disabled={busy}
                autoComplete={
                  accountCreated ? "current-password" : "new-password"
                }
                slotProps={{ htmlInput: { minLength: 8, maxLength: 1024 } }}
                helperText="Минимум 8 символов (контракт API). Хранится как argon2id-хэш."
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {accountCreated && (
              <Alert severity="info">
                Учётка создана. Повторная попытка выполнит только вход.
              </Alert>
            )}
            <Button component={Link} to="/login">
              Уже настроено? Войти
            </Button>
          </>
        )}
        {step === 1 && (
          <>
            <Typography variant="h1" component="h1">
              Базовая сеть
            </Typography>
            <p>
              Создадим черновик LAN. Применение — отдельное действие на экране
              применения.
            </p>
            <div className="fields">
              <TextField
                required
                label="LAN-интерфейс"
                value={lan}
                disabled={busy}
                slotProps={{
                  htmlInput: { pattern: "[a-zA-Z][a-zA-Z0-9_.-]{0,14}" },
                }}
                onChange={(e) => setLan(e.target.value)}
              />
              <TextField
                required
                label="Адрес LAN (CIDR)"
                value={address}
                disabled={busy}
                onChange={(e) => setAddress(e.target.value)}
                helperText="Например, 192.168.10.1/24. Проверка выполняется API при сохранении."
              />
            </div>
            <Alert severity="info">
              TODO-API · обнаружение портов и DHCP-клиент WAN пока отсутствуют.
            </Alert>
          </>
        )}
        {step === 2 && (
          <>
            <Typography variant="h1" component="h1">
              Включить безопасную настройку?
            </Typography>
            <p>
              При последующих применениях агент будет ждать подтверждения и
              откатывать изменения по таймеру.
            </p>
            <div className="safecard">
              <FormControlLabel
                label="Безопасная настройка"
                control={
                  <Switch
                    checked={preferences.safe}
                    onChange={(_, safe) =>
                      setPreferences((p) => ({ ...p, safe }))
                    }
                  />
                }
              />
              <div className="fields">
                <TextField
                  required
                  type="number"
                  label="Окно подтверждения (секунды)"
                  value={preferences.timeout}
                  slotProps={{ htmlInput: { min: 60, max: 600, step: 1 } }}
                  onChange={(e) =>
                    setPreferences((p) => ({
                      ...p,
                      timeout: Number(e.target.value),
                    }))
                  }
                />
              </div>
            </div>
            <Alert severity="info">
              Параметры сохраняются в этом браузере и передаются при применении.
              Серверного API настроек нет. Первое применение требует
              выключенного безопасного режима: агенту нужна стабильная версия
              для отката.
            </Alert>
          </>
        )}
        {step === 3 && (
          <>
            <Typography variant="h1" component="h1">
              Первичная настройка готова
            </Typography>
            <Alert severity="success">
              Учётная запись создана, вход выполнен, черновик LAN сохранён.
              Конфигурация ещё не применена.
            </Alert>
            <Button component={Link} to="/apply" variant="contained">
              Перейти к применению
            </Button>
          </>
        )}
        {step < 3 && (
          <div className="footer-actions">
            {step === 2 && (
              <Button disabled={busy} onClick={() => setStep(1)}>
                ← Назад
              </Button>
            )}
            <Button type="submit" variant="contained" disabled={busy}>
              {busy
                ? "Сохранение…"
                : step === 2
                  ? "Сохранить"
                  : "Продолжить →"}
            </Button>
          </div>
        )}
      </form>
    </div>
  );
}
export function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const lock = useRef(false);
  const { refresh, loadUser, user } = useRouterState();
  const navigate = useNavigate();
  useEffect(() => {
    if (user) navigate("/");
  }, [user, navigate]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError(null);
    try {
      await api.login({ username, password });
      setPassword("");
      await loadUser();
      await refresh();
      navigate("/");
    } catch (err) {
      setError(err);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  return (
    <div className="onb">
      <Typography component="h1" variant="h1">
        Вход в vs-router
      </Typography>
      <ErrorNotice error={error} />
      <form onSubmit={submit}>
        <div className="fields">
          <TextField
            required
            label="Логин"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <TextField
            required
            type="password"
            label="Пароль"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <Button type="submit" variant="contained" disabled={busy}>
          Войти
        </Button>
        <Button component={Link} to="/onboarding">
          Первый запуск
        </Button>
      </form>
    </div>
  );
}
