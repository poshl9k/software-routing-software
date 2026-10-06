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
import type { HostInterface } from "../types";
import { readPreferences, savePreferences } from "../preferences";
import { useRouterState } from "../state";
export default function Onboarding() {
  const [step, setStep] = useState(0);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [accountCreated, setAccountCreated] = useState(false);
  const [lan, setLan] = useState("");
  const [address, setAddress] = useState("192.168.10.1/24");
  const [preferences, setPreferences] = useState(readPreferences);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [hostInterfaces, setHostInterfaces] = useState<HostInterface[]>([]);
  const [hostError, setHostError] = useState<unknown>(null);
  const lock = useRef(false);
  const { refresh, loadUser } = useRouterState();
  const physicalNics = hostInterfaces.filter(
    (i) => i.kind === "physical" && i.name !== "lo",
  );
  async function loadHostInterfaces() {
    try {
      const interfaces = await api.hostInterfaces();
      setHostInterfaces(interfaces);
      setHostError(null);
      setLan((selected) => interfaces.some(
        (i) => i.kind === "physical" && i.name !== "lo" && i.name === selected,
      ) ? selected : "");
    } catch (err) {
      setHostInterfaces([]);
      setLan("");
      setHostError(err);
    }
  }
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
        await loadHostInterfaces();
        setStep(1);
      } else if (step === 1) {
        setStep(2);
      } else if (step === 2) {
        if (!physicalNics.some((i) => i.name === lan)) {
          throw new Error("Выберите LAN-интерфейс из списка портов системы");
        }
        await api.createDraft({
          ...emptyConfiguration,
          interfaces: [
            {
              name: lan,
              type: "physical",
              zone: "lan",
              description: null,
              addressing: "static",
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
              Укажем LAN-интерфейс из реальных портов системы. Применение —
              отдельное действие на экране применения.
            </p>
            <div className="fields">
              <TextField
                select
                required
                label="LAN-интерфейс"
                value={lan}
                disabled={busy || physicalNics.length === 0}
                SelectProps={{ native: true }}
                slotProps={{ inputLabel: { shrink: true } }}
                onChange={(e) => setLan(e.target.value)}
              >
                <option value="">Выберите порт LAN</option>
                {physicalNics.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name} · {i.mac}
                  </option>
                ))}
              </TextField>
              <TextField
                required
                label="Адрес LAN (CIDR)"
                value={address}
                disabled={busy}
                onChange={(e) => setAddress(e.target.value)}
                helperText="Например, 192.168.10.1/24. Проверка выполняется API при сохранении."
              />
            </div>
            {hostError && (
              <Alert severity="warning">
                Не удалось получить список интерфейсов из системы — проверьте
                агент.
              </Alert>
            )}
            {physicalNics.length === 0 && (
              <Button disabled={busy} onClick={() => void loadHostInterfaces()}>
                Обновить список интерфейсов
              </Button>
            )}
            <Alert severity="info">
              Выберите назначенный с консоли LAN-порт, не WAN. Перед первым
              применением проверьте WAN и маршрут по умолчанию с локальной
              консоли: у первого apply нет автоотката.
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
              Серверного API настроек нет. Первое применение не имеет
              автоотката. Нужен доступ к локальной консоли. Сохраните выбранный
              с консоли LAN, его адрес и HTTPS на порту 443; агент проверит их
              перед применением на подготовленном хосте.
            </Alert>
          </>
        )}
        {step === 3 && (
          <>
            <Typography variant="h1" component="h1">
              Первичная настройка готова
            </Typography>
            <Alert severity="success">
              Учётная запись создана, вход выполнен, базовая сеть LAN сохранена.
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
            <Button type="submit" variant="contained" disabled={busy || (step === 1 && !physicalNics.some((i) => i.name === lan))}>
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
