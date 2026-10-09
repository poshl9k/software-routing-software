import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Alert,
  Button,
  FormControlLabel,
  Switch,
  Typography,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { emptyConfiguration } from "../fixtures";
import { ErrorNotice } from "../components/ErrorNotice";
import { WizardProgress } from "../components/WizardProgress";
import { InfoNote } from "../components/InfoNote";
import { Field } from "../components/Field";
import { Select } from "../components/Select";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
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
  const lock = useRef(false);
  const { refresh, loadUser } = useRouterState();
  // Requires a session, so it is only enabled once the account step is passed.
  const hostInterfaces = useQuery({
    queryKey: queryKeys.hostInterfaces(),
    queryFn: api.hostInterfaces,
    enabled: step > 0,
  });
  const physicalNics = (hostInterfaces.data ?? []).filter(
    (i) => i.kind === "physical" && i.name !== "lo",
  );
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
      <WizardProgress current={step} steps={["Администратор", "LAN и адрес", "Проверка и безопасность", "Черновик готов"]} />
      <ErrorNotice error={error} />
      <form onSubmit={next}>
        {step === 0 && (
          <>
            <Typography variant="h1" component="h1">
              Учётная запись администратора
            </Typography>
            <div className="fields">
              <Field
                required
                label="Логин администратора"
                value={username}
                disabled={busy || accountCreated}
                autoComplete="username"
                inputProps={{ pattern: "[a-zA-Z0-9_.-]+" }}
                maxLength={64}
                onChange={setUsername}
              />
              <Field
                required
                type="password"
                label="Пароль"
                value={password}
                disabled={busy}
                autoComplete={
                  accountCreated ? "current-password" : "new-password"
                }
                inputProps={{ minLength: 8 }}
                maxLength={1024}
                hint="Минимум 8 символов (контракт API). Хранится как argon2id-хэш."
                onChange={setPassword}
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
              <Select
                label="LAN-интерфейс"
                value={lan}
                disabled={busy || physicalNics.length === 0}
                placeholder={{ label: "Выберите порт LAN" }}
                options={physicalNics.map((i) => ({
                  value: i.name,
                  label: `${i.name} · ${i.mac}`,
                }))}
                onChange={setLan}
              />
              <Field
                required
                label="Адрес LAN (CIDR)"
                value={address}
                disabled={busy}
                hint="Например, 192.168.10.1/24. Проверка выполняется API при сохранении."
                onChange={setAddress}
              />
            </div>
            {hostInterfaces.error && (
              <Alert severity="warning">
                Не удалось получить список интерфейсов из системы — проверьте
                агент.
              </Alert>
            )}
            {physicalNics.length === 0 && (
              <Button disabled={busy} onClick={() => void hostInterfaces.refetch()}>
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
                <Field
                  required
                  type="number"
                  label="Окно подтверждения (секунды)"
                  value={preferences.timeout}
                  inputProps={{ min: 60, max: 600, step: 1 }}
                  onChange={(v) =>
                    setPreferences((p) => ({
                      ...p,
                      timeout: Number(v),
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
            <InfoNote severity="warning">
              Первое применение без автоотката. Держите доступ к локальной консоли; проверьте LAN, адрес и HTTPS на порту 443 перед применением.
            </InfoNote>
            <Button component={Link} to="/apply" variant="contained">
              Проверить и применить
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
          <Field
            required
            label="Логин"
            autoComplete="username"
            value={username}
            onChange={setUsername}
          />
          <Field
            required
            type="password"
            label="Пароль"
            autoComplete="current-password"
            value={password}
            onChange={setPassword}
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
