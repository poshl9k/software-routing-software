import { useState } from "react";
import {
  Alert,
  Button,
  CssBaseline,
  LinearProgress,
  TextField,
  ThemeProvider,
  Tooltip,
} from "@mui/material";
import {
  Link,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import Dashboard, { Events } from "./pages/Dashboard";
import Network from "./pages/Network";
import Firewall from "./pages/Firewall";
import { DHCP, DNS, Proxy, Tunnels } from "./pages/Services";
import ApplyScreen from "./pages/ApplyScreen";
import Maintenance from "./pages/Maintenance";
import Onboarding, { Login } from "./pages/Onboarding";
import { theme } from "./theme";
import {
  RouterProvider,
  useApplyCommands,
  useConfiguration,
  useRouterState,
} from "./state";
import { ErrorNotice, Todo, fmtDateTime } from "./ui";
function ApplyTopButton() {
  const { demo } = useConfiguration();
  const { uncertain } = useRouterState();
  const {
    draft,
    confirmed,
    preferences,
    pending,
    active,
    seconds,
    timeoutValid,
    command,
  } = useApplyCommands();
  if (demo) return null;
  const mmss =
    seconds === null
      ? null
      : `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
  if (pending)
    return (
      <Tooltip title="Агент ждёт подтверждения; по истечении окна — автоматический откат">
        <span>
          <Button
            variant="contained"
            color="success"
            disabled={seconds === 0 || seconds === null}
            onClick={() => void command("confirm")}
          >
            Подтвердить{mmss ? ` · ${mmss}` : ""}
          </Button>
        </span>
      </Tooltip>
    );
  if (active || uncertain)
    return (
      <Tooltip
        title={
          uncertain
            ? "Результат последней команды неизвестен; проверьте состояние на странице «Применение»"
            : "Команда выполняется; подробности на странице «Применение»"
        }
      >
        <span>
          <Button variant="contained" component={Link} to="/apply">
            Выполняется…
          </Button>
        </span>
      </Tooltip>
    );
  if (!draft) return null;
  const applyDisabled =
    !timeoutValid || (preferences.safe && !confirmed);
  const when = fmtDateTime(draft.created_at);
  return (
    <Tooltip
      title={
        applyDisabled
          ? preferences.safe && !confirmed
            ? "Безопасный режим требует ранее подтверждённой версии; параметры — на странице «Применение»"
            : "Окно подтверждения должно быть 60–600 секунд; параметры — на странице «Применение»"
          : `Применить черновик v${draft.id}${when ? ` от ${when}` : ""} с сохранёнными параметрами; diff и параметры — на странице «Применение»`
      }
    >
      <span>
        <Button
          variant="contained"
          color="primary"
          disabled={applyDisabled}
          onClick={() => void command("apply")}
        >
          Применить
        </Button>
      </span>
    </Tooltip>
  );
}
export const navigation = [
  { to: "/", label: "Обзор", icon: "◱" },
  { to: "/network", label: "Сеть", icon: "⑃" },
  { to: "/dhcp", label: "DHCP", icon: "⇄" },
  { to: "/dns", label: "DNS", icon: "⌾" },
  { to: "/network?tab=routes", label: "Маршруты", icon: "⇋" },
  { to: "/tunnels", label: "Туннели", icon: "⚿" },
  { to: "/proxy", label: "Прокси", icon: "◎" },
  { to: "/firewall", label: "Правила", icon: "✉" },
  { to: "/events", label: "Журнал", icon: "▤" },
  { to: "/apply", label: "Применение", icon: "⚙" },
  { to: "/maintenance", label: "Обслуживание", icon: "⌁" },
];
function Layout() {
  const { pathname, search } = useLocation();
  const [query, setQuery] = useState("");
  const { loading, error, demo, version, refresh } = useConfiguration();
  const { applyError } = useRouterState();
  const title =
    navigation.find((n) => n.to === pathname + search)?.label ??
    navigation.find((n) => n.to === pathname)?.label;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">
          <span className="logo-mark" />
          VS-ROUTER
        </div>
        <nav className="nav" aria-label="Разделы панели">
          {navigation
            .filter((n) => n.label.toLowerCase().includes(query.toLowerCase()))
            .map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end
                className={() =>
                  (
                    n.to === "/network"
                      ? pathname === "/network" && !search
                      : n.to === "/network?tab=routes"
                        ? pathname === "/network" && search.includes("routes")
                        : n.to === pathname
                  )
                    ? "active"
                    : ""
                }
              >
                <span className="icon" aria-hidden="true">
                  {n.icon}
                </span>
                {n.label}
              </NavLink>
            ))}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            vs-router › <b>{title}</b>
          </div>
          <TextField
            className="search"
            label="Поиск раздела"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <ApplyTopButton />
          <Button component={Link} to="/login">
            Вход
          </Button>
          <Button onClick={() => void refresh()} disabled={loading}>
            Обновить
          </Button>
        </header>
        <ErrorNotice error={applyError} />
        {loading && <LinearProgress aria-label="Загрузка конфигурации" />}
        <ErrorNotice error={error} />
        {demo ? (
          <Todo>
            Показаны демонстрационные данные из макетов. Доступная версия
            конфигурации не получена.
          </Todo>
        ) : (
          <Alert severity="info">
            Конфигурация v{version?.id}
            {version?.created_at && (
              <>
                {" "}· {fmtDateTime(version.created_at)}
              </>
            )}{" "}
            ·{" "}
            {version?.status === "draft" ? "черновик" : "подтверждена в БД"}.
            Это желаемая конфигурация; runtime-статусы отмечены отдельно.
          </Alert>
        )}
        <Outlet />
      </main>
    </div>
  );
}
export default function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <RouterProvider>
        <Routes>
          <Route path="/onboarding" element={<Onboarding />} />
          <Route path="/login" element={<Login />} />
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="network" element={<Network />} />
            <Route path="dhcp" element={<DHCP />} />
            <Route path="dns" element={<DNS />} />
            <Route path="tunnels" element={<Tunnels />} />
            <Route path="proxy" element={<Proxy />} />
            <Route path="firewall" element={<Firewall />} />
            <Route path="apply" element={<ApplyScreen />} />
            <Route path="maintenance" element={<Maintenance />} />
            <Route path="events" element={<Events />} />
            <Route
              path="*"
              element={
                <Alert severity="warning">
                  Страница не найдена. <Link to="/">Открыть обзор</Link>
                </Alert>
              }
            />
          </Route>
        </Routes>
      </RouterProvider>
    </ThemeProvider>
  );
}
