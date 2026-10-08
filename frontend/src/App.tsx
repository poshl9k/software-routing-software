import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  CssBaseline,
  GlobalStyles,
  LinearProgress,
  Snackbar,
  TextField,
  ThemeProvider,
  Tooltip,
} from "@mui/material";
import {
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import Dashboard, { Events } from "./pages/Dashboard";
import Network from "./pages/Network";
import Firewall from "./pages/Firewall";
import Routing from "./pages/Routing";
import SSH from "./pages/SSH";
import { DHCP, DNS, Proxy, Tunnels } from "./pages/Services";
import ApplyScreen from "./pages/ApplyScreen";
import Maintenance from "./pages/Maintenance";
import Onboarding, { Login } from "./pages/Onboarding";
import { globalStyles, theme } from "./theme";
import {
  RouterProvider,
  useApplyCommands,
  useConfiguration,
  useRouterState,
} from "./state";
import { useApplyStatus } from "./hooks/useApplyStatus";
import { Badge } from "./components/Badge";
import { ErrorNotice } from "./components/ErrorNotice";
import { Icon, type IconName } from "./components/Icon";
import { InfoNote } from "./components/InfoNote";
import { fmtDateTime } from "./components/format";

function ApplyTopButton() {
  const { noConfiguration } = useConfiguration();
  const { uncertain, busy, user } = useRouterState();
  const location = useLocation();
  // The Apply screen owns the read (and its confirm button) while it is open.
  const { loading: checking } = useApplyStatus({
    enabled: location.pathname !== "/apply",
  });
  const {
    draft,
    confirmed,
    pending,
    active,
    seconds,
    timeoutValid,
    command,
  } = useApplyCommands();
  if (noConfiguration || user?.role !== "admin") return null;
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
            disabled={busy || checking || uncertain || seconds === 0 || seconds === null}
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
  const applyDisabled = checking || uncertain || busy || !timeoutValid;
  const when = fmtDateTime(draft.created_at);
  return (
    <Tooltip
      title={
        applyDisabled
          ? "Окно подтверждения должно быть 60–600 секунд; параметры — на странице «Применение»"
          : !confirmed
            ? "Первое применение без автоотката. Нужен доступ к локальной консоли; сохраните выбранный LAN и HTTPS на порту 443."
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
export const navigation: { to: string; label: string; icon: IconName }[] = [
  { to: "/", label: "Обзор", icon: "overview" },
  { to: "/network", label: "Сеть", icon: "network" },
  { to: "/dhcp", label: "DHCP", icon: "dhcp" },
  { to: "/dns", label: "DNS", icon: "dns" },
  { to: "/network?tab=routes", label: "Маршруты", icon: "routes" },
  { to: "/routing", label: "Маршрутизация", icon: "routing" },
  { to: "/tunnels", label: "Туннели", icon: "tunnels" },
  { to: "/proxy", label: "Прокси", icon: "proxy" },
  { to: "/firewall", label: "Правила", icon: "firewall" },
  { to: "/ssh", label: "SSH", icon: "ssh" },
  { to: "/events", label: "Журнал", icon: "events" },
  { to: "/apply", label: "Применение", icon: "apply" },
  { to: "/maintenance", label: "Обслуживание", icon: "maintenance" },
];
function Layout() {
  const { pathname, search } = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const {
    loading,
    error,
    noConfiguration,
    version,
    refresh,
    user,
    signOut,
    notice,
    setNotice,
    applyError,
    setApplyError,
  } = useConfiguration();
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
                <span className="icon">
                  <Icon name={n.icon} />
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
          {!noConfiguration && version && (
            <Badge tone={version.status === "draft" ? "amber" : "green"}>
              v{version.id} ·{" "}
              {version.status === "draft" ? "черновик" : "подтверждена"}
              {fmtDateTime(version.created_at)
                ? ` · ${fmtDateTime(version.created_at)}`
                : ""}
            </Badge>
          )}
          <TextField
            className="search"
            label="Поиск раздела"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <ApplyTopButton />
          {user ? (
            <>
              <span className="user-name">{user.username}</span>
              <Button
                onClick={() =>
                  void signOut().then(() => navigate("/login"))
                    .catch((err: unknown) => setApplyError(err))
                }
              >
                Выйти
              </Button>
            </>
          ) : (
            <Button component={Link} to="/login">
              Вход
            </Button>
          )}
          <Button onClick={() => void refresh()} disabled={loading}>
            Обновить
          </Button>
        </header>
        <ErrorNotice error={applyError} />
        {loading && <LinearProgress aria-label="Загрузка конфигурации" />}
        <ErrorNotice error={error} />
        <Snackbar
          open={notice !== null}
          autoHideDuration={4000}
          onClose={() => setNotice(null)}
          message={notice ?? ""}
        />
        {noConfiguration && (
          <InfoNote>
            Нет сохранённой конфигурации — выполните первичную настройку (раздел «Первый запуск») или проверьте доступность панели.
          </InfoNote>
        )}
        <Outlet />
      </main>
    </div>
  );
}
/**
 * Auth gate. Until the session check resolves nothing is shown; without a
 * session the visitor is sent to the login page. There is no read-only or demo
 * fallback shell — an unauthenticated user must never see panel content.
 */
function Protected() {
  const { authChecked, user, loadUser } = useRouterState();
  useEffect(() => {
    void loadUser();
  }, [loadUser]);
  if (!authChecked) return <LinearProgress aria-label="Проверка сессии" />;
  if (!user) return <Navigate to="/login" replace />;
  return <Layout />;
}
export default function App() {
  return (
    <ThemeProvider theme={theme}>
      <GlobalStyles styles={globalStyles} />
      <CssBaseline />
      <RouterProvider>
        <Routes>
          <Route path="/onboarding" element={<Onboarding />} />
          <Route path="/login" element={<Login />} />
          <Route element={<Protected />}>
            <Route index element={<Dashboard />} />
            <Route path="network" element={<Network />} />
            <Route path="dhcp" element={<DHCP />} />
            <Route path="dns" element={<DNS />} />
            <Route path="tunnels" element={<Tunnels />} />
            <Route path="proxy" element={<Proxy />} />
            <Route path="routing" element={<Routing />} />
            <Route path="firewall" element={<Firewall />} />
            <Route path="ssh" element={<SSH />} />
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