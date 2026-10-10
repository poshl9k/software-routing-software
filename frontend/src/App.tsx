import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  CssBaseline,
  Drawer,
  GlobalStyles,
  LinearProgress,
  Snackbar,
  TextField,
  ThemeProvider,
  Tooltip,
  useMediaQuery,
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
import { ApplyStatusRail, type ApplyStatusRailProps } from "./components/ApplyStatusRail";
import { Badge } from "./components/Badge";
import { ErrorNotice } from "./components/ErrorNotice";
import { Icon, type IconName } from "./components/Icon";
import { InfoNote } from "./components/InfoNote";

function ApplyTopButton({ checking }: { checking: boolean }) {
  const { noConfiguration } = useConfiguration();
  const { uncertain, busy, user } = useRouterState();
  const { pending, active, seconds, command } = useApplyCommands();
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
  return null;
}
type NavigationItem = { to: string; label: string; icon: IconName };
export const navigation: { group: string; items: NavigationItem[] }[] = [
  { group: "Обзор", items: [{ to: "/", label: "Обзор", icon: "overview" }] },
  { group: "Интернет", items: [
    { to: "/network", label: "Подключения и адреса", icon: "network" },
    { to: "/tunnels", label: "Туннели", icon: "tunnels" },
    { to: "/routing", label: "Выборочная маршрутизация", icon: "routing" },
  ] },
  { group: "Домашняя сеть", items: [
    { to: "/dhcp", label: "DHCP", icon: "dhcp" },
    { to: "/dns", label: "DNS", icon: "dns" },
  ] },
  { group: "Безопасность", items: [
    { to: "/firewall", label: "Правила", icon: "firewall" },
    { to: "/ssh", label: "SSH", icon: "ssh" },
  ] },
  { group: "Сервисы", items: [{ to: "/proxy", label: "Входящие сайты", icon: "proxy" }] },
  { group: "Управление", items: [
    { to: "/events", label: "Журнал", icon: "events" },
    { to: "/maintenance", label: "Обслуживание", icon: "maintenance" },
  ] },
];
function Layout() {
  const { pathname, search } = useLocation();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const desktop = useMediaQuery("(min-width: 651px)");
  const reducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  useEffect(() => {
    if (desktop) setDrawerOpen(false);
  }, [desktop]);
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
  // The routes tab is a deep link inside Network, not a second navigation item.
  const tab = new URLSearchParams(search).get("tab");
  const section = navigation.find((group) => group.items.some((item) => item.to === pathname));
  const title = pathname === "/apply" ? "Конфигурация" :
    pathname === "/network" && tab === "routes" ? "Подключения и адреса" :
      section?.items.find((item) => item.to === pathname)?.label;
  const { uncertain } = useRouterState();
  // Only one imperative marker reader outside /apply; ApplyScreen owns it there.
  const { loading: checking } = useApplyStatus({ enabled: pathname !== "/apply" });
  const { draft, confirmed, pending, active, seconds, state } = useApplyCommands();
  const rail: ApplyStatusRailProps = uncertain || (checking && pathname !== "/apply")
    ? { state: "uncertain" }
    : pending ? { state: "pending", seconds }
    : active ? { state: "running" }
    : applyError || state?.status === "failed" || state?.status === "rollback_failed" || state?.status === "rolled_back"
      ? { state: "error" }
      : draft ? { state: "draft", draftVersion: draft.id, stableVersion: confirmed?.id }
      : confirmed ? { state: "applied", confirmedVersion: confirmed.id }
      : { state: "uncertain" };
  const navContents = (mobile: boolean) => navigation.map((group) => {
    const items = group.items.filter((item) =>
      item.label.toLowerCase().includes(query.trim().toLowerCase()) ||
      group.group.toLowerCase().includes(query.trim().toLowerCase()));
    if (!items.length) return null;
    return (
      <Box component="section" key={group.group} aria-label={group.group} sx={{ mb: 1 }}>
        <Box component="h2" sx={{ px: 2.5, mt: 1.5, mb: 0.5, fontSize: 12, fontWeight: 600, color: "text.secondary" }}>
          {group.group}
        </Box>
        {items.map((item) => (
          <NavLink key={item.to} to={item.to} end
            onClick={mobile ? () => setDrawerOpen(false) : undefined}
            className={() => item.to === pathname ? "active" : ""}
            aria-current={item.to === pathname ? "page" : undefined}
          >
            <span className="icon"><Icon name={item.icon} /></span>
            {item.label}
          </NavLink>
        ))}
      </Box>
    );
  });
  const configurationRail = (mobile: boolean) => (
    <Box className="configuration-rail">
      <Box component="h2" sx={{ px: 2, fontSize: 12, color: "text.secondary" }}>Конфигурация</Box>
      <ApplyStatusRail {...rail} action={user?.role === "admin" ?
        (mobile ? <Button component={Link} to="/apply" onClick={() => setDrawerOpen(false)} variant="outlined">Проверить изменения</Button> : undefined) :
        <Button component={Link} to="/apply" onClick={mobile ? () => setDrawerOpen(false) : undefined}>Открыть</Button>} />
    </Box>
  );
  return (
    <div className="shell">
      <Box component="aside" className="sidebar" sx={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div className="logo"><span className="logo-mark" />VS-ROUTER</div>
        <Box component="nav" className="nav" aria-label="Разделы панели" sx={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          {navContents(false)}
        </Box>
        {configurationRail(false)}
      </Box>
      <Drawer anchor="left" open={drawerOpen} onClose={() => setDrawerOpen(false)}
        transitionDuration={reducedMotion ? 0 : { enter: 160, exit: 120 }}
        slotProps={{ paper: { className: "mobile-drawer" } }}
      >
        <div className="logo"><span className="logo-mark" />VS-ROUTER</div>
        <TextField label="Поиск раздела" value={query} onChange={(e) => setQuery(e.target.value)} sx={{ mx: 2, mb: 1 }} />
        <Box component="nav" className="nav" aria-label="Разделы панели" sx={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          {navContents(true)}
        </Box>
        {configurationRail(true)}
      </Drawer>
      <main className="main">
        <header className="topbar">
          <Button className="mobile-menu" variant="outlined" onClick={() => setDrawerOpen(true)} aria-label="Разделы" aria-haspopup="dialog" aria-expanded={drawerOpen}>Разделы</Button>
          <div className="breadcrumbs">
            vs-router › <b>{title}</b>
          </div>
          {!noConfiguration && version && (
            <Badge tone={version.status === "draft" ? "amber" : "green"}>
              v{version.id} ·{" "}
              {version.status === "draft" ? "черновик" : "подтверждена"}
            </Badge>
          )}
          <TextField
            className="search"
            label="Поиск раздела"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <ApplyTopButton checking={checking} />
          <Button className="mobile-status" component={Link} to="/apply" variant="outlined" aria-label={`Конфигурация: ${rail.state === "pending" ? "ожидается подтверждение" : rail.state === "running" ? "применение выполняется" : rail.state === "draft" ? "черновик" : rail.state === "applied" ? "подтверждена" : rail.state === "error" ? "ошибка применения" : "состояние неизвестно"}. Открыть применение`}>
            Конфигурация{rail.state === "pending" ? " · подтвердить" : rail.state === "error" ? " · ошибка" : ""}
          </Button>
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
            Нет сохранённой конфигурации — <Link to="/onboarding">начните первичную настройку</Link> или проверьте доступность панели.
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