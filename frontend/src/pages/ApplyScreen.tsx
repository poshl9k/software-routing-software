import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  FormControlLabel,
  MenuItem,
  Switch,
  TextField,
  Typography,
} from "@mui/material";
import { Link } from "react-router-dom";
import { api } from "../api";
import { observation, useApplyCommands, statusLabels, useCountdown, useRouterState } from "../state";
import { Badge, Card, DataTable, ErrorNotice, fmtDateTime } from "../ui";
import type { ApplyResult } from "../types";
export default function ApplyScreen() {
  const { uncertain, busy, applyState, discardDraft, setNotice, user,
    setApplyState, setApplyError, setUncertain } =
    useRouterState();
  const {
    drafts,
    draft,
    confirmed,
    preferences,
    setPreferences,
    seconds,
    state,
    pending,
    active,
    timeoutValid,
    error,
    command,
  } = useApplyCommands();
  const [selected, setSelected] = useState<number | "">("");
  const [diff, setDiff] = useState<unknown[] | null>(null);
  const [diffError, setDiffError] = useState<unknown>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusRefresh, setStatusRefresh] = useState(0);
  const shownDraft =
    drafts.find((v) => v.id === selected) ?? draft;
  useEffect(() => {
    if (user?.role !== "admin" || busy) return;
    const controller = new AbortController();
    setStatusLoading(true);
    api.applyStatus(controller.signal)
      .then((marker) => {
        if (controller.signal.aborted) return;
        setApplyState((previous) => marker ? observation(marker) :
          previous && ["confirmed", "rolled_back", "failed"].includes(previous.result.status)
            ? previous : null);
        setUncertain(false);
        if (statusRefresh) setApplyError(null);
        setStatusLoading(false);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setApplyError(err);
        setUncertain(true);
        setStatusLoading(false);
      });
    return () => controller.abort();
  }, [user?.role, busy, statusRefresh, setApplyState, setApplyError, setUncertain]);
  useEffect(() => {
    let cancelled = false;
    setDiff(null);
    setDiffError(null);
    if (confirmed && shownDraft)
      api
        .diff(confirmed.id, shownDraft.id)
        .then((data: unknown[]) => {
          if (!cancelled) setDiff(data);
        })
        .catch((err: unknown) => {
          if (!cancelled) setDiffError(err);
        });
    return () => {
      cancelled = true;
    };
  }, [confirmed?.id, shownDraft?.id]);
  return (
    <div className="apply-wrap">
      <Typography component="h1" variant="h1" className="page-title">
        Применение изменений
      </Typography>
      <ErrorNotice error={error || (state?.error ?
        new Error(`${state.error.message} · ${state.error.code}`) : null)} />
      {!confirmed && (
        <Alert severity="warning">
          Первое применение выполняется без автоотката: подтверждённой версии ещё нет.
          Нужен доступ к локальной консоли. На подготовленном хосте агент проверяет
          сохранение выбранного физического LAN, его адреса и HTTPS на порту 443.
          Выбранный таймер начнёт действовать после первого успешного применения.
        </Alert>
      )}
      <Alert severity="info">
        Первичный адрес и порт управления зарезервированы. Перенос этого адреса
        на другой порт и смена адреса панели пока не поддерживаются.
      </Alert>
      {uncertain && (
        <Alert severity="warning">
          Результат команды неизвестен. Проверьте состояние агента; повторное
          применение заблокировано в этой вкладке.
        </Alert>
      )}
      {state && (
        <Alert
          severity={
            ["failed", "rollback_failed"].includes(state.status)
              ? "error"
              : pending
                ? "warning"
                : "info"
          }
        >
          {statusLabels[state.status]} · v{state.version_id} · состояние агента
        </Alert>
      )}
      {pending && (
        <>
          <Alert severity="warning">
            Конфигурация не подтверждена. Агент выполняет автоматический откат
            при истечении окна или потере доступа.
          </Alert>
          <div className="countdown">
            <span>Подтвердите изменения в течение</span>
            <span className="timer" role="timer">
              {seconds === null
                ? "—"
                : `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`}
            </span>
            <span className="sub">
              {applyState?.approximate
                ? "Приблизительно: от начала запроса. Дедлайн агента недоступен."
                : "По дедлайну агента"}
            </span>
          </div>
          {seconds === 0 && (
            <Alert severity="warning">
              Окно истекло по локальному таймеру. Подтверждение отключено; факт
              отката без маркера неизвестен.
            </Alert>
          )}
        </>
      )}
      <Card title="Параметры применения">
        <div className="fields">
          <TextField
            select
            label="Черновик"
            value={draft?.id ?? ""}
            slotProps={{ inputLabel: { shrink: true } }}
            onChange={(e) => setSelected(Number(e.target.value))}
            disabled={busy || !!active || user?.role !== "admin"}
          >
            {drafts
              .map((v) => (
                <MenuItem value={v.id} key={v.id}>
                  v{v.id}
                  {fmtDateTime(v.created_at) ? ` · ${fmtDateTime(v.created_at)}` : ""}
                </MenuItem>
              ))}
          </TextField>
          <FormControlLabel
            label="Безопасная настройка"
            htmlFor="safe-apply-switch"
            control={
              <Switch
                id="safe-apply-switch"
                inputProps={{ "aria-label": "Безопасная настройка" }}
                checked={preferences.safe}
                disabled={busy || !!active || user?.role !== "admin"}
                onChange={(_, safe) => setPreferences((p) => ({ ...p, safe }))}
              />
            }
          />
          <TextField
            type="number"
            label="Окно подтверждения (секунды)"
            value={preferences.timeout}
            disabled={busy || !!active || user?.role !== "admin"}
            error={!timeoutValid}
            helperText="60–600 секунд; по умолчанию 180"
            slotProps={{ htmlInput: { min: 60, max: 600 } }}
            onChange={(e) =>
              setPreferences((p) => ({ ...p, timeout: Number(e.target.value) }))
            }
          />
        </div>
        {!draft && <Alert severity="info">Нет черновика для применения.</Alert>}
        {preferences.safe && !confirmed && (
          <Alert severity="warning">
            Безопасный режим требует ранее подтверждённой версии на агенте.
            Первая конфигурация применяется без него.
          </Alert>
        )}
      </Card>
      <Card title="Фазы применения">
        <DataTable
          heads={["Сервис", "Фаза"]}
          rows={Object.entries(state?.phases ?? {}).map(([service, phase]) => [
            service,
            <Badge
              tone={
                phase === "failed"
                  ? "red"
                  : phase === "applied"
                    ? "green"
                    : "blue"
              }
            >
              {phase}
            </Badge>,
          ])}
        />
        <p className="sub">
          Фазы nftables, Unbound и Kea поступают в ответе команды. Поток
          промежуточных фаз и Caddy: TODO-API.
        </p>
      </Card>
      <Card
        title={`Изменения (${confirmed ? `v${confirmed.id}${fmtDateTime(confirmed.created_at) ? ` от ${fmtDateTime(confirmed.created_at)}` : ""}` : "нет стабильной версии"} → ${draft ? `v${draft.id}${fmtDateTime(draft.created_at) ? ` от ${fmtDateTime(draft.created_at)}` : ""}` : "нет черновика"})`}
      >
        <ErrorNotice error={diffError} />
        {diff ? (
          <pre className="diff">{JSON.stringify(diff, null, 2)}</pre>
        ) : (
          <p className="sub">
            Для diff нужны подтверждённая версия и черновик.
          </p>
        )}
      </Card>
      <div className="footer-actions">
        <Button
          disabled={busy || statusLoading || user?.role !== "admin"}
          onClick={() => setStatusRefresh((value) => value + 1)}
        >
          Обновить состояние
        </Button>
        <Button
          variant="contained"
          disabled={
            busy ||
            statusLoading ||
            user?.role !== "admin" ||
            !!active ||
            uncertain ||
            !draft ||
            !timeoutValid
          }
          onClick={() => void command("apply")}
        >
          {busy ? "Выполняется…" : "Применить"}
        </Button>
        <Button
          variant="contained"
          disabled={busy || user?.role !== "admin" || statusLoading || uncertain || !pending || seconds === 0 || seconds === null}
          onClick={() => void command("confirm")}
        >
          Подтвердить изменения
        </Button>
        <Button
          color="error"
          variant="contained"
          disabled={busy || user?.role !== "admin" || !(active || uncertain)}
          onClick={() => void command("rollback")}
        >
          Откатить сейчас
        </Button>
        <Button
          color="error"
          disabled={busy || user?.role !== "admin" || !draft || !!active}
          onClick={() => {
            if (window.confirm("Сбросить черновик? Изменения будут потеряны."))
              void discardDraft()
                .then(() => setNotice("Черновик сброшен"))
                .catch((err: unknown) => setApplyError(err));
          }}
        >
          Сбросить черновик
        </Button>
        <Button component={Link} to="/">
          Вернуться к обзору
        </Button>
      </div>
    </div>
  );
}
