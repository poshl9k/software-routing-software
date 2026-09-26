import { useEffect, useRef, useState } from "react";
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
import {
  observation,
  statusLabels,
  useCountdown,
  useRouterState,
} from "../state";
import { Badge, Card, DataTable, ErrorNotice, Todo } from "../ui";
import { readPreferences, savePreferences } from "../preferences";
import type { ApplyResult } from "../types";
export default function ApplyScreen() {
  const {
    versions,
    refresh,
    applyState,
    setApplyState,
    uncertain,
    setUncertain,
    busy,
    setBusy,
  } = useRouterState();
  const [preferences, setPreferences] = useState(readPreferences);
  const [selected, setSelected] = useState<number | "">("");
  const [error, setError] = useState<unknown>(null);
  const [diff, setDiff] = useState<unknown[] | null>(null);
  const [diffError, setDiffError] = useState<unknown>(null);
  const requestLock = useRef(false);
  const draft = versions.find(
    (v) => v.status === "draft" && (selected === "" || selected === v.id),
  );
  const confirmed = versions
    .filter((v) => v.status === "confirmed")
    .sort((a, b) => b.id - a.id)[0];
  const seconds = useCountdown(applyState?.deadline ?? null);
  const state = applyState?.result;
  const pending = state?.status === "pending";
  const active =
    state &&
    ["pending", "applying", "rolling_back", "rollback_failed"].includes(
      state.status,
    );
  useEffect(() => {
    let cancelled = false;
    setDiff(null);
    setDiffError(null);
    if (confirmed && draft)
      api
        .diff(confirmed.id, draft.id)
        .then((data) => {
          if (!cancelled) setDiff(data);
        })
        .catch((err) => {
          if (!cancelled) setDiffError(err);
        });
    return () => {
      cancelled = true;
    };
  }, [confirmed?.id, draft?.id]);
  async function command(kind: "apply" | "confirm" | "rollback") {
    if (requestLock.current || busy) return;
    requestLock.current = true;
    setBusy(true);
    setError(null);
    const started = Date.now();
    try {
      let result: ApplyResult;
      if (kind === "apply") {
        if (!draft) return;
        const params = {
          version_id: draft.id,
          safe_mode: preferences.safe,
          confirmation_timeout: preferences.timeout,
        };
        savePreferences(preferences);
        result = await api.apply(params);
        setApplyState(observation(result, params, started));
      } else {
        if (kind === "confirm" && !state) return;
        result =
          kind === "confirm"
            ? await api.confirm(state!.version_id)
            : await api.rollback();
        setApplyState(observation(result));
      }
      setUncertain(false);
      if (result.error)
        setError(new Error(`${result.error.message} · ${result.error.code}`));
      await refresh();
    } catch (err) {
      setError(err);
      setUncertain(true);
    } finally {
      requestLock.current = false;
      setBusy(false);
    }
  }
  const timeoutValid =
    Number.isInteger(preferences.timeout) &&
    preferences.timeout >= 60 &&
    preferences.timeout <= 600;
  return (
    <div className="apply-wrap">
      <Typography component="h1" variant="h1" className="page-title">
        Применение изменений
      </Typography>
      <Todo>
        HTTP-чтение маркера агента отсутствует. Здесь показан только последний
        ответ команды в этой вкладке. После перезагрузки состояние неизвестно;
        БД не заменяет маркер.
      </Todo>
      <ErrorNotice error={error} />
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
          {statusLabels[state.status]} · v{state.version_id} · последний ответ
          команды
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
            onChange={(e) => setSelected(Number(e.target.value))}
            disabled={busy || !!active}
          >
            {versions
              .filter((v) => v.status === "draft")
              .map((v) => (
                <MenuItem value={v.id} key={v.id}>
                  v{v.id}
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
                disabled={busy || !!active}
                onChange={(_, safe) => setPreferences((p) => ({ ...p, safe }))}
              />
            }
          />
          <TextField
            type="number"
            label="Окно подтверждения (секунды)"
            value={preferences.timeout}
            disabled={busy || !!active}
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
        title={`Изменения (${confirmed ? `v${confirmed.id}` : "нет стабильной версии"} → ${draft ? `v${draft.id}` : "нет черновика"})`}
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
          variant="contained"
          disabled={
            busy ||
            !!active ||
            uncertain ||
            !draft ||
            !timeoutValid ||
            (preferences.safe && !confirmed)
          }
          onClick={() => void command("apply")}
        >
          {busy ? "Выполняется…" : "Применить черновик"}
        </Button>
        <Button
          variant="contained"
          disabled={busy || !pending || seconds === 0 || seconds === null}
          onClick={() => void command("confirm")}
        >
          Подтвердить изменения
        </Button>
        <Button
          color="error"
          variant="contained"
          disabled={busy || !(active || uncertain)}
          onClick={() => void command("rollback")}
        >
          Откатить сейчас
        </Button>
        <Button component={Link} to="/">
          Вернуться к обзору
        </Button>
      </div>
    </div>
  );
}
