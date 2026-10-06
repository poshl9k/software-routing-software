import { useState } from "react";
import {
  Alert,
  Button,
  FormControlLabel,
  Switch,
} from "@mui/material";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import { useApplyCommands, statusLabels, useRouterState } from "../state";
import { useApplyStatus } from "../hooks/useApplyStatus";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { PageHeader } from "../components/PageHeader";
import { Select } from "../components/Select";
import { fmtDateTime } from "../components/format";

const reasonTexts: Record<string, string> = {
  "agent.reload_failed": "не удалось применить конфигурацию сервиса",
  "agent.validation_failed": "конфигурация сервиса не прошла проверку",
  "panel.unavailable": "панель управления недоступна",
  timeout: "истекло окно подтверждения",
  requested: "откат запрошен вручную",
};
const reasonText = (code: string) => reasonTexts[code] ?? code;

export default function ApplyScreen() {
  const { uncertain, busy, applyState, discardDraft, setNotice, user,
    setApplyError } = useRouterState();
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
  const [statusRefresh, setStatusRefresh] = useState(0);
  const { loading: statusLoading } = useApplyStatus({
    refreshToken: statusRefresh,
    clearErrorOnRefresh: true,
  });
  const shownDraft =
    drafts.find((v) => v.id === selected) ?? draft;
  const diffQuery = useQuery({
    queryKey: queryKeys.diff(confirmed?.id ?? null, shownDraft?.id ?? null),
    queryFn: () => api.diff(confirmed!.id, shownDraft!.id),
    enabled: !!confirmed && !!shownDraft,
  });
  return (
    <div className="apply-wrap">
      <PageHeader>Применение изменений</PageHeader>
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
              : state.status === "rolled_back" || pending
                ? "warning"
                : "info"
          }
        >
          {statusLabels[state.status]} · v{state.version_id}
          {state.status === "rolled_back" && state.reason
            ? ` · причина: ${reasonText(state.reason)}${state.reason_service ? ` (${state.reason_service})` : ""}`
            : ""}
          {" · состояние агента"}
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
          <Select
            label="Черновик"
            value={shownDraft ? String(shownDraft.id) : ""}
            options={drafts.map((v) => ({
              value: String(v.id),
              label: `v${v.id}${fmtDateTime(v.created_at) ? ` · ${fmtDateTime(v.created_at)}` : ""}`,
            }))}
            disabled={busy || !!active || user?.role !== "admin"}
            onChange={(value) => setSelected(Number(value))}
          />
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
          <Field
            type="number"
            label="Окно подтверждения (секунды)"
            value={preferences.timeout}
            disabled={busy || !!active || user?.role !== "admin"}
            valid={timeoutValid}
            hint="60–600 секунд; по умолчанию 180"
            inputProps={{ min: 60, max: 600 }}
            onChange={(v) =>
              setPreferences((p) => ({ ...p, timeout: Number(v) }))
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
          промежуточных фаз и Caddy пока не транслируется.
        </p>
      </Card>
      <Card
        title={`Изменения (${confirmed ? `v${confirmed.id}${fmtDateTime(confirmed.created_at) ? ` от ${fmtDateTime(confirmed.created_at)}` : ""}` : "нет стабильной версии"} → ${draft ? `v${draft.id}${fmtDateTime(draft.created_at) ? ` от ${fmtDateTime(draft.created_at)}` : ""}` : "нет черновика"})`}
      >
        <ErrorNotice error={diffQuery.error} />
        {diffQuery.data ? (
          <pre className="diff">{JSON.stringify(diffQuery.data, null, 2)}</pre>
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