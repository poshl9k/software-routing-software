import { Alert, Button, Checkbox, FormControlLabel, Typography } from "@mui/material";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useConfiguration } from "../state";
import { api } from "../api";
import { queryKeys } from "../query";
import type { TProxy, TProxyRule } from "../types";
import { addressValid, lines, nameValid } from "../components/validators";
import { EditorFooter } from "../components/EditorShell";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { PageHeader } from "../components/PageHeader";
import { SelectField, interfaceLabel } from "../components/Select";
import { useDraftEditor } from "../hooks/useDraftEditor";

const domainValid = (domain: string) => /^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$/.test(domain);
const ruleValid = (rule: TProxyRule) => nameValid(rule.name) &&
  (rule.domain_suffix.length > 0 || rule.ip_cidr.length > 0) &&
  rule.domain_suffix.every(domainValid) &&
  rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr));
const timeValid = (time: string) => /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(time);

/** Draft-only TProxy page. Live interception stays blocked by the backend. */
export default function Routing() {
  const { configuration, version, user, error: apiError } = useConfiguration();
  const editor = useDraftEditor<TProxy>();
  const queryClient = useQueryClient();
  // On-demand: only fetched when the operator asks, so `enabled: false`.
  const preview = useQuery({
    queryKey: queryKeys.tproxyPreview(version?.id ?? null),
    queryFn: api.previewTproxy,
    enabled: false,
  });
  const clearPreview = () =>
    queryClient.removeQueries({ queryKey: queryKeys.tproxyPreview(version?.id ?? null) });
  const current: TProxy = editor.value ?? { ...configuration.tproxy,
    rules: [...configuration.tproxy.rules].sort((a, b) => a.order - b.order) };
  const sources = configuration.interfaces.filter((i) => i.zone && i.zone !== "wan");
  const patch = (value: Partial<TProxy>) => editor.setValue({ ...current, ...value });
  const updateRule = (index: number, value: Partial<TProxyRule>) =>
    patch({ rules: current.rules.map((r, i) => i === index ? { ...r, ...value } : r) });
  const schedule = current.update_schedule;
  const scheduleValid = schedule.mode === "interval"
    ? Number.isInteger(schedule.interval_hours) && schedule.interval_hours >= 1 && schedule.interval_hours <= 168
    : timeValid(schedule.window_start) && timeValid(schedule.window_end) && schedule.window_start < schedule.window_end;
  const valid = scheduleValid && current.rules.every(ruleValid) &&
    new Set(current.rules.map((r) => r.name)).size === current.rules.length;
  const save = async () => {
    if (user?.role === "operator" || !valid) return;
    clearPreview();
    await editor.save((tproxy) => ({ ...configuration, tproxy: { ...tproxy, enabled: false } }));
  };
  return (
    <>
      <PageHeader>Маршрутизация · sing-box TProxy</PageHeader>
      <Alert severity="warning">
        TProxy пока недоступен: перехват и защита при отказе не проверены. Сохранённые правила не влияют на трафик.
      </Alert>
      <ErrorNotice error={editor.error ?? preview.error ?? apiError} />
      <Typography>Состояние: {configuration.tproxy.enabled ? "включён" : "выключен"}</Typography>
      <Button disabled>Включить TProxy</Button>
      {!editor.isEdit || user?.role === "operator" ? (
        <>
          <Button disabled={!version || user?.role === "operator"}
            onClick={() => { clearPreview(); editor.begin(current); }}>Редактировать</Button>
          <Typography>Источники: {current.ingress_interfaces.join(", ") || "не выбраны"}</Typography>
          {current.rules.map((rule) => <Typography key={rule.name}>{rule.name} · {rule.action}</Typography>)}
          <Button disabled={user?.role !== "admin" || version?.status !== "draft" || preview.isFetching}
            onClick={() => void preview.refetch()}>Предпросмотр сохранённого черновика</Button>
          {preview.data && !editor.isEdit && preview.data.version_id === version?.id && <>
            <Alert severity="info">Синтаксический предпросмотр. Это не работающий перехват; источники и расписание не активны.</Alert>
            <pre aria-label="Конфигурация sing-box">{JSON.stringify(preview.data.singbox, null, 2)}</pre>
          </>}
        </>
      ) : (
        <>
          <Typography variant="h2">Источники трафика</Typography>
          {sources.map((source) => <FormControlLabel
            key={source.name}
            label={interfaceLabel(source.name, configuration.interfaces)}
            control={<Checkbox checked={current.ingress_interfaces.includes(source.name)}
              onChange={(_, checked) => patch({ ingress_interfaces: checked
                ? [...current.ingress_interfaces, source.name]
                : current.ingress_interfaces.filter((name) => name !== source.name) })} />}
          />)}
          <Typography variant="h2">Правила (первое совпадение)</Typography>
          {current.rules.map((rule, index) => <div key={index} className="form-grid">
            <Field label="Имя правила" value={rule.name} valid={nameValid(rule.name)}
              onChange={(name) => updateRule(index, { name })} />
            <Field label="Домены (по строкам)" multiline value={rule.domain_suffix.join("\n")}
              valid={rule.domain_suffix.every(domainValid)}
              onChange={(text) => updateRule(index, { domain_suffix: lines(text) })} />
            <Field label="IPv4-сети (по строкам)" multiline value={rule.ip_cidr.join("\n")}
              valid={rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
              onChange={(text) => updateRule(index, { ip_cidr: lines(text) })} />
            <SelectField label="Действие" value={rule.action} options={["direct", "block"]}
              onChange={(action) => updateRule(index, { action })} />
            <Button disabled={index === 0} onClick={() => {
              const rules = [...current.rules];
              [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
              patch({ rules: rules.map((r, order) => ({ ...r, order })) });
            }}>Вверх {rule.name}</Button>
            <Button color="error" onClick={() => patch({ rules: current.rules.filter((_, i) => i !== index)
              .map((r, order) => ({ ...r, order })) })}>Удалить {rule.name}</Button>
          </div>)}
          <Button onClick={() => patch({ rules: [...current.rules, {
            name: "", domain_suffix: [], ip_cidr: [], action: "direct", order: current.rules.length,
          }] })}>+ Добавить правило</Button>
          <Typography variant="h2">Обновление списков (после запуска TProxy)</Typography>
          <SelectField label="Режим обновления" value={schedule.mode}
            options={["interval", "window"]}
            onChange={(mode) => patch({ update_schedule: { ...schedule, mode } })} />
          {schedule.mode === "interval" ? (
            <Field label="Интервал, часов" type="number" value={schedule.interval_hours}
              valid={scheduleValid}
              onChange={(value) => patch({ update_schedule: { ...schedule, interval_hours: Number(value) } })} />
          ) : (
            <>
              <Field label="Начало окна" value={schedule.window_start}
                valid={timeValid(schedule.window_start)}
                onChange={(window_start) => patch({ update_schedule: { ...schedule, window_start } })} />
              <Field label="Конец окна" value={schedule.window_end}
                valid={timeValid(schedule.window_end) && schedule.window_start < schedule.window_end}
                onChange={(window_end) => patch({ update_schedule: { ...schedule, window_end } })} />
            </>
          )}
          <EditorFooter saving={editor.saving} valid={valid} cancel={editor.cancel}
            save={() => void save()} />
        </>
      )}
    </>
  );
}