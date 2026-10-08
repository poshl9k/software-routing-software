import { Alert, Button, Checkbox, FormControlLabel, Typography } from "@mui/material";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useConfiguration } from "../state";
import { api } from "../api";
import { queryKeys } from "../query";
import type { TProxy, TProxyBypass, TProxyRule } from "../types";
import { addressValid, lines, nameValid, portValid } from "../components/validators";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormActions, FormGrid } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { SelectField, interfaceLabel } from "../components/Select";
import { ValueTabs } from "../components/Tabs";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { ProxiesEditor, RuleSets } from "./RoutingProxy";

const domainValid = (domain: string) => /^(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+$/.test(domain);
const portRangeValid = (value: string) => {
  const match = /^(\d+)(?:-(\d+))?$/.exec(value);
  return !!match && portValid(Number(match[1])) &&
    (!match[2] || (portValid(Number(match[2])) && Number(match[2]) >= Number(match[1])));
};
const ruleValid = (rule: TProxyRule, outbounds: readonly string[], ruleSets: readonly string[]) =>
  nameValid(rule.name) &&
  (rule.domain_suffix.length > 0 || rule.ip_cidr.length > 0 ||
    rule.source_ip_cidr.length > 0 || rule.rule_sets.length > 0 || rule.ports.length > 0) &&
  rule.domain_suffix.every(domainValid) &&
  rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) &&
  rule.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) &&
  rule.ports.every(portRangeValid) &&
  rule.rule_sets.every((name) => ruleSets.includes(name)) &&
  (rule.action !== "route" ||
    (rule.outbound !== null && outbounds.includes(rule.outbound)));
// A bypass row excludes traffic from capture: at least one of source/dest/ports,
// IPv4-only addresses, valid ports.
const bypassValid = (row: TProxyBypass) =>
  nameValid(row.name) &&
  (row.source_ip_cidr.length > 0 || row.ip_cidr.length > 0 || row.ports.length > 0) &&
  row.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) &&
  row.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) &&
  row.ports.every(portRangeValid);
const timeValid = (time: string) => /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(time);

/** Draft-only TProxy policy. Live interception stays blocked by the backend. */
function TProxyEditor() {
  const { configuration, version, user } = useConfiguration();
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
  // Outbounds a rule may route to: declared proxy outbounds and groups. They
  // are only rendered by the generator while the proxies section is enabled.
  const outboundOptions = [
    ...configuration.proxies.outbounds.map((o) => o.tag),
    ...configuration.proxies.groups.map((g) => g.tag),
  ];
  const ruleSetOptions = configuration.rule_sets.map((s) => s.name);
  const patch = (value: Partial<TProxy>) => editor.setValue({ ...current, ...value });
  const updateRule = (index: number, value: Partial<TProxyRule>) =>
    patch({ rules: current.rules.map((r, i) => i === index ? { ...r, ...value } : r) });
  const updateBypass = (index: number, value: Partial<TProxyBypass>) =>
    patch({ bypass: current.bypass.map((r, i) => i === index ? { ...r, ...value } : r) });
  const schedule = current.update_schedule;
  const scheduleValid = schedule.mode === "interval"
    ? Number.isInteger(schedule.interval_hours) && schedule.interval_hours >= 1 && schedule.interval_hours <= 168
    : timeValid(schedule.window_start) && timeValid(schedule.window_end) && schedule.window_start < schedule.window_end;
  const finalValid = current.final !== "route" ||
    (current.final_outbound !== null && outboundOptions.includes(current.final_outbound));
  const valid = scheduleValid && finalValid &&
    current.rules.every((r) => ruleValid(r, outboundOptions, ruleSetOptions)) &&
    new Set(current.rules.map((r) => r.name)).size === current.rules.length &&
    current.bypass.every(bypassValid) &&
    new Set(current.bypass.map((r) => r.name)).size === current.bypass.length;
  const save = async () => {
    if (user?.role === "operator" || !valid) return;
    clearPreview();
    await editor.save((tproxy) => ({ ...configuration, tproxy: { ...tproxy, enabled: false } }));
  };
  return (
    <>
      <Alert severity="warning">
        TProxy пока недоступен: перехват и защита при отказе не проверены. Сохранённые правила не влияют на трафик.
      </Alert>
      <ErrorNotice error={editor.error ?? preview.error} />
      <Typography>Состояние: {configuration.tproxy.enabled ? "включён" : "выключен"}</Typography>
      <Button disabled>Включить TProxy</Button>
      {!editor.isEdit || user?.role === "operator" ? (
        <>
          <Button disabled={!version || user?.role === "operator"}
            onClick={() => { clearPreview(); editor.begin(current); }}>Редактировать</Button>
          <Typography>Источники: {current.ingress_interfaces.join(", ") || "не выбраны"}</Typography>
          {current.rules.map((rule) => <Typography key={rule.name}>{rule.name} · {rule.action}
            {rule.action === "route" && rule.outbound ? ` → ${rule.outbound}` : ""}</Typography>)}
          <Typography>Конечное действие: {current.final}
            {current.final === "route" && current.final_outbound ? ` → ${current.final_outbound}` : ""}</Typography>
          <Typography>Исключения (bypass): {current.bypass.length}</Typography>
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
          {current.rules.map((rule, index) => <div key={index} className="rule-row">
            <FormGrid>
              <Field label="Имя правила" value={rule.name} valid={nameValid(rule.name)}
                onChange={(name) => updateRule(index, { name })} />
              <Field label="Домены (по строкам)" multiline value={rule.domain_suffix.join("\n")}
                valid={rule.domain_suffix.every(domainValid)}
                onChange={(text) => updateRule(index, { domain_suffix: lines(text) })} />
              <Field label="IPv4-сети (по строкам)" multiline value={rule.ip_cidr.join("\n")}
                valid={rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(text) => updateRule(index, { ip_cidr: lines(text) })} />
              <Field label="Источник IP (по строкам)" multiline value={rule.source_ip_cidr.join("\n")}
                valid={rule.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(text) => updateRule(index, { source_ip_cidr: lines(text) })} />
              <Field label="Порты (по строкам)" multiline value={rule.ports.join("\n")}
                valid={rule.ports.every(portRangeValid)}
                onChange={(text) => updateRule(index, { ports: lines(text) })} />
              <SelectField label="Протокол" value={rule.protocol} options={["any", "tcp", "udp"]}
                onChange={(protocol) => updateRule(index, { protocol })} />
              <SelectField label="Действие" value={rule.action} options={["direct", "block", "route"]}
                onChange={(action) => updateRule(index, {
                  action,
                  outbound: action === "route" ? rule.outbound : null,
                })} />
              {rule.action === "route" && (
                <SelectField label="Выход" value={rule.outbound ?? ""} options={outboundOptions}
                  onChange={(outbound) => updateRule(index, { outbound })} />
              )}
              <FormActions>
                <Button disabled={index === 0} onClick={() => {
                  const rules = [...current.rules];
                  [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
                  patch({ rules: rules.map((r, order) => ({ ...r, order })) });
                }}>Вверх {rule.name}</Button>
                <DeleteButton
                  label={`Удалить правило ${rule.name}`}
                  onClick={() => patch({ rules: current.rules.filter((_, i) => i !== index)
                    .map((r, order) => ({ ...r, order })) })}
                />
              </FormActions>
            </FormGrid>
            {ruleSetOptions.length > 0 && (
              <>
                <Typography>Наборы правил</Typography>
                {ruleSetOptions.map((name) => <FormControlLabel key={name} label={name}
                  control={<Checkbox checked={rule.rule_sets.includes(name)}
                    onChange={(_, checked) => updateRule(index, { rule_sets: checked
                      ? [...rule.rule_sets, name]
                      : rule.rule_sets.filter((n) => n !== name) })} />} />)}
              </>
            )}
          </div>)}
          <Button onClick={() => patch({ rules: [...current.rules, {
            name: "", domain_suffix: [], ip_cidr: [], source_ip_cidr: [], rule_sets: [],
            protocol: "any", ports: [], action: "direct", outbound: null,
            order: current.rules.length,
          }] })}>+ Добавить правило</Button>
          <Typography variant="h2">Конечное действие</Typography>
          <FormGrid>
            <SelectField label="Для несовпавшего трафика" value={current.final}
              options={["direct", "block", "route"]}
              onChange={(final) => patch({
                final,
                final_outbound: final === "route" ? current.final_outbound : null,
              })} />
            {current.final === "route" && (
              <SelectField label="Выход по умолчанию" value={current.final_outbound ?? ""}
                options={outboundOptions}
                onChange={(final_outbound) => patch({ final_outbound })} />
            )}
          </FormGrid>
          <Typography variant="h2">Исключения из перехвата (bypass)</Typography>
          {current.bypass.map((row, index) => <div key={index} className="rule-row">
            <FormGrid>
              <Field label="Имя исключения" value={row.name} valid={nameValid(row.name)}
                onChange={(name) => updateBypass(index, { name })} />
              <Field label="Источник IP (bypass)" multiline value={row.source_ip_cidr.join("\n")}
                valid={row.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(text) => updateBypass(index, { source_ip_cidr: lines(text) })} />
              <Field label="Назначение IPv4 (bypass)" multiline value={row.ip_cidr.join("\n")}
                valid={row.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(text) => updateBypass(index, { ip_cidr: lines(text) })} />
              <Field label="Порты (bypass)" multiline value={row.ports.join("\n")}
                valid={row.ports.every(portRangeValid)}
                onChange={(text) => updateBypass(index, { ports: lines(text) })} />
              <SelectField label="Протокол (bypass)" value={row.protocol} options={["any", "tcp", "udp"]}
                onChange={(protocol) => updateBypass(index, { protocol })} />
              <FormActions>
                <DeleteButton label={`Удалить исключение ${row.name || index + 1}`}
                  onClick={() => patch({ bypass: current.bypass.filter((_, i) => i !== index) })} />
              </FormActions>
            </FormGrid>
          </div>)}
          <Button onClick={() => patch({ bypass: [...current.bypass, {
            name: "", source_ip_cidr: [], ip_cidr: [], ports: [], protocol: "any",
          }] })}>+ Добавить исключение</Button>
          <Typography variant="h2">Обновление списков (после запуска TProxy)</Typography>
          <FormGrid>
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
          </FormGrid>
          <EditorFooter saving={editor.saving} valid={valid} cancel={editor.cancel}
            save={() => void save()} />
        </>
      )}
    </>
  );
}

type RoutingTab = "tproxy" | "proxies" | "rulesets";

/** The «Маршрутизация» section: TProxy policy, proxy exits and rule-set sources. */
export default function Routing() {
  const { error: apiError } = useConfiguration();
  const [tab, setTab] = useState<RoutingTab>("tproxy");
  return (
    <>
      <PageHeader>Маршрутизация</PageHeader>
      <ErrorNotice error={apiError} />
      <ValueTabs
        value={tab}
        change={setTab}
        tabs={[
          { value: "tproxy", label: "sing-box TProxy" },
          { value: "proxies", label: "Прокси-выходы" },
          { value: "rulesets", label: "Rule-set" },
        ]}
      />
      {tab === "tproxy" && <TProxyEditor />}
      {tab === "proxies" && <ProxiesEditor />}
      {tab === "rulesets" && <RuleSets />}
    </>
  );
}
