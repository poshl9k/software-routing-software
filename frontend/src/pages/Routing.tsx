import { Alert, Button, Checkbox, FormControlLabel, Typography } from "@mui/material";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useConfiguration } from "../state";
import { api } from "../api";
import { queryKeys } from "../query";
import type { TProxy, TProxyBypass, TProxyDNSServer, TProxyDNSRule, TProxyRule } from "../types";
import { addressValid, lines, nameValid, portValid } from "../components/validators";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormActions, FormGrid } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
import { Select, SelectField, interfaceLabel } from "../components/Select";
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
const dnsServerValid = (row: TProxyDNSServer, tags: readonly string[]) =>
  nameValid(row.tag) && row.server.trim().length > 0 &&
  (row.server_port === null || portValid(row.server_port)) &&
  (row.type !== "tls" || !!row.tls_name?.trim()) &&
  (row.domain_resolver === null ||
    (row.domain_resolver !== row.tag && tags.includes(row.domain_resolver)));
const dnsRuleValid = (row: TProxyDNSRule, tags: readonly string[], ruleSets: readonly string[]) =>
  nameValid(row.name) && (row.domain_suffix.length > 0 || row.rule_sets.length > 0) &&
  row.domain_suffix.every(domainValid) && row.rule_sets.every((name) => ruleSets.includes(name)) &&
  tags.includes(row.server);
const timeValid = (time: string) => /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/.test(time);
const emptyWizardRule = (): TProxyRule => ({
  name: "", domain_suffix: [], ip_cidr: [], source_ip_cidr: [], rule_sets: [],
  protocol: "any", ports: [], action: "direct", outbound: null, order: 0,
});

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
  // Browse starts in the compact view; editing still opens the full editor.
  const [view, setView] = useState<"simple" | "wizard" | "expert">("simple");
  const [step, setStep] = useState(0);
  const [wizardSources, setWizardSources] = useState<string[]>([]);
  const [wizardRule, setWizardRule] = useState<TProxyRule>(emptyWizardRule);
  const [wizardSubmitted, setWizardSubmitted] = useState(false);
  const current: TProxy = editor.value ?? { ...configuration.tproxy,
    rules: [...configuration.tproxy.rules].sort((a, b) => a.order - b.order) };
  const sources = configuration.interfaces.filter((i) => i.zone && i.zone !== "wan");
  // Counters and summary for the "Простой" (compact) view.
  const sourcesCount = current.ingress_interfaces.length;
  const rulesCount = current.rules.length;
  const bypassCount = current.bypass.length;
  const finalAction = current.final;
  const countersRow = `Источники: ${sourcesCount} · ` +
                     `Правила: ${rulesCount} · ` +
                     `Исключения: ${bypassCount} · ` +
                     `Конечное действие: ${finalAction}`;
  // One-line flow summary: «источники → sing-box → назначения · финал: {final}»
  const sourcesJoined = current.ingress_interfaces.join(", ") || "не выбраны";
  const destinations: string[] = [];
  for (const rule of current.rules) {
    const dest = rule.action === "route" && rule.outbound ? rule.outbound : rule.action;
    if (dest !== current.final && !destinations.includes(dest)) {
      destinations.push(dest);
    }
  }
  destinations.push(current.final); // always ends with the final action, no duplicate
  const summaryLine = `${sourcesJoined} → sing-box → ${destinations.join(", ")} · финал: ${current.final}`;
  // Outbounds a rule may route to: declared proxy outbounds and groups. They
  // are only rendered by the generator while the proxies section is enabled.
  const outboundOptions = [
    ...configuration.proxies.outbounds.map((o) => o.tag),
    ...configuration.proxies.groups.map((g) => g.tag),
  ];
  const ruleSetOptions = configuration.rule_sets.map((s) => s.name);
  const dnsTags = current.dns.servers.map((server) => server.tag);
  const patch = (value: Partial<TProxy>) => editor.setValue({ ...current, ...value });
  const updateDNSServer = (index: number, value: Partial<TProxyDNSServer>) =>
    patch({ dns: { ...current.dns, servers: current.dns.servers.map((row, i) =>
      i === index ? { ...row, ...value } : row) } });
  const updateDNSRule = (index: number, value: Partial<TProxyDNSRule>) =>
    patch({ dns: { ...current.dns, rules: current.dns.rules.map((row, i) =>
      i === index ? { ...row, ...value } : row) } });
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
    new Set(current.bypass.map((r) => r.name)).size === current.bypass.length &&
    current.dns.servers.every((row) => dnsServerValid(row, dnsTags)) &&
    new Set(dnsTags).size === dnsTags.length &&
    current.dns.rules.every((row) => dnsRuleValid(row, dnsTags, ruleSetOptions)) &&
    new Set(current.dns.rules.map((row) => row.name)).size === current.dns.rules.length;
  const save = async () => {
    if (user?.role === "operator" || !valid) return;
    clearPreview();
    await editor.save((tproxy) => ({ ...configuration, tproxy: { ...tproxy, enabled: false } }));
  };
  const wizardRuleValid = ruleValid(wizardRule, outboundOptions, ruleSetOptions);
  const wizardCanSave = !!version && user?.role !== "operator" && editor.isEdit &&
    !editor.saving && wizardSources.length > 0 && wizardRuleValid && valid &&
    !current.rules.some((rule) => rule.name === wizardRule.name);
  const updateWizardRule = (change: Partial<TProxyRule>) =>
    setWizardRule((rule) => ({ ...rule, ...change }));
  const saveWizard = async () => {
    if (!wizardCanSave) return;
    clearPreview();
    // Entering the wizard tab already began the draft editor, so `editor.save`
    // has a working copy to commit (a no-op save would otherwise fail silently).
    setWizardSubmitted(true);
    await editor.save((tproxy) => ({ ...configuration, tproxy: {
      ...tproxy, enabled: false, ingress_interfaces: wizardSources,
      rules: [...tproxy.rules, { ...wizardRule, order: tproxy.rules.length }],
    } }));
  };
  useEffect(() => {
    if (wizardSubmitted && !editor.isEdit && !editor.saving) {
      setStep(0);
      setWizardSources([]);
      setWizardRule(emptyWizardRule());
      setWizardSubmitted(false);
      setView("simple");
    }
  }, [wizardSubmitted, editor.isEdit, editor.saving]);
  return (
    <>
      <Alert severity="warning">
        TProxy пока недоступен: перехват и защита при отказе не проверены. Сохранённые правила не влияют на трафик.
      </Alert>
      <ErrorNotice error={editor.error ?? preview.error} />
      <Typography>Состояние: {configuration.tproxy.enabled ? "включён" : "выключен"}</Typography>
      <Button disabled>Включить TProxy</Button>
      <ValueTabs
        value={view}
        change={(next) => {
          setView(next);
          if (next === "wizard" && !editor.isEdit && version && user?.role !== "operator") {
            editor.begin(current);
          }
        }}
        tabs={[{ value: "simple", label: "Простой" },
          { value: "wizard", label: "Мастер" }, { value: "expert", label: "Эксперт" }]}
      />
      {view === "wizard" ? (
        <>
          <Typography variant="h2">{["Источники", "Признаки", "Выход", "Предпросмотр"][step]}</Typography>
          {step === 0 && <>
            {sources.map((source) => <FormControlLabel key={source.name}
              label={interfaceLabel(source.name, configuration.interfaces)}
              control={<Checkbox checked={wizardSources.includes(source.name)}
                onChange={(_, checked) => setWizardSources((selected) => checked
                  ? [...selected, source.name]
                  : selected.filter((name) => name !== source.name))} />} />)}
            {sources.length === 0 && <Typography>Нет доступных источников трафика.</Typography>}
          </>}
          {step === 1 && <>
            <FormGrid>
              <Field label="Имя правила (мастер)" value={wizardRule.name} valid={nameValid(wizardRule.name)}
                onChange={(name) => updateWizardRule({ name })} />
              <Field label="Домены (мастер)" multiline value={wizardRule.domain_suffix.join("\n")}
                valid={wizardRule.domain_suffix.every(domainValid)}
                onChange={(text) => updateWizardRule({ domain_suffix: lines(text) })} />
              <Field label="Назначение IPv4 (мастер)" multiline value={wizardRule.ip_cidr.join("\n")}
                valid={wizardRule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(text) => updateWizardRule({ ip_cidr: lines(text) })} />
              <Field label="Порты (мастер)" multiline value={wizardRule.ports.join("\n")}
                valid={wizardRule.ports.every(portRangeValid)}
                onChange={(text) => updateWizardRule({ ports: lines(text) })} />
              <SelectField label="Протокол (мастер)" value={wizardRule.protocol}
                options={["any", "tcp", "udp"]}
                onChange={(protocol) => updateWizardRule({ protocol })} />
            </FormGrid>
            {ruleSetOptions.length > 0 && <>
              <Typography>Наборы правил</Typography>
              {ruleSetOptions.map((name) => <FormControlLabel key={name} label={name}
                control={<Checkbox checked={wizardRule.rule_sets.includes(name)}
                  onChange={(_, checked) => updateWizardRule({ rule_sets: checked
                    ? [...wizardRule.rule_sets, name]
                    : wizardRule.rule_sets.filter((selected) => selected !== name) })} />} />)}
            </>}
          </>}
          {step === 2 && <FormGrid>
            <SelectField label="Действие (мастер)" value={wizardRule.action}
              options={["direct", "block", "route"]}
              onChange={(action) => updateWizardRule({ action,
                outbound: action === "route" ? wizardRule.outbound : null })} />
            {wizardRule.action === "route" && <SelectField label="Выход (мастер)"
              value={wizardRule.outbound ?? ""} required options={outboundOptions}
              onChange={(outbound) => updateWizardRule({ outbound })} />}
          </FormGrid>}
          {step === 3 && <>
            <Typography>Источники: {wizardSources.join(", ")}</Typography>
            <Typography>Правило: {wizardRule.name}</Typography>
            <Typography>Домены: {wizardRule.domain_suffix.join(", ") || "нет"}</Typography>
            <Typography>Наборы правил: {wizardRule.rule_sets.join(", ") || "нет"}</Typography>
            <Typography>Назначения IPv4: {wizardRule.ip_cidr.join(", ") || "нет"}</Typography>
            <Typography>Порты: {wizardRule.ports.join(", ") || "нет"}</Typography>
            <Typography>Назначение: {wizardRule.action === "route" ? wizardRule.outbound : wizardRule.action}</Typography>
            <Typography>Полный предпросмотр sing-box доступен после сохранения черновика.</Typography>
          </>}
          <FormActions>
            {step > 0 && <Button onClick={() => setStep((previous) => previous - 1)}>Назад</Button>}
            {step < 3 ? <Button disabled={step === 0 ? wizardSources.length === 0 :
              step === 1 ? !nameValid(wizardRule.name) ||
                ![...wizardRule.domain_suffix, ...wizardRule.ip_cidr,
                  ...wizardRule.rule_sets, ...wizardRule.ports].length ||
                !wizardRule.domain_suffix.every(domainValid) ||
                !wizardRule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) ||
                !wizardRule.ports.every(portRangeValid) : !wizardRuleValid}
              onClick={() => setStep((previous) => previous + 1)}>Далее</Button>
              : <Button disabled={!wizardCanSave} onClick={() => void saveWizard()}>Сохранить черновик</Button>}
          </FormActions>
        </>
      ) : !editor.isEdit || user?.role === "operator" ? (
        <>
          {/* Простой view: counters + summary above the existing browse content. */}
          {view === "simple" && <>
            <Typography>{countersRow}</Typography>
            <Typography>{summaryLine}</Typography>
          </>}
          <Button disabled={!version || user?.role === "operator"}
            onClick={() => { clearPreview(); setView("expert"); editor.begin(current); }}>Редактировать</Button>
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
      ) : view === "simple" ? (
        <>
          {/* Простой view in edit: counters + summary + EditorFooter */}
          <Typography>{countersRow}</Typography>
          <Typography>{summaryLine}</Typography>
          <EditorFooter saving={editor.saving} valid={valid} cancel={editor.cancel}
            save={() => void save()} />
        </>
      ) : (
        <>
          {/* Expert view in edit: the full editor (today's behavior) */}
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
          <Typography variant="h2">DNS-политика (sing-box контур)</Typography>
          <Typography variant="h2">DNS-серверы</Typography>
          {current.dns.servers.map((row, index) => <div key={index} className="rule-row">
            <FormGrid>
              <Field label="Тег DNS-сервера" value={row.tag}
                valid={nameValid(row.tag) && dnsTags.indexOf(row.tag) === index}
                onChange={(tag) => updateDNSServer(index, { tag })} />
              <SelectField label="Тип DNS-сервера" value={row.type}
                options={["udp", "tls", "https"]}
                onChange={(type) => updateDNSServer(index, { type })} />
              <Field label="Сервер DNS" value={row.server} valid={!!row.server.trim()}
                onChange={(server) => updateDNSServer(index, { server })} />
              <Field label="Порт DNS" type="number" value={row.server_port ?? ""}
                inputProps={{ min: 1, max: 65535 }}
                valid={row.server_port === null || portValid(row.server_port)}
                onChange={(value) => updateDNSServer(index, {
                  server_port: value === "" ? null : Number(value),
                })} />
              {(row.type === "tls" || row.type === "https") &&
                <Field label="TLS-имя DNS" value={row.tls_name ?? ""}
                  valid={row.type !== "tls" || !!row.tls_name?.trim()}
                  onChange={(value) => updateDNSServer(index, { tls_name: value || null })} />}
              {row.type === "https" &&
                <Field label="Путь DNS" value={row.path ?? ""}
                  hint="Пусто — /dns-query по умолчанию"
                  onChange={(value) => updateDNSServer(index, { path: value || null })} />}
              <Select label="Резолвер DNS" value={row.domain_resolver ?? ""}
                placeholder={{ label: "Без резолвера" }}
                options={dnsTags.filter((tag, i) => i !== index && !!tag)
                  .map((tag) => ({ value: tag, label: tag }))}
                onChange={(value) => updateDNSServer(index, { domain_resolver: value || null })} />
              <Field label="Detour DNS" value={row.detour ?? ""}
                onChange={(value) => updateDNSServer(index, { detour: value || null })} />
              <FormActions>
                <DeleteButton label={`Удалить DNS-сервер ${row.tag || index + 1}`}
                  onClick={() => patch({ dns: { ...current.dns,
                    servers: current.dns.servers.filter((_, i) => i !== index) } })} />
              </FormActions>
            </FormGrid>
          </div>)}
          <Button onClick={() => patch({ dns: { ...current.dns, servers: [
            ...current.dns.servers, { tag: "", type: "udp", server: "", server_port: null,
              tls_name: null, path: null, domain_resolver: null, detour: null },
          ] } })}>+ Добавить DNS-сервер</Button>
          <Typography variant="h2">DNS-правила</Typography>
          {current.dns.rules.map((row, index) => <div key={index} className="rule-row">
            <FormGrid>
              <Field label="Имя DNS-правила" value={row.name}
                valid={nameValid(row.name) && current.dns.rules.findIndex((r) => r.name === row.name) === index}
                onChange={(name) => updateDNSRule(index, { name })} />
              <Field label="Домены DNS-правила" multiline value={row.domain_suffix.join("\n")}
                valid={row.domain_suffix.every(domainValid) &&
                  (row.domain_suffix.length > 0 || row.rule_sets.length > 0)}
                onChange={(text) => updateDNSRule(index, { domain_suffix: lines(text) })} />
              <SelectField label="DNS-сервер правила" value={row.server} required
                options={dnsTags.filter(Boolean)}
                onChange={(server) => updateDNSRule(index, { server })} />
              <FormActions>
                <DeleteButton label={`Удалить DNS-правило ${row.name || index + 1}`}
                  onClick={() => patch({ dns: { ...current.dns,
                    rules: current.dns.rules.filter((_, i) => i !== index) } })} />
              </FormActions>
            </FormGrid>
            {ruleSetOptions.length > 0 && <>
              <Typography>Наборы правил DNS</Typography>
              {ruleSetOptions.map((name) => <FormControlLabel key={name} label={name}
                control={<Checkbox checked={row.rule_sets.includes(name)}
                  onChange={(_, checked) => updateDNSRule(index, { rule_sets: checked
                    ? [...row.rule_sets, name]
                    : row.rule_sets.filter((selected) => selected !== name) })} />} />)}
            </>}
          </div>)}
          <Button onClick={() => patch({ dns: { ...current.dns, rules: [
            ...current.dns.rules, { name: "", domain_suffix: [], rule_sets: [], server: "" },
          ] } })}>+ Добавить DNS-правило</Button>
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
