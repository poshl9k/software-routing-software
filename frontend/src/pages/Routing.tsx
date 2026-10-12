import { Alert, Button, Checkbox, FormControlLabel, Radio, RadioGroup, Typography } from "@mui/material";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { PageSection } from "../components/PageSection";
import { ExpertDisclosure } from "../components/ExpertDisclosure";
import { InlineStatus } from "../components/InlineStatus";
import { Toggle } from "../components/Toggle";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InfoNote } from "../components/InfoNote";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useConfiguration } from "../state";
import { api } from "../api";
import { queryKeys } from "../query";
import type { TProxy, TProxyBypass, TProxyDNSServer, TProxyDNSRule, TProxyRule } from "../types";
import { addressValid, engineTagValid, lines, nameValid, portValid } from "../components/validators";
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
const macValid = (mac: string) => /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(mac);
const regexValid = (pattern: string) => {
  try { new RegExp(pattern); return true; } catch { return false; }
};
const matcherIssue = (rule: TProxyRule, ruleSets: readonly string[], child = false): string | null => {
  const domains = [rule.domain_suffix, rule.domain_exact ?? [], rule.domain_keyword ?? [], rule.domain_regex ?? []];
  const hasMatchers = [...domains, rule.ip_cidr, rule.source_ip_cidr, rule.source_mac ?? [],
    rule.inbound ?? [], rule.rule_sets, rule.ports].some((values) => values.length > 0) ||
    rule.ip_is_private != null || rule.network != null;
  if (child && (rule.logical_mode || rule.logical_rules?.length)) return "tproxy.logical_nested";
  if (child && (rule.action !== "direct" || rule.outbound !== null)) return "tproxy.logical_child_action";
  if (!rule.logical_mode && rule.logical_rules?.length) return "tproxy.logical_mode_required";
  if (rule.logical_mode) {
    if ((rule.logical_rules?.length ?? 0) < 2) return "tproxy.logical_rules_required";
    if (hasMatchers || rule.protocol !== "any") return "tproxy.logical_matchers_unexpected";
    for (const nested of rule.logical_rules ?? []) {
      if (!nameValid(nested.name)) return "tproxy.logical_child_name_invalid";
      const issue = matcherIssue(nested, ruleSets, true);
      if (issue) return issue;
    }
  } else if (!hasMatchers) return "tproxy.rule_matcher_required";
  if ([rule.domain_suffix, rule.domain_exact ?? []].some((values) => !values.every(domainValid))) return "tproxy.domain_invalid";
  if (domains.filter((values) => values.length).length > 1) return "tproxy.domain_matchers_conflict";
  if ([...(rule.domain_keyword ?? []), ...(rule.domain_regex ?? []), ...(rule.inbound ?? [])]
    .some((value) => !value.trim())) return "tproxy.matcher_empty";
  if (!(rule.domain_regex ?? []).every(regexValid)) return "tproxy.domain_regex_invalid";
  if (!(rule.source_mac ?? []).every(macValid)) return "tproxy.source_mac_invalid";
  if (rule.network && rule.protocol !== "any" && rule.network !== rule.protocol) return "tproxy.network_conflict";
  if (!rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))) return "tproxy.ipv4_required";
  if (!rule.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))) return "tproxy.source_ipv4_required";
  if (!rule.ports.every(portRangeValid)) return "tproxy.port_invalid";
  if (!rule.rule_sets.every((name) => ruleSets.includes(name))) return "tproxy.rule_set_unavailable";
  return null;
};
const ruleValid = (rule: TProxyRule, outbounds: readonly string[], ruleSets: readonly string[]) =>
  nameValid(rule.name) && !matcherIssue(rule, ruleSets) &&
  (rule.action === "route" ? rule.outbound !== null && outbounds.includes(rule.outbound) : rule.outbound === null);
const emptyRule = (): TProxyRule => ({
  name: "", domain_suffix: [], ip_cidr: [], source_ip_cidr: [], rule_sets: [],
  protocol: "any", ports: [], action: "direct", outbound: null, order: 0,
});
const matcherErrorLabels: Record<string, string> = {
  "tproxy.logical_child_name_invalid": "Укажите корректное имя подправила.",
  "tproxy.logical_nested": "Вложенные логические группы недопустимы.",
  "tproxy.logical_child_action": "Подправило не может задавать действие или выход.",
  "tproxy.logical_mode_required": "Выберите режим логической группы.",
  "tproxy.logical_rules_required": "Для группы нужны минимум два подправила.",
  "tproxy.logical_matchers_unexpected": "В логической группе условия задаются только в подправилах.",
  "tproxy.rule_matcher_required": "Укажите хотя бы одно условие правила.",
  "tproxy.domain_invalid": "Некорректный домен.",
  "tproxy.domain_matchers_conflict": "Типы доменных условий нельзя смешивать в одном правиле; используйте группу.",
  "tproxy.matcher_empty": "Пустое условие недопустимо.",
  "tproxy.domain_regex_invalid": "Некорректное регулярное выражение домена.",
  "tproxy.source_mac_invalid": "MAC должен иметь вид 00:11:22:33:44:55.",
  "tproxy.network_conflict": "Сеть и протокол противоречат друг другу.",
  "tproxy.ipv4_required": "Укажите корректную IPv4-сеть назначения.",
  "tproxy.source_ipv4_required": "Укажите корректную IPv4-сеть источника.",
  "tproxy.port_invalid": "Некорректный порт или диапазон.",
  "tproxy.rule_set_unavailable": "Набор правил недоступен.",
};
function RuleMatchers({ rule, change, ruleSets, prefix = "" }: {
  rule: TProxyRule; change: (update: Partial<TProxyRule>) => void;
  ruleSets: readonly string[]; prefix?: string;
}) {
  const label = (text: string) => `${prefix}${text}`;
  return <FormGrid>
    <Field label={label("Домены (по строкам)")} multiline value={rule.domain_suffix.join("\n")}
      valid={rule.domain_suffix.every(domainValid)} onChange={(text) => change({ domain_suffix: lines(text) })} />
    <Field label={label("Точный домен")} multiline value={(rule.domain_exact ?? []).join("\n")}
      valid={(rule.domain_exact ?? []).every(domainValid)} onChange={(text) => change({ domain_exact: lines(text) })} />
    <Field label={label("Ключевое слово домена")} multiline value={(rule.domain_keyword ?? []).join("\n")}
      onChange={(text) => change({ domain_keyword: lines(text) })} />
    <Field label={label("Регулярное выражение домена")} multiline value={(rule.domain_regex ?? []).join("\n")}
      valid={(rule.domain_regex ?? []).every(regexValid)} onChange={(text) => change({ domain_regex: lines(text) })} />
    <Field label={label("IPv4-сети (по строкам)")} multiline value={rule.ip_cidr.join("\n")}
      valid={rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
      onChange={(text) => change({ ip_cidr: lines(text) })} />
    <Field label={label("Источник IP (по строкам)")} multiline value={rule.source_ip_cidr.join("\n")}
      valid={rule.source_ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
      onChange={(text) => change({ source_ip_cidr: lines(text) })} />
    <Field label={label("MAC источника")} multiline value={(rule.source_mac ?? []).join("\n")}
      valid={(rule.source_mac ?? []).every(macValid)} onChange={(text) => change({ source_mac: lines(text) })} />
    <Field label={label("Вход (inbound)")} multiline value={(rule.inbound ?? []).join("\n")}
      onChange={(text) => change({ inbound: lines(text) })} />
    <Field label={label("Порты (по строкам)")} multiline value={rule.ports.join("\n")}
      valid={rule.ports.every(portRangeValid)} onChange={(text) => change({ ports: lines(text) })} />
    <Select label={label("Частный IP")} value={rule.ip_is_private == null ? "" : String(rule.ip_is_private)}
      placeholder={{ label: "Любой" }} options={[{ value: "true", label: "Да" }, { value: "false", label: "Нет" }]}
      onChange={(value) => change({ ip_is_private: value === "" ? null : value === "true" })} />
    <Select label={label("Сеть")} value={rule.network ?? ""} placeholder={{ label: "Любая" }}
      options={[{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }]}
      onChange={(value) => change({ network: value ? value as "tcp" | "udp" : null })} />
    <SelectField label={label("Протокол")} value={rule.protocol} options={["any", "tcp", "udp"]}
      onChange={(protocol) => change({ protocol })} />
    {ruleSets.length > 0 && <div><Typography>Наборы правил</Typography>
      {ruleSets.map((name) => <FormControlLabel key={name} label={name}
        control={<Checkbox checked={rule.rule_sets.includes(name)} onChange={(_, checked) => change({
          rule_sets: checked ? [...rule.rule_sets, name] : rule.rule_sets.filter((n) => n !== name),
        })} />} />)}
    </div>}
  </FormGrid>;
}
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
const emptyWizardRule = (): TProxyRule => ({ ...emptyRule(), action: "route" });
const wizardDNSDirect = (): TProxyDNSServer => ({ tag: "dns-direct", type: "udp", server: "1.1.1.1",
  server_port: 53, tls_name: null, path: null, domain_resolver: null, detour: "direct" });
const wizardDNSTunnel = (outbound: string): TProxyDNSServer => ({ ...wizardDNSDirect(),
  tag: "dns-tunnel", detour: outbound });

/** TProxy policy is saved as a draft; only the shared apply flow changes traffic. */
function TProxyEditor() {
  const { configuration, version, versions, user } = useConfiguration();
  const applied = versions.filter((item) => item.status === "confirmed")
    .sort((a, b) => b.id - a.id)[0];
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
  const [view, setView] = useState<"configure" | "expert">("configure");
  const [quickstart, setQuickstart] = useState(false);
  const [addingRule, setAddingRule] = useState(false);
  const [guidedRule, setGuidedRule] = useState<TProxyRule>(emptyRule);
  const [sourceMode, setSourceMode] = useState<"all" | "selected">("selected");
  const runtime = useQuery({ queryKey: ["runtime", "engine"], queryFn: api.runtimeEngine, retry: false, refetchInterval: 15000 });
  const [step, setStep] = useState(0);
  const [wizardSources, setWizardSources] = useState<string[]>([]);
  const [wizardDNSTags, setWizardDNSTags] = useState({ direct: "dns-direct", tunnel: "dns-tunnel" });
  const [wizardDNSAddress, setWizardDNSAddress] = useState("1.1.1.1");
  const [wizardRule, setWizardRule] = useState<TProxyRule>(emptyWizardRule);
  const [wizardSubmitted, setWizardSubmitted] = useState(false);
  const [pendingEnable, setPendingEnable] = useState(false);
  const [pendingDNSDelete, setPendingDNSDelete] = useState<{ tag: string; index: number; refs: string[] } | null>(null);
  const current: TProxy = editor.value ?? { ...configuration.tproxy,
    rules: [...configuration.tproxy.rules].sort((a, b) => a.order - b.order) };
  const sources = configuration.interfaces.filter((i) => i.zone && i.zone !== "wan");
  const lanSources = sources.filter((i) => i.zone === "lan");
  const actionOptions = [
    { value: "direct", label: "Как обычно (напрямую)" },
    { value: "block", label: "Заблокировать" },
    { value: "route", label: "Через выход" },
  ];
  const sourcesJoined = current.ingress_interfaces.join(", ") || "не выбраны";
  const actionLabel = (action: TProxyRule["action"]) =>
    action === "route" ? "Прокси-выход" : action === "block" ? "Блокировать" : "Обычный маршрут";
  const matchLabel = (rule: TProxyRule): string => {
    if (rule.logical_mode) return `${rule.logical_mode === "and" ? "все" : "любое"} из: ${(rule.logical_rules ?? []).map((child) => matchLabel(child)).join("; ") || "нет условий"}`;
    return [
      ...rule.source_ip_cidr.map((v) => `устройство ${v}`),
      ...(rule.source_mac ?? []).map((v) => `MAC ${v}`),
      ...rule.domain_suffix.map((v) => `домен ${v}`),
      ...(rule.domain_exact ?? []).map((v) => `точный домен ${v}`),
      ...(rule.domain_keyword ?? []).map((v) => `слово в домене ${v}`),
      ...(rule.domain_regex ?? []).map((v) => `шаблон домена ${v}`),
      ...rule.ip_cidr.map((v) => `сеть ${v}`),
      ...rule.rule_sets.map((v) => `список ${v}`),
      ...rule.ports.map((v) => `порт ${v}`),
      ...(rule.inbound ?? []).map((v) => `вход ${v}`),
      ...(rule.ip_is_private == null ? [] : [rule.ip_is_private ? "частный IP" : "публичный IP"]),
      ...(rule.network ? [rule.network] : rule.protocol !== "any" ? [rule.protocol] : []),
    ].join(", ") || "условия не заданы";
  };
  const outboundIssue = (tag: string | null) =>
    !tag || !outboundOptions.includes(tag) ? "ссылка сломана" :
      !configuration.proxies.enabled ? "секция выходов выключена" : null;
  const summaryLine = `${sourcesJoined} → sing-box → первое подходящее правило → ${actionLabel(current.final)}${current.final_outbound && current.final === "route" ? ` → ${current.final_outbound}` : ""}`;
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
  const udpTimeoutValid = current.udp_timeout_seconds == null ||
    (Number.isInteger(current.udp_timeout_seconds) && current.udp_timeout_seconds >= 1 && current.udp_timeout_seconds <= 86400);
  const valid = udpTimeoutValid && scheduleValid && finalValid &&
    current.rules.every((r) => ruleValid(r, outboundOptions, ruleSetOptions)) &&
    new Set(current.rules.map((r) => r.name)).size === current.rules.length &&
    current.bypass.every(bypassValid) &&
    new Set(current.bypass.map((r) => r.name)).size === current.bypass.length &&
    current.dns.servers.every((row) => dnsServerValid(row, dnsTags)) &&
    new Set(dnsTags).size === dnsTags.length &&
    current.dns.rules.every((row) => dnsRuleValid(row, dnsTags, ruleSetOptions)) &&
    new Set(current.dns.rules.map((row) => row.name)).size === current.dns.rules.length;
  const wizardRuleValid = ruleValid(wizardRule, outboundOptions, ruleSetOptions);
  const wizardDNSRuleName = `dns_${wizardRule.name}`.slice(0, 31);
  const wizardDNSValid = engineTagValid(wizardDNSTags.direct) && engineTagValid(wizardDNSTags.tunnel) &&
    wizardDNSTags.direct !== wizardDNSTags.tunnel && addressValid(wizardDNSAddress) &&
    !wizardDNSAddress.includes("/") &&
    !current.dns.servers.some((server) => [wizardDNSTags.direct, wizardDNSTags.tunnel].includes(server.tag)) &&
    !current.dns.rules.some((rule) => rule.name === wizardDNSRuleName) &&
    engineTagValid(wizardDNSRuleName) &&
    (wizardRule.domain_suffix.length > 0 || wizardRule.rule_sets.length > 0);
  const wizardCandidate = quickstart;
  const ingress = wizardCandidate ? wizardSources : current.ingress_interfaces;
  const rules = wizardCandidate ? [...current.rules, wizardRule] : current.rules;
  const usesOutbound = rules.some((r) => r.action === "route") || current.final === "route";
  const enableIssue = ingress.length === 0 ? "Выберите хотя бы один источник трафика." :
    ingress.some((name) => !sources.some((source) => source.name === name)) ? "Источник трафика недоступен." :
    rules.length === 0 ? "Добавьте хотя бы одно правило." :
    !valid || !rules.every((r) => ruleValid(r, outboundOptions, ruleSetOptions)) ||
      new Set(rules.map((r) => r.name)).size !== rules.length
      ? "Исправьте правила, ссылки на выходы и обязательные поля." :
    usesOutbound && !configuration.proxies.enabled
      ? "Включите секцию прокси-выходов для выбранного выхода." : null;
  const setEnabled = (enabled: boolean) => {
    if (!enabled) { setPendingEnable(false); patch({ enabled: false }); }
    else if (!enableIssue) setPendingEnable(true);
  };
  const save = async () => {
    if (user?.role === "operator" || !valid || (current.enabled && enableIssue)) return;
    clearPreview();
    await editor.save((tproxy) => ({ ...configuration, tproxy }));
  };
  const wizardFresh = !current.enabled && current.rules.length === 0 &&
    current.dns.rules.length === 0 && current.dns.servers.length === 0;
  const wizardCanSave = !!version && user?.role !== "operator" && editor.isEdit &&
    wizardFresh && configuration.proxies.enabled &&
    !editor.saving && wizardSources.length > 0 && wizardRuleValid && wizardDNSValid && valid &&
    !current.rules.some((rule) => rule.name === wizardRule.name) &&
    (!current.enabled || !enableIssue);
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
      sniff: true,
      final: "direct", final_outbound: null,
      rules: [...tproxy.rules, { ...wizardRule, order: tproxy.rules.length }],
      dns: { ...tproxy.dns,
        servers: [...tproxy.dns.servers,
          { ...wizardDNSDirect(), tag: wizardDNSTags.direct, server: wizardDNSAddress },
          { ...wizardDNSTunnel(wizardRule.outbound!), tag: wizardDNSTags.tunnel, server: wizardDNSAddress }],
        rules: [...tproxy.dns.rules, { name: wizardDNSRuleName,
          domain_suffix: wizardRule.domain_suffix, rule_sets: wizardRule.rule_sets,
          server: wizardDNSTags.tunnel }],
      },
    } }));
  };
  useEffect(() => {
    if (wizardSubmitted && !editor.isEdit && !editor.saving) {
      setStep(0);
      setWizardSources([]);
      setWizardRule(emptyWizardRule());
      setWizardSubmitted(false);
      setQuickstart(false);
      setView("configure");
    }
  }, [wizardSubmitted, editor.isEdit, editor.saving]);
  return (
    <>
      <PageSection title="Выборочная маршрутизация (TProxy)"
        subtitle="Трафик выбранных устройств идёт через выбранный выход, остальной — как обычно."
        action={<Button variant="contained" disabled={!version || user?.role === "operator" || editor.saving ||
          (!current.enabled && !!enableIssue)} onClick={() => {
            if (!editor.isEdit) editor.begin(current);
            setEnabled(!current.enabled);
          }}>{current.enabled ? "Выключить" : "Включить"}</Button>}>
        <Badge tone={version?.status === "confirmed" && !editor.isEdit ? (current.enabled ? "green" : "blue") : "amber"}>
          {!version ? "Конфигурация недоступна" : `${current.enabled ? "Включено" : "Выключено"} · ${editor.isEdit ? "несохранённый черновик" : version.status === "confirmed" ? "применено" : "черновик"}`}
        </Badge>
        {version?.status === "draft" && applied && <Typography variant="body2">Применённая версия: {applied.configuration.tproxy.enabled ? "включена" : "выключена"}. Черновик ещё не применён.</Typography>}
        <Typography variant="body2">{summaryLine}</Typography>
        <InlineStatus tone={runtime.isError || !runtime.data ? "unknown" : runtime.data.running ? "green" : "neutral"}
          text={`Движок: ${runtime.isError || !runtime.data ? "состояние недоступно" : runtime.data.running ? "работает" : "остановлен"} · версия ${runtime.isError ? "неизвестна" : runtime.data?.version ?? "неизвестна"} · Clash API ${runtime.isError || !runtime.data ? "неизвестен" : runtime.data.clash_api ? "доступен" : "недоступен"}`} />
      </PageSection>
      <ErrorNotice error={editor.error ?? preview.error} />
      {enableIssue && !current.enabled && <Typography variant="body2">Для включения: {enableIssue}</Typography>}
      <ExpertDisclosure><Typography variant="h3">Как это работает</Typography>
        <Typography>Перехватывается только транзит выбранных LAN-источников. Исключения идут обычным маршрутом; остальные правила проверяются сверху вниз. При отказе выбранный трафик не должен уходить напрямую в WAN. Предпросмотр проверяет конфигурацию, но не подтверждает работу перехвата.</Typography>
        <Typography>Системные правила: sniff определяет домен; DNS на порту 53 перехватывается; локальные IPv4-адреса идут напрямую; для UDP действует настроенный таймаут. Эти правила здесь не редактируются.</Typography>
      </ExpertDisclosure>
      <ConfirmDialog open={pendingEnable} title="Включить выборочную маршрутизацию?"
        body="После сохранения и общего применения трафик LAN, совпадающий с правилами, будет направляться или перенаправляться согласно политике. Ошибка в настройках может нарушить подключение. Проверьте правила и доступность выходов перед применением."
        confirmLabel="Включить в черновике" cancelLabel="Отмена"
        onCancel={() => setPendingEnable(false)} onConfirm={() => {
          if (!enableIssue && editor.isEdit) patch({ enabled: true });
          setPendingEnable(false);
        }} />
      <ConfirmDialog open={!!pendingDNSDelete} title="Удалить DNS-сервер?"
        body={`Ссылки на ${pendingDNSDelete?.tag}: ${pendingDNSDelete?.refs.join(", ") || "нет"}. Удаление оставит зависимые поля без ссылки.`}
        confirmLabel="Удалить" cancelLabel="Отмена" danger
        onCancel={() => setPendingDNSDelete(null)} onConfirm={() => {
          if (pendingDNSDelete) patch({ dns: { ...current.dns,
            servers: current.dns.servers.filter((_, i) => i !== pendingDNSDelete.index) } });
          setPendingDNSDelete(null);
        }} />
      <ValueTabs value={view} change={setView}
        tabs={[{ value: "configure", label: "Настроить" }, { value: "expert", label: "Эксперт" }]} />
      {view === "expert" && <Card title="Служебные правила (добавляются автоматически)">
        <Typography variant="body2">Только просмотр: их порядок и условия задаёт движок, а не список ваших правил.</Typography>
        <Typography>1. Определение домена (sniff) — {current.sniff ? "включено" : "выключено"}</Typography>
        <Typography>2. DNS-запросы (порт 53) → локальный DNS-контур</Typography>
        <Typography>3. Локальные адреса IPv4 → напрямую</Typography>
        <Typography>4. Таймаут UDP → {current.udp_timeout_seconds == null ? "не задан" : `${current.udp_timeout_seconds} с`}</Typography>
      </Card>}
      {view === "expert" && <Card title="Параметры движка">
        {editor.isEdit && user?.role !== "operator" ? <FormGrid>
          <Toggle label="Sniff" value={current.sniff ?? false} onChange={(sniff) => patch({ sniff })} />
          <Field label="Таймаут UDP, секунд" type="number" value={current.udp_timeout_seconds ?? ""}
            hint="Пусто — выключено" valid={udpTimeoutValid} inputProps={{ min: 1, max: 86400, step: 1 }}
            onChange={(value) => patch({ udp_timeout_seconds: value === "" ? null : Number(value) })} />
        </FormGrid> : <Typography>Sniff: {current.sniff ? "включён" : "выключен"}; таймаут UDP: {current.udp_timeout_seconds ?? "выключен"}</Typography>}
        {!udpTimeoutValid && <ErrorNotice error={new Error("Таймаут UDP: целое число от 1 до 86400 (tproxy.udp_timeout_seconds).")}/>}
      </Card>}
      {view === "expert" && editor.isEdit && user?.role !== "operator" &&
        <Toggle label="Включить выборочную маршрутизацию" value={current.enabled}
          disabled={editor.saving || (!current.enabled && !!enableIssue)} onChange={setEnabled} />}
      {view === "configure" && quickstart ? (
        <>
          {!wizardFresh && <ErrorNotice error={new Error("Мастер доступен только для пустой выключенной TProxy/DNS-политики. Существующую политику изменяйте в «Эксперте».")} />}
          {!configuration.proxies.enabled && <ErrorNotice error={new Error("Включите секцию прокси-выходов перед сохранением мастера.")} />}
          <Typography>Источник → Правила → Включить</Typography>
          <Typography variant="h2">{["Источник", "Правила", "Включить после сохранения"][step]}</Typography>
          {step === 0 && <>
            <FormGrid><SelectField label="Выход (мастер)" value={wizardRule.outbound ?? ""}
              required options={outboundOptions} onChange={(outbound) => updateWizardRule({ outbound })} /></FormGrid>
            <Typography>Источники трафика</Typography>
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
          {step === 2 && <>
            <Typography>Источник: {wizardSources.join(", ")}; правило: {wizardRule.name}; выход: {wizardRule.outbound}.</Typography>
            <Typography>После сохранения политика останется выключенной. Чтобы направлять трафик, нажмите «Включить» вверху и примените общий черновик.</Typography>
            <Typography>Для доменов будет создан отдельный DNS-маршрут через выход. Остальной трафик пойдёт как обычно.</Typography>
            <ExpertDisclosure>
              <Typography>Дополнительно: адрес DNS и имена автоматических серверов</Typography>
              <FormGrid>
              <Field label="DNS-сервер (IP)" value={wizardDNSAddress}
                valid={addressValid(wizardDNSAddress) && !wizardDNSAddress.includes("/")}
                onChange={setWizardDNSAddress} />
              <Field label="Тег прямого DNS" value={wizardDNSTags.direct} valid={engineTagValid(wizardDNSTags.direct)}
                onChange={(direct) => setWizardDNSTags((tags) => ({ ...tags, direct }))} />
              <Field label="Тег туннельного DNS" value={wizardDNSTags.tunnel} valid={engineTagValid(wizardDNSTags.tunnel)}
                onChange={(tunnel) => setWizardDNSTags((tags) => ({ ...tags, tunnel }))} />
              </FormGrid>
            </ExpertDisclosure>
            {!wizardDNSValid && <ErrorNotice error={new Error("Проверьте DNS-теги (латиница, цифры, дефис/подчёркивание), IP, уникальность и наличие доменов или наборов для DNS-правила.")} />}
          </>}
          <FormActions>
            {step > 0 && <Button onClick={() => setStep((previous) => previous - 1)}>Назад</Button>}
            {step < 2 ? <Button disabled={step === 0 ? wizardSources.length === 0 || !wizardRule.outbound || !outboundOptions.includes(wizardRule.outbound) :
              !nameValid(wizardRule.name) ||
                ![...wizardRule.domain_suffix, ...wizardRule.ip_cidr,
                  ...wizardRule.rule_sets, ...wizardRule.ports].length ||
                !wizardRule.domain_suffix.every(domainValid) ||
                !wizardRule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr)) ||
                !wizardRule.ports.every(portRangeValid) || !wizardDNSValid || !wizardRuleValid}
              onClick={() => setStep((previous) => previous + 1)}>{step === 0 ? "Настроить правило" : "Проверить и сохранить"}</Button>
              : <Button disabled={!wizardCanSave} onClick={() => void saveWizard()}>Сохранить черновик</Button>}
          </FormActions>
        </>
      ) : view === "configure" ? (
        <>
          {!editor.isEdit && wizardFresh && <Card title="Начните настройку">
            <Typography>Источник → Правила → Включить. Настройка сохранится выключенной, пока вы отдельно не включите и не примените её.</Typography>
            <Button disabled={!version || user?.role === "operator"} onClick={() => {
              clearPreview(); editor.begin(current); setQuickstart(true); setStep(0);
            }}>Выбрать источник</Button>
          </Card>}
          {!editor.isEdit && <Button disabled={!version || user?.role === "operator"}
            onClick={() => { clearPreview(); editor.begin(current); }}>Редактировать</Button>}
          <Card title="Источник трафика">
            {editor.isEdit ? <>
              <RadioGroup aria-label="Источник трафика" value={sourceMode} onChange={(_, mode) => {
                setSourceMode(mode as "all" | "selected");
                if (mode === "all") patch({ ingress_interfaces: lanSources.map((source) => source.name) });
              }}>
                <FormControlLabel value="all" label="Все устройства (LAN)" control={<Radio />} />
                <FormControlLabel value="selected" label="Выбранные интерфейсы" control={<Radio />} />
              </RadioGroup>
              {sourceMode === "selected" && sources.map((source) => <FormControlLabel key={source.name}
                label={interfaceLabel(source.name, configuration.interfaces)} control={<Checkbox
                  checked={current.ingress_interfaces.includes(source.name)} onChange={(_, checked) => patch({
                    ingress_interfaces: checked ? [...current.ingress_interfaces, source.name] :
                      current.ingress_interfaces.filter((name) => name !== source.name),
                  })} />} />)}
              {sources.length === 0 && <Typography>Доступных LAN-источников нет.</Typography>}
            </> : <Typography>{sourcesJoined}</Typography>}
          </Card>
          <Card title="Правила" action={editor.isEdit ? <Button onClick={() => setAddingRule(true)}>+ Добавить правило</Button> : undefined}>
            <Typography variant="body2">Первое подходящее правило определяет путь трафика.</Typography>
            {current.rules.length === 0 && <Typography>Правил пока нет.</Typography>}
            {current.rules.map((rule, index) => <div key={index} className="rule-row">
              <Typography>{index + 1}. {rule.name || "Новое правило"}</Typography>
              <Typography>Что: {matchLabel(rule)} · Куда: {actionLabel(rule.action)}{rule.action === "route" ? ` · ${rule.outbound || "выход не выбран"}` : ""}</Typography>
              {editor.isEdit && <FormGrid>
                <Field label="Имя правила" value={rule.name} valid={nameValid(rule.name)}
                  onChange={(name) => updateRule(index, { name })} />
                <Field label="Что: домены" multiline value={rule.domain_suffix.join("\n")}
                  valid={rule.domain_suffix.every(domainValid)} onChange={(value) => updateRule(index, { domain_suffix: lines(value) })} />
                <Field label="Что: IPv4-сети" multiline value={rule.ip_cidr.join("\n")}
                  valid={rule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                  onChange={(value) => updateRule(index, { ip_cidr: lines(value) })} />
                <Field label="Что: порты" multiline value={rule.ports.join("\n")}
                  valid={rule.ports.every(portRangeValid)} onChange={(value) => updateRule(index, { ports: lines(value) })} />
                <Select label="Куда" value={rule.action} options={actionOptions}
                  onChange={(value) => { const action = value as TProxyRule["action"]; updateRule(index, { action, outbound: action === "route" ? rule.outbound : null }); }} />
                {rule.action === "route" && <SelectField label="Выход" value={rule.outbound ?? ""}
                  options={outboundOptions} onChange={(outbound) => updateRule(index, { outbound })} />}
                {matcherIssue(rule, ruleSetOptions) && <ErrorNotice error={new Error(
                  `${matcherErrorLabels[matcherIssue(rule, ruleSetOptions)!]} (${matcherIssue(rule, ruleSetOptions)})`,
                )} />}
              </FormGrid>}
              {editor.isEdit && <FormActions>
                <Button disabled={index === 0} onClick={() => { const rules = [...current.rules];
                  [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
                  patch({ rules: rules.map((r, order) => ({ ...r, order })) }); }}>Вверх {rule.name}</Button>
                <DeleteButton label={`Удалить правило ${rule.name || index + 1}`} onClick={() => patch({
                  rules: current.rules.filter((_, i) => i !== index).map((r, order) => ({ ...r, order })),
                })} />
              </FormActions>}
            </div>)}
            {editor.isEdit && addingRule && <FormGrid>
              <Field label="Имя правила" value={guidedRule.name} valid={nameValid(guidedRule.name)}
                onChange={(name) => setGuidedRule({ ...guidedRule, name })} />
              <Typography>Что направить — выберите домен сервиса или задайте свои условия.</Typography>
              <FormActions>
                <Button variant="outlined" onClick={() => setGuidedRule({ ...guidedRule, domain_suffix: ["youtube.com"] })}>YouTube (youtube.com)</Button>
                <Button variant="outlined" onClick={() => setGuidedRule({ ...guidedRule, domain_suffix: ["rutube.ru"] })}>RuTube (rutube.ru)</Button>
              </FormActions>
              <Field label="Домены" multiline value={guidedRule.domain_suffix.join("\n")}
                valid={guidedRule.domain_suffix.every(domainValid)} onChange={(value) => setGuidedRule({ ...guidedRule, domain_suffix: lines(value) })} />
              <Field label="IPv4-сети" multiline value={guidedRule.ip_cidr.join("\n")}
                valid={guidedRule.ip_cidr.every((cidr) => !cidr.includes(":") && addressValid(cidr))}
                onChange={(value) => setGuidedRule({ ...guidedRule, ip_cidr: lines(value) })} />
              <Field label="Порты" multiline value={guidedRule.ports.join("\n")}
                valid={guidedRule.ports.every(portRangeValid)} onChange={(value) => setGuidedRule({ ...guidedRule, ports: lines(value) })} />
              {ruleSetOptions.map((name) => <FormControlLabel key={name} label={name} control={<Checkbox
                checked={guidedRule.rule_sets.includes(name)} onChange={(_, checked) => setGuidedRule({ ...guidedRule,
                  rule_sets: checked ? [...guidedRule.rule_sets, name] : guidedRule.rule_sets.filter((item) => item !== name),
                })} />} />)}
              <Select label="Куда" value={guidedRule.action} options={actionOptions}
                onChange={(value) => { const action = value as TProxyRule["action"]; setGuidedRule({ ...guidedRule, action, outbound: action === "route" ? guidedRule.outbound : null }); }} />
              {guidedRule.action === "route" && <SelectField label="Выход" value={guidedRule.outbound ?? ""}
                options={outboundOptions} onChange={(outbound) => setGuidedRule({ ...guidedRule, outbound })} />}
              <FormActions><Button onClick={() => setAddingRule(false)}>Отмена</Button>
                <Button disabled={!ruleValid(guidedRule, outboundOptions, ruleSetOptions) || current.rules.some((r) => r.name === guidedRule.name)}
                  onClick={() => { patch({ rules: [...current.rules, { ...guidedRule, order: current.rules.length }] });
                    setAddingRule(false); setGuidedRule(emptyRule()); }}>Добавить</Button></FormActions>
            </FormGrid>}
          </Card>
          <Card title="Конечное действие">
            {editor.isEdit ? <FormGrid><Select label="Для несовпавшего трафика" value={current.final}
              options={actionOptions} onChange={(value) => { const final = value as TProxy["final"]; patch({ final,
                final_outbound: final === "route" ? current.final_outbound : null }); }} />
              {current.final === "route" && <SelectField label="Выход по умолчанию" value={current.final_outbound ?? ""}
                options={outboundOptions} onChange={(final_outbound) => patch({ final_outbound })} />}</FormGrid> :
              <Typography>{actionLabel(current.final)}{current.final_outbound && current.final === "route" ? ` · ${current.final_outbound}` : ""}</Typography>}
          </Card>
          <Button onClick={() => setView("expert")}>Дополнительно → Эксперт</Button>
          {editor.isEdit && <EditorFooter saving={editor.saving} valid={valid && (!current.enabled || !enableIssue)}
            cancel={editor.cancel} save={() => void save()} />}
          <Button disabled={user?.role !== "admin" || version?.status !== "draft" || preview.isFetching}
            onClick={() => void preview.refetch()}>Предпросмотр сохранённого черновика</Button>
          {preview.data && !editor.isEdit && preview.data.version_id === version?.id && <>
            <Alert severity="info">Синтаксический предпросмотр. Это не работающий перехват; источники и расписание не активны.</Alert>
            <pre aria-label="Конфигурация sing-box">{JSON.stringify(preview.data.singbox, null, 2)}</pre>
          </>}
        </>
      ) : !editor.isEdit || user?.role === "operator" ? (
        <>
          <Button disabled={!version || user?.role === "operator"}
            onClick={() => { clearPreview(); editor.begin(current); }}>Редактировать</Button>
          <Card title="Источники"><Typography>{sourcesJoined}</Typography></Card>
          <Card title="Правила">{current.rules.map((rule, index) => <Typography key={index}>
            {index + 1}. {rule.name} · {matchLabel(rule)} → {actionLabel(rule.action)}
            {rule.action === "route" ? ` · ${rule.outbound || "не выбран"}` : ""}
          </Typography>)}</Card>
          <Card title="Конечное действие"><Typography>{actionLabel(current.final)}</Typography></Card>
          <Card title="Исключения"><Typography>{current.bypass.length ? current.bypass.map((row) => row.name).join(", ") : "Исключений нет"}</Typography></Card>
          <Card title="DNS-политика"><Typography>Серверы: {current.dns.servers.length} · правила: {current.dns.rules.length}</Typography></Card>
          <Button disabled={user?.role !== "admin" || version?.status !== "draft" || preview.isFetching}
            onClick={() => void preview.refetch()}>Предпросмотр сохранённого черновика</Button>
          {preview.data && preview.data.version_id === version?.id && <pre aria-label="Конфигурация sing-box">{JSON.stringify(preview.data.singbox, null, 2)}</pre>}
        </>
      ) : (
        <>
          {/* Expert view in edit: the full editor (today's behavior) */}
          <Typography variant="h2">Источники</Typography>
          {sources.map((source) => <FormControlLabel
            key={source.name}
            label={interfaceLabel(source.name, configuration.interfaces)}
            control={<Checkbox checked={current.ingress_interfaces.includes(source.name)}
              onChange={(_, checked) => patch({ ingress_interfaces: checked
                ? [...current.ingress_interfaces, source.name]
                : current.ingress_interfaces.filter((name) => name !== source.name) })} />}
          />)}
          <Typography variant="h2">Исключения</Typography>
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
          <Typography variant="h2">Правила по порядку (первое совпадение)</Typography>
          <InfoNote>Исключения имеют приоритет: всегда обычный маршрут. Правила проверяются сверху вниз; новое правило добавляется последним.</InfoNote>
          {current.rules.map((rule, index) => <div key={index} className="rule-row">
            <Typography>{index + 1}. {rule.name || "Новое правило"}: {matchLabel(rule)} → {actionLabel(rule.action)}{rule.action === "route" ? ` → ${rule.outbound || "не выбран"}` : ""}</Typography>
            <FormGrid>
              <Field label="Имя правила" value={rule.name} valid={nameValid(rule.name)}
                onChange={(name) => updateRule(index, { name })} />
              {!rule.logical_mode && <RuleMatchers rule={rule} ruleSets={ruleSetOptions}
                change={(value) => updateRule(index, value)} />}
              <SelectField label="Действие" value={rule.action} options={["direct", "block", "route"]}
                onChange={(action) => updateRule(index, {
                  action,
                  outbound: action === "route" ? rule.outbound : null,
                })} />
              {rule.action === "route" && (
                <>
                  <SelectField label="Выход" value={rule.outbound ?? ""} options={outboundOptions}
                    onChange={(outbound) => updateRule(index, { outbound })} />
                  {outboundIssue(rule.outbound) && <InfoNote>{outboundIssue(rule.outbound)}: {rule.outbound || "выход не выбран"}</InfoNote>}
                </>
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
            <Select label="Логическая группа" value={rule.logical_mode ?? ""}
              placeholder={{ label: "Обычное правило" }}
              options={[{ value: "and", label: "И (and)" }, { value: "or", label: "ИЛИ (or)" }]}
              onChange={(mode) => updateRule(index, mode ? {
                logical_mode: mode as "and" | "or",
                logical_rules: rule.logical_rules?.length ? rule.logical_rules : [
                  { ...rule, name: "child_a", action: "direct", outbound: null, order: 0,
                    logical_mode: null, logical_rules: [] },
                  { ...emptyRule(), name: "child_b" },
                ], domain_suffix: [], domain_exact: [], domain_keyword: [], domain_regex: [],
                ip_cidr: [], source_ip_cidr: [], source_mac: [], inbound: [], ip_is_private: null,
                network: null, rule_sets: [], ports: [], protocol: "any",
              } : { logical_mode: null, logical_rules: [] })} />
            {rule.logical_mode && (rule.logical_rules ?? []).map((child, childIndex) => <div
              key={childIndex} className="rule-row">
              <Typography>Подправило {childIndex + 1}</Typography>
              <Field label={`Имя подправила ${childIndex + 1}`} value={child.name}
                valid={nameValid(child.name)} onChange={(name) => updateRule(index, {
                  logical_rules: rule.logical_rules?.map((r, i) => i === childIndex ? { ...r, name } : r),
                })} />
              <RuleMatchers rule={child} ruleSets={ruleSetOptions} prefix={`Подправило ${childIndex + 1}: `}
                change={(value) => updateRule(index, {
                  logical_rules: rule.logical_rules?.map((r, i) => i === childIndex ? { ...r, ...value } : r),
                })} />
              <DeleteButton label={`Удалить подправило ${childIndex + 1}`} onClick={() => updateRule(index, {
                logical_rules: rule.logical_rules?.filter((_, i) => i !== childIndex),
              })} />
            </div>)}
            {rule.logical_mode && <Button onClick={() => updateRule(index, {
              logical_rules: [...(rule.logical_rules ?? []), { ...emptyRule(), name: `child_${(rule.logical_rules?.length ?? 0) + 1}` }],
            })}>Добавить подправило</Button>}
            {matcherIssue(rule, ruleSetOptions) && <ErrorNotice error={new Error(
              `${matcherErrorLabels[matcherIssue(rule, ruleSetOptions)!]} (${matcherIssue(rule, ruleSetOptions)})`,
            )} />}
          </div>)}
          <Button onClick={() => patch({ rules: [...current.rules, {
            ...emptyRule(), order: current.rules.length,
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
              <>
                <SelectField label="Выход по умолчанию" value={current.final_outbound ?? ""}
                  options={outboundOptions}
                  onChange={(final_outbound) => patch({ final_outbound })} />
                {outboundIssue(current.final_outbound) && <InfoNote>{outboundIssue(current.final_outbound)}: {current.final_outbound || "выход не выбран"}</InfoNote>}
              </>
            )}
          </FormGrid>
          <Typography variant="h2">DNS-политика (sing-box контур)</Typography>
          <Typography variant="h2">DNS-серверы</Typography>
          {current.dns.servers.map((row, index) => <div key={index} className="rule-row">
            <FormGrid>
              <Field label="Тег DNS-сервера" value={row.tag}
                valid={engineTagValid(row.tag) && dnsTags.indexOf(row.tag) === index}
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
              {row.domain_resolver && !dnsTags.includes(row.domain_resolver) && <InfoNote>ссылка сломана: {row.domain_resolver}</InfoNote>}
              <Field label="Detour DNS" value={row.detour ?? ""}
                onChange={(value) => updateDNSServer(index, { detour: value || null })} />
              <FormActions>
                <DeleteButton label={`Удалить DNS-сервер ${row.tag || index + 1}`}
                  onClick={() => setPendingDNSDelete({ tag: row.tag, index, refs: [
                    ...current.dns.rules.filter((r) => r.server === row.tag).map((r) => `DNS-правило ${r.name}`),
                    ...current.dns.servers.filter((r) => r.domain_resolver === row.tag && r !== row).map((r) => `DNS-резолвер ${r.tag}`),
                  ] })} />
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
                valid={engineTagValid(row.name) && current.dns.rules.findIndex((r) => r.name === row.name) === index}
                onChange={(name) => updateDNSRule(index, { name })} />
              <Field label="Домены DNS-правила" multiline value={row.domain_suffix.join("\n")}
                valid={row.domain_suffix.every(domainValid) &&
                  (row.domain_suffix.length > 0 || row.rule_sets.length > 0)}
                onChange={(text) => updateDNSRule(index, { domain_suffix: lines(text) })} />
              <SelectField label="DNS-сервер правила" value={row.server} required
                options={dnsTags.filter(Boolean)}
                onChange={(server) => updateDNSRule(index, { server })} />
              {row.server && !dnsTags.includes(row.server) && <InfoNote>ссылка сломана: {row.server}</InfoNote>}
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
                  hint="ЧЧ:ММ по времени сервера; не включает TProxy"
                  valid={timeValid(schedule.window_start)}
                  onChange={(window_start) => patch({ update_schedule: { ...schedule, window_start } })} />
                <Field label="Конец окна" value={schedule.window_end}
                  valid={timeValid(schedule.window_end) && schedule.window_start < schedule.window_end}
                  onChange={(window_end) => patch({ update_schedule: { ...schedule, window_end } })} />
              </>
            )}
          </FormGrid>
          <EditorFooter saving={editor.saving} valid={valid && (!current.enabled || !enableIssue)} cancel={editor.cancel}
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
          { value: "rulesets", label: "Источники списков" },
        ]}
      />
      {tab === "tproxy" && <TProxyEditor />}
      {tab === "proxies" && <ProxiesEditor />}
      {tab === "rulesets" && <RuleSets />}
    </>
  );
}
