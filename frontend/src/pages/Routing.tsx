import { Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Radio, RadioGroup, Typography } from "@mui/material";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
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
import type { CatalogService, ProxyOutbound, RuleSetSource, TProxy, TProxyBypass, TProxyDNSServer, TProxyDNSRule, TProxyRule } from "../types";
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
import { ServiceCatalog } from "../components/ServiceCatalog";
import { parseShareLinks } from "../shareLinks";

const catalogSources = (services: CatalogService[]): RuleSetSource[] => services.flatMap((service) =>
  service.rule_sets.map((set) => ({ name: set.tag, format: set.format, url: set.url,
    max_records: 100_000, max_bytes: 5_000_000 })));

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
/** TProxy policy is saved as a draft; only the shared apply flow changes traffic. */
function TProxyEditor({ onOpenProxies }: { onOpenProxies: () => void }) {
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
  const [addingRule, setAddingRule] = useState(false);
  const [guidedRule, setGuidedRule] = useState<TProxyRule>(emptyRule);
  const [catalogContext, setCatalogContext] = useState<"rule" | "expert" | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [catalogMessage, setCatalogMessage] = useState<string | null>(null);
  const [pendingSets, setPendingSets] = useState<RuleSetSource[]>([]);
  const [manualSetOpen, setManualSetOpen] = useState(false);
  const [manualSet, setManualSet] = useState<RuleSetSource>({ name: "", format: "text-domain", url: "", max_records: 100_000, max_bytes: 5_000_000 });
  const [dnsEditor, setDnsEditor] = useState<{ kind: "server" | "rule"; index: number } | null>(null);
  const [catalogNames, setCatalogNames] = useState<Record<string, string>>({});
  const catalog = useQuery({ queryKey: queryKeys.presetCatalog(), queryFn: api.presetCatalog,
    enabled: catalogContext !== null });
  const [sourceMode, setSourceMode] = useState<"all" | "selected">("selected");
  const runtime = useQuery({ queryKey: ["runtime", "engine"], queryFn: api.runtimeEngine, retry: false, refetchInterval: 15000 });
  const [pendingEnable, setPendingEnable] = useState(false);
  const [pendingDisable, setPendingDisable] = useState(false);
  const [enableProxies, setEnableProxies] = useState(false);
  const [pendingOutbounds, setPendingOutbounds] = useState<ProxyOutbound[]>([]);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<Error | null>(null);
  const [editingRule, setEditingRule] = useState<number | null>(null);
  const [ruleStep, setRuleStep] = useState(0);
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
      ...rule.rule_sets.map((v) => {
        const name = catalogNames[v] ?? catalog.data?.services.find((service) =>
          service.rule_sets.some((set) => set.tag === v))?.name;
        return name ? `Из каталога: ${name}` : `Набор: ${v}`;
      }),
      ...rule.ports.map((v) => `порт ${v}`),
      ...(rule.inbound ?? []).map((v) => `вход ${v}`),
      ...(rule.ip_is_private == null ? [] : [rule.ip_is_private ? "частный IP" : "публичный IP"]),
      ...(rule.network ? [rule.network] : rule.protocol !== "any" ? [rule.protocol] : []),
    ].join(", ") || "условия не заданы";
  };
  const summaryLine = `${sourcesJoined} → sing-box → первое подходящее правило → ${actionLabel(current.final)}${current.final_outbound && current.final === "route" ? ` → ${current.final_outbound}` : ""}`;
  // Outbounds a rule may route to: declared proxy outbounds and groups. They
  // are only rendered by the generator while the proxies section is enabled.
  const outboundOptions = [
    ...configuration.proxies.outbounds.map((o) => o.tag),
    ...pendingOutbounds.map((o) => o.tag),
    ...configuration.proxies.groups.map((g) => g.tag),
  ];
  const ruleSetOptions = [...configuration.rule_sets.map((s) => s.name), ...pendingSets.map((s) => s.name)];
  const selectCatalog = (ids: string[]) => {
    const services = (catalog.data?.services ?? []).filter((service) => ids.includes(service.id));
    const selected = catalogSources(services);
    const configuredTags = new Set(configuration.rule_sets.map((set) => set.name));
    const stagedTags = new Set(pendingSets.map((set) => set.name));
    const existing = new Set(ruleSetOptions);
    const duplicates = selected.filter((set) => configuredTags.has(set.name)).map((set) => set.name);
    const alreadyStaged = selected.filter((set) => stagedTags.has(set.name)).map((set) => set.name);
    const fresh = selected.filter((set) => {
      if (existing.has(set.name)) return false;
      existing.add(set.name);
      return true;
    });
    if (catalogContext === "rule" && selected.length === 0) {
      setCatalogError("У выбранных сервисов нет наборов правил. Задайте домены вручную.");
      setCatalogContext(null);
      return;
    }
    setPendingSets((previous) => [...previous, ...fresh]);
    setCatalogNames((previous) => ({ ...previous,
      ...Object.fromEntries(services.flatMap((service) => service.rule_sets.map((set) => [set.tag, service.name]))),
    }));
    if (catalogContext === "rule") {
      setGuidedRule((previous) => ({ ...previous,
        name: previous.name || (nameValid(services[0]?.name ?? "") ? services[0].name :
          selected[0]?.name.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 31) ?? ""),
        rule_sets: [...new Set([...previous.rule_sets, ...selected.map((set) => set.name)])],
      }));
    }
    setCatalogMessage([
      duplicates.length ? `Уже есть в конфиге: ${[...new Set(duplicates)].join(", ")}.` : "",
      alreadyStaged.length ? `Уже добавлено в черновик: ${[...new Set(alreadyStaged)].join(", ")}.` : "",
      fresh.length ? `Добавлено наборов в черновик: ${fresh.length}.` : "",
    ].filter(Boolean).join(" ") || "Новых наборов нет.");
    setCatalogError(null);
    setCatalogContext(null);
  };
  const manualSetValid = engineTagValid(manualSet.name) && !ruleSetOptions.includes(manualSet.name) && (() => {
    try { const url = new URL(manualSet.url); return url.protocol === "https:" && !!url.hostname; }
    catch { return false; }
  })();
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
  const ingress = current.ingress_interfaces;
  const rules = current.rules;
  const usesOutbound = rules.some((r) => r.action === "route") || current.final === "route";
  const enableIssue = ingress.length === 0 ? "Выберите хотя бы один источник трафика." :
    ingress.some((name) => !sources.some((source) => source.name === name)) ? "Источник трафика недоступен." :
    rules.length === 0 ? "Добавьте хотя бы одно правило." :
    !valid || !rules.every((r) => ruleValid(r, outboundOptions, ruleSetOptions)) ||
      new Set(rules.map((r) => r.name)).size !== rules.length
      ? "Исправьте правила, ссылки на выходы и обязательные поля." :
    usesOutbound && !configuration.proxies.enabled && !enableProxies && pendingOutbounds.length === 0
      ? "Включите секцию прокси-выходов для выбранного выхода." : null;
  const setEnabled = (enabled: boolean) => {
    if (!enabled) { setPendingEnable(false); setPendingDisable(true); }
    else if (!enableIssue) setPendingEnable(true);
  };
  const cancel = () => { editor.cancel(); setPendingSets([]); setPendingOutbounds([]); setEnableProxies(false); setCatalogMessage(null); setCatalogError(null); };
  const save = async () => {
    if (user?.role === "operator" || !valid || (current.enabled && enableIssue)) return;
    clearPreview();
    await editor.save((tproxy) => ({ ...configuration, tproxy,
      rule_sets: [...configuration.rule_sets, ...pendingSets],
      proxies: enableProxies || pendingOutbounds.length > 0 ? { ...configuration.proxies, enabled: true, outbounds: [...configuration.proxies.outbounds, ...pendingOutbounds] } : configuration.proxies }));
  };
  const moveRule = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= current.rules.length) return;
    const reordered = [...current.rules];
    [reordered[index], reordered[target]] = [reordered[target], reordered[index]];
    patch({ rules: reordered.map((rule, order) => ({ ...rule, order })) });
  };
  const importLink = () => {
    const parsed = parseShareLinks(importText);
    if (parsed.length !== 1 || !parsed[0].outbound || parsed[0].error) {
      setImportError(new Error(parsed[0]?.error ?? "Укажите одну корректную ссылку."));
      return;
    }
    const outbound = parsed[0].outbound;
    if (outboundOptions.includes(outbound.tag) || outbound.tag === "direct") {
      setImportError(new Error("Выход с таким тегом уже существует."));
      return;
    }
    if (!editor.isEdit) editor.begin(current);
    setPendingOutbounds((items) => [...items, outbound]);
    setImportText("");
    setImportError(null);
    setImportOpen(false);
  };
  useEffect(() => {
    if (!editor.isEdit && !editor.saving) { setPendingSets([]); setPendingOutbounds([]); setEnableProxies(false); }
  }, [editor.isEdit, editor.saving]);
  return (
    <>
      <ServiceCatalog open={catalogContext !== null} onClose={() => setCatalogContext(null)}
        onSelect={selectCatalog} declaredTags={ruleSetOptions} />
      <Dialog open={importOpen} onClose={() => setImportOpen(false)} aria-labelledby="tproxy-import-title" maxWidth="sm" fullWidth>
        <DialogTitle id="tproxy-import-title">Добавить выход по ссылке</DialogTitle>
        <DialogContent>
          <Field label="Ссылка на прокси" type="password" autoComplete="off" value={importText} onChange={(value) => { setImportText(value); setImportError(null); }} />
          <ErrorNotice error={importError} />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setImportOpen(false)}>Отмена</Button>
          <Button disabled={!importText.trim() || user?.role === "operator" || !version} onClick={importLink}>Добавить в черновик</Button>
        </DialogActions>
      </Dialog>
      {catalogMessage && <InfoNote>{catalogMessage}</InfoNote>}
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
        <Typography variant="body2">Правил {current.rules.length} · Наборов {configuration.rule_sets.length + pendingSets.length} · Выходов {outboundOptions.length} · DNS-серверов {current.dns.servers.length}</Typography>
        <InlineStatus tone={runtime.isError || !runtime.data ? "unknown" : runtime.data.running ? "green" : "neutral"}
          text={`Движок: ${runtime.isError || !runtime.data ? "состояние недоступно" : runtime.data.running ? "работает" : "остановлен"} · версия ${runtime.isError ? "неизвестна" : runtime.data?.version ?? "неизвестна"} · Clash API ${runtime.isError || !runtime.data ? "неизвестен" : runtime.data.clash_api ? "доступен" : "недоступен"} · nft TProxy ${runtime.isError || !runtime.data ? "неизвестен" : runtime.data.nft_tproxy_tables ? "есть" : "нет"}`} />
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
      <ConfirmDialog open={pendingDisable} title="Выключить выборочную маршрутизацию?"
        body="После сохранения и общего применения перехват выбранного трафика прекратится."
        confirmLabel="Выключить в черновике" cancelLabel="Отмена"
        onCancel={() => setPendingDisable(false)} onConfirm={() => { patch({ enabled: false }); setPendingDisable(false); }} />
      <ConfirmDialog open={!!pendingDNSDelete} title="Удалить DNS-сервер?"
        body={`Ссылки на ${pendingDNSDelete?.tag}: ${pendingDNSDelete?.refs.join(", ") || "нет"}. Удаление оставит зависимые поля без ссылки.`}
        confirmLabel="Удалить" cancelLabel="Отмена" danger
        onCancel={() => setPendingDNSDelete(null)} onConfirm={() => {
          if (pendingDNSDelete) patch({ dns: { ...current.dns,
            servers: current.dns.servers.filter((_, i) => i !== pendingDNSDelete.index) } });
          setPendingDNSDelete(null);
        }} />
      <ValueTabs value={view} change={setView}
        tabs={[{ value: "configure", label: "Простой" }, { value: "expert", label: "Эксперт" }]} />
      {outboundOptions.length === 0 && <Card title="Прокси-выходы не настроены"><EmptyState>Нет прокси-выходов. Добавьте выход, чтобы направлять трафик через туннель. Правила «Напрямую» и «Блокировать» доступны уже сейчас.</EmptyState><Button variant="contained" disabled={!version || user?.role === "operator"} onClick={() => setImportOpen(true)}>Добавить по ссылке</Button><Button onClick={onOpenProxies}>Открыть прокси-выходы</Button></Card>}
      {outboundOptions.length > 0 && !configuration.proxies.enabled && pendingOutbounds.length === 0 && <Card title="Прокси-выходы выключены"><InfoNote>Правила с выходом начнут работать после включения секции и применения черновика.</InfoNote><Button disabled={!version || user?.role === "operator" || editor.saving} onClick={() => { if (!editor.isEdit) editor.begin(current); setEnableProxies(true); }}>Включить прокси-выходы в черновике</Button>{enableProxies && <Badge tone="amber">Включатся после сохранения и применения</Badge>}</Card>}
      {view === "expert" && <Card title="Правила · первое совпадение" action={editor.isEdit ? <Button onClick={() => { setView("configure"); setAddingRule(true); setRuleStep(0); setGuidedRule(emptyRule()); }}>+ Правило</Button> : undefined}>
        <DataTable heads={["#", "Действие", "Условия", "Выход", "Действия"]} rows={current.rules.map((rule, index) => [
          index + 1, actionLabel(rule.action), `${rule.name}: ${matchLabel(rule)}`, rule.outbound ?? "—",
          editor.isEdit ? <FormActions>
            <Button disabled={index === 0} onClick={() => moveRule(index, -1)}>Вверх</Button>
            <Button disabled={index === current.rules.length - 1} onClick={() => moveRule(index, 1)}>Вниз</Button>
            <Button onClick={() => setEditingRule(editingRule === index ? null : index)}>Редактировать</Button>
            <DeleteButton label={`Удалить правило ${rule.name || index + 1}`} onClick={() => {
              patch({ rules: current.rules.filter((_, i) => i !== index).map((item, order) => ({ ...item, order })) });
              setEditingRule(null);
            }} />
          </FormActions> : "—",
        ])} empty={<EmptyState>Пользовательских правил нет — выбранный трафик идёт к конечному действию.</EmptyState>} />
        {editor.isEdit && editingRule !== null && current.rules[editingRule] && <Card title={`Правило ${current.rules[editingRule].name || editingRule + 1}`}>
          <FormGrid>
            <Field label="Имя правила" value={current.rules[editingRule].name} valid={nameValid(current.rules[editingRule].name)} onChange={(name) => updateRule(editingRule, { name })} />
            <RuleMatchers rule={current.rules[editingRule]} ruleSets={ruleSetOptions} change={(value) => updateRule(editingRule, value)} />
            <Select label="Логическая группа" value={current.rules[editingRule].logical_mode ?? ""} placeholder={{ label: "Обычное правило" }} options={[{ value: "and", label: "И (and)" }, { value: "or", label: "ИЛИ (or)" }]} onChange={(mode) => updateRule(editingRule, mode ? {
              logical_mode: mode as "and" | "or", logical_rules: current.rules[editingRule].logical_rules?.length ? current.rules[editingRule].logical_rules : [
                { ...emptyRule(), name: "child_a" }, { ...emptyRule(), name: "child_b" },
              ], domain_suffix: [], domain_exact: [], domain_keyword: [], domain_regex: [], ip_cidr: [], source_ip_cidr: [], source_mac: [], inbound: [], ip_is_private: null, network: null, rule_sets: [], ports: [], protocol: "any",
            } : { logical_mode: null, logical_rules: [] })} />
            {(current.rules[editingRule].logical_rules ?? []).map((child, childIndex) => <div key={childIndex}>
              <Field label={`Имя подправила ${childIndex + 1}`} value={child.name} valid={nameValid(child.name)} onChange={(name) => updateRule(editingRule, { logical_rules: current.rules[editingRule].logical_rules?.map((item, i) => i === childIndex ? { ...item, name } : item) })} />
              <RuleMatchers rule={child} ruleSets={ruleSetOptions} prefix={`Подправило ${childIndex + 1}: `} change={(value) => updateRule(editingRule, { logical_rules: current.rules[editingRule].logical_rules?.map((item, i) => i === childIndex ? { ...item, ...value } : item) })} />
              <DeleteButton label={`Удалить подправило ${childIndex + 1}`} onClick={() => updateRule(editingRule, { logical_rules: current.rules[editingRule].logical_rules?.filter((_, i) => i !== childIndex) })} />
            </div>)}
            {current.rules[editingRule].logical_mode && <Button onClick={() => updateRule(editingRule, { logical_rules: [...(current.rules[editingRule].logical_rules ?? []), { ...emptyRule(), name: `child_${(current.rules[editingRule].logical_rules?.length ?? 0) + 1}` }] })}>Добавить подправило</Button>}
            <Select label="Действие" value={current.rules[editingRule].action} options={actionOptions} onChange={(value) => { const action = value as TProxyRule["action"]; updateRule(editingRule, { action, outbound: action === "route" ? current.rules[editingRule].outbound : null }); }} />
            {current.rules[editingRule].action === "route" && <Select label="Выход" value={current.rules[editingRule].outbound ?? ""} placeholder={{ label: "Выберите выход" }} options={outboundOptions.map((tag) => ({ value: tag, label: tag }))} onChange={(outbound) => updateRule(editingRule, { outbound })} />}
          </FormGrid>
          {matcherIssue(current.rules[editingRule], ruleSetOptions) && <ErrorNotice error={new Error(matcherErrorLabels[matcherIssue(current.rules[editingRule], ruleSetOptions)!])} />}
          <Button onClick={() => setEditingRule(null)}>Готово</Button>
        </Card>}
        <InfoNote>Если ни одно правило не подошло: {actionLabel(current.final)}{current.final_outbound ? ` · ${current.final_outbound}` : ""}.</InfoNote>
      </Card>}
      {view === "expert" && <Card title="Наборы правил" action={editor.isEdit && user?.role !== "operator" ? <Button onClick={() => setManualSetOpen(true)}>+ Набор</Button> : undefined}>
        <DataTable heads={["Тег", "Формат", "Источник", "Через", "Действия"]} rows={[...configuration.rule_sets, ...pendingSets].map((set, index) => [
          set.name, set.format, set.url, "Прямое подключение",
          index >= configuration.rule_sets.length && editor.isEdit ? <DeleteButton label={`Удалить набор ${set.name}`} onClick={() => setPendingSets((items) => items.filter((item) => item.name !== set.name))} /> : "—",
        ])} empty={<EmptyState>Наборы правил не объявлены.</EmptyState>} />
        {manualSetOpen && <Card title="Новый набор"><FormGrid>
          <Field label="Тег" value={manualSet.name} valid={engineTagValid(manualSet.name) && !ruleSetOptions.includes(manualSet.name)} onChange={(name) => setManualSet({ ...manualSet, name })} />
          <SelectField label="Формат" value={manualSet.format} options={["text-domain", "text-cidr", "json", "geosite", "geoip", "srs"]} onChange={(format) => setManualSet({ ...manualSet, format })} />
          <Field label="URL источника" value={manualSet.url} valid={manualSetValid || !manualSet.url} onChange={(url) => setManualSet({ ...manualSet, url })} />
        </FormGrid><FormActions><Button onClick={() => setManualSetOpen(false)}>Отмена</Button><Button disabled={!manualSetValid} onClick={() => { setPendingSets((items) => [...items, manualSet]); setManualSetOpen(false); setManualSet({ name: "", format: "text-domain", url: "", max_records: 100_000, max_bytes: 5_000_000 }); }}>Добавить в черновик</Button></FormActions></Card>}
        {editor.isEdit && <Button onClick={() => setCatalogContext("expert")}>Из каталога</Button>}
        {catalogError && <ErrorNotice error={new Error(catalogError)} />}
      </Card>}
      {view === "expert" && <Card title="Выходы" action={<Button onClick={() => setImportOpen(true)}>+ Выход</Button>}>
        <DataTable heads={["Тег", "Тип", "Сервер", "Действия"]} rows={[
          ...configuration.proxies.outbounds.map((outbound) => [outbound.tag, outbound.type, outbound.server, <Button onClick={onOpenProxies}>Открыть</Button>]),
          ...pendingOutbounds.map((outbound) => [outbound.tag, outbound.type, outbound.server, <DeleteButton label={`Удалить выход ${outbound.tag}`} onClick={() => setPendingOutbounds((items) => items.filter((item) => item.tag !== outbound.tag))} />]),
          ...configuration.proxies.groups.map((group) => [group.tag, "Группа", "—", <Button onClick={onOpenProxies}>Открыть</Button>]),
        ]} empty={<EmptyState>Прокси-выходов нет.</EmptyState>} />
        <Button onClick={onOpenProxies}>Открыть редактор выходов</Button>
      </Card>}
      {view === "expert" && <Card title="DNS-серверы и правила" action={editor.isEdit ? <Button onClick={() => { const index = current.dns.servers.length; patch({ dns: { ...current.dns, servers: [...current.dns.servers, { tag: "", type: "udp", server: "", server_port: null, tls_name: null, path: null, domain_resolver: null, detour: null }] } }); setDnsEditor({ kind: "server", index }); }}>+ Сервер</Button> : undefined}>
        <DataTable heads={["Тег", "Тип", "Сервер", "Через", "Действия"]} rows={current.dns.servers.map((row, index) => [row.tag, row.type, row.server, row.detour ?? "direct", editor.isEdit ? <FormActions><Button onClick={() => setDnsEditor({ kind: "server", index })}>Редактировать</Button><DeleteButton label={`Удалить DNS-сервер ${row.tag || index + 1}`} onClick={() => setPendingDNSDelete({ tag: row.tag, index, refs: [
          ...current.dns.rules.filter((rule) => rule.server === row.tag).map((rule) => `DNS-правило ${rule.name}`),
          ...current.dns.servers.filter((server) => server !== row && server.domain_resolver === row.tag).map((server) => `DNS-резолвер ${server.tag}`),
        ] })} /></FormActions> : "—"])} empty={<EmptyState>DNS-серверов нет.</EmptyState>} />
        <DataTable heads={["Правило", "Условия", "Сервер", "Действия"]} rows={current.dns.rules.map((row, index) => [row.name, [...row.domain_suffix, ...row.rule_sets].join(", "), row.server, editor.isEdit ? <FormActions><Button onClick={() => setDnsEditor({ kind: "rule", index })}>Редактировать</Button><DeleteButton label={`Удалить DNS-правило ${row.name || index + 1}`} onClick={() => patch({ dns: { ...current.dns, rules: current.dns.rules.filter((_, i) => i !== index) } })} /></FormActions> : "—"])} empty={<EmptyState>DNS-правил нет.</EmptyState>} />
        {editor.isEdit && <Button onClick={() => { const index = current.dns.rules.length; patch({ dns: { ...current.dns, rules: [...current.dns.rules, { name: "", domain_suffix: [], rule_sets: [], server: "" }] } }); setDnsEditor({ kind: "rule", index }); }}>+ DNS-правило</Button>}
          {current.dns.servers.map((row, index) => dnsEditor?.kind === "server" && dnsEditor.index === index && <div key={index} className="rule-row">
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
            </FormGrid>
          </div>)}
          {current.dns.rules.map((row, index) => dnsEditor?.kind === "rule" && dnsEditor.index === index && <div key={index} className="rule-row">
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
        <InfoNote>DNS final и strategy не поддерживаются текущей моделью конфигурации.</InfoNote>
      </Card>}
      {view === "expert" && <Card title="Конечное действие">
        {editor.isEdit ? <FormGrid><SelectField label="Для несовпавшего трафика" value={current.final} options={["direct", "block", "route"]} onChange={(final) => patch({ final, final_outbound: final === "route" ? current.final_outbound : null })} />
          {current.final === "route" && <SelectField label="Выход по умолчанию" value={current.final_outbound ?? ""} options={outboundOptions} onChange={(final_outbound) => patch({ final_outbound })} />}</FormGrid> : <Typography>{actionLabel(current.final)}{current.final_outbound ? ` · ${current.final_outbound}` : ""}</Typography>}
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
      {view === "configure" ? (
        <>
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
          <Card title="Правила · первое совпадение" action={editor.isEdit ? <Button onClick={() => { setAddingRule(true); setRuleStep(0); setGuidedRule(emptyRule()); }}>+ Правило</Button> : undefined}>
            <DataTable heads={["#", "Куда", "Условия", "Действия"]} rows={[
              ["S1", "Sniff", current.sniff ? "Определение домена включено" : "Определение домена выключено", "Системное"],
              ["S2", "DNS", "Порт 53", "Системное"],
              ["S3", "Напрямую", "Локальные IPv4-адреса", "Системное"],
              ["S4", "UDP", current.udp_timeout_seconds == null ? "Таймаут не задан" : `Таймаут ${current.udp_timeout_seconds} с`, "Системное"],
              ...current.rules.map((rule, index) => [index + 1, `${actionLabel(rule.action)}${rule.outbound ? ` · ${rule.outbound}` : ""}`, `${rule.name}: ${matchLabel(rule)}`,
                editor.isEdit ? <FormActions>
                  <Button disabled={index === 0} onClick={() => moveRule(index, -1)}>Вверх</Button>
                  <Button disabled={index === current.rules.length - 1} onClick={() => moveRule(index, 1)}>Вниз</Button>
                  <Button onClick={() => setEditingRule(editingRule === index ? null : index)}>Редактировать</Button>
                  <DeleteButton label={`Удалить правило ${rule.name || index + 1}`} onClick={() => { patch({ rules: current.rules.filter((_, i) => i !== index).map((item, order) => ({ ...item, order })) }); setEditingRule(null); }} />
                </FormActions> : "—",
              ]),
            ]} />
            {editor.isEdit && editingRule !== null && current.rules[editingRule] && <Card title={`Правило ${current.rules[editingRule].name || editingRule + 1}`}>
              <Field label="Имя правила" value={current.rules[editingRule].name} valid={nameValid(current.rules[editingRule].name)}
                onChange={(name) => updateRule(editingRule, { name })} />
              <RuleMatchers rule={current.rules[editingRule]} ruleSets={ruleSetOptions}
                change={(change) => updateRule(editingRule, change)} />
              <Select label="Действие" value={current.rules[editingRule].action} options={actionOptions}
                onChange={(value) => { const action = value as TProxyRule["action"]; updateRule(editingRule, { action, outbound: action === "route" ? current.rules[editingRule].outbound : null }); }} />
              {current.rules[editingRule].action === "route" && <Select label="Выход" value={current.rules[editingRule].outbound ?? ""}
                placeholder={{ label: "Выберите выход" }} options={outboundOptions.map((tag) => ({ value: tag, label: tag }))}
                onChange={(outbound) => updateRule(editingRule, { outbound })} />}
              {matcherIssue(current.rules[editingRule], ruleSetOptions) && <ErrorNotice error={new Error(matcherErrorLabels[matcherIssue(current.rules[editingRule], ruleSetOptions)!])} />}
              <Button onClick={() => setEditingRule(null)}>Готово</Button>
            </Card>}
            {editor.isEdit && addingRule && <Card title="Новое правило">
              <Typography>Шаг {ruleStep + 1} из 3: {ruleStep === 0 ? "условия" : ruleStep === 1 ? "назначение" : "проверка"}</Typography>
              {ruleStep === 0 && <FormGrid>
                <Field label="Имя правила" value={guidedRule.name} valid={nameValid(guidedRule.name)}
                  onChange={(name) => setGuidedRule((rule) => ({ ...rule, name }))} />
                <FormActions><Button onClick={() => setCatalogContext("rule")}>Из каталога</Button></FormActions>
                {catalogError && <ErrorNotice error={new Error(catalogError)} />}
                <RuleMatchers rule={guidedRule} ruleSets={ruleSetOptions}
                  change={(change) => setGuidedRule((rule) => ({ ...rule, ...change }))} />
              </FormGrid>}
              {ruleStep === 1 && <FormGrid>
                <Select label="Куда направить" value={guidedRule.action} options={actionOptions}
                  onChange={(value) => { const action = value as TProxyRule["action"]; setGuidedRule((rule) => ({ ...rule, action, outbound: action === "route" ? rule.outbound : null })); }} />
                {guidedRule.action === "route" && <Select label="Выход" value={guidedRule.outbound ?? ""}
                  placeholder={{ label: "Выберите выход" }} options={outboundOptions.map((tag) => ({ value: tag, label: tag }))}
                  onChange={(outbound) => setGuidedRule((rule) => ({ ...rule, outbound }))} />}
                {guidedRule.action === "route" && outboundOptions.length === 0 && <InfoNote>Сначала добавьте прокси-выход.</InfoNote>}
              </FormGrid>}
              {ruleStep === 2 && <InfoNote>{guidedRule.name}: {matchLabel(guidedRule)} → {actionLabel(guidedRule.action)}{guidedRule.outbound ? ` · ${guidedRule.outbound}` : ""}. Правило добавится в локальный черновик; затем сохраните страницу.</InfoNote>}
              <FormActions>
                <Button onClick={() => { setAddingRule(false); setRuleStep(0); }}>Отмена</Button>
                {ruleStep > 0 && <Button onClick={() => setRuleStep((step) => step - 1)}>Назад</Button>}
                {ruleStep < 2 ? <Button disabled={ruleStep === 0 && (!nameValid(guidedRule.name) || !!matcherIssue(guidedRule, ruleSetOptions))}
                  onClick={() => setRuleStep((step) => step + 1)}>Далее</Button> :
                  <Button disabled={!ruleValid(guidedRule, outboundOptions, ruleSetOptions) || current.rules.some((rule) => rule.name === guidedRule.name)}
                    onClick={() => { patch({ rules: [...current.rules, { ...guidedRule, order: current.rules.length }] }); setAddingRule(false); setGuidedRule(emptyRule()); setRuleStep(0); }}>Добавить</Button>}
              </FormActions>
            </Card>}
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
            cancel={cancel} save={() => void save()} />}
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
          <Card title="Конечное действие"><Typography>{actionLabel(current.final)}</Typography></Card>
          <Card title="Исключения"><Typography>{current.bypass.length ? current.bypass.map((row) => row.name).join(", ") : "Исключений нет"}</Typography></Card>
          <Card title="DNS-политика"><Typography>Серверы: {current.dns.servers.length} · правила: {current.dns.rules.length}</Typography></Card>
          <Button disabled={user?.role !== "admin" || version?.status !== "draft" || preview.isFetching}
            onClick={() => void preview.refetch()}>Предпросмотр сохранённого черновика</Button>
          {preview.data && preview.data.version_id === version?.id && <pre aria-label="Конфигурация sing-box">{JSON.stringify(preview.data.singbox, null, 2)}</pre>}
        </>
      ) : (
        <>
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
          {current.bypass.length === 0 && <EmptyState>Исключений нет.</EmptyState>}
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
                  hint="ЧЧ:ММ по времени сервера; не включает TProxy"
                  valid={timeValid(schedule.window_start)}
                  onChange={(window_start) => patch({ update_schedule: { ...schedule, window_start } })} />
                <Field label="Конец окна" value={schedule.window_end}
                  valid={timeValid(schedule.window_end) && schedule.window_start < schedule.window_end}
                  onChange={(window_end) => patch({ update_schedule: { ...schedule, window_end } })} />
              </>
            )}
          </FormGrid>
          <EditorFooter saving={editor.saving} valid={valid && (!current.enabled || !enableIssue)} cancel={cancel}
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
      {tab === "tproxy" && <TProxyEditor onOpenProxies={() => setTab("proxies")} />}
      {tab === "proxies" && <ProxiesEditor />}
      {tab === "rulesets" && <RuleSets />}
    </>
  );
}
