/**
 * Master wizard for the product routing model (`Configuration.routing_rules`).
 *
 * The product model is the one that actually routes traffic on the panel
 * (ADR-0019); the legacy tproxy configuration has no dedicated UI surface.
 * This speaks the ADR-0029 vocabulary: a subject (server / subscriber
 * device / interface), a destination and one exit.
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import { ChoiceCards } from "../components/ChoiceCards";
import { FlowChain } from "../components/FlowChain";
import { LoadingSkeleton } from "../components/LoadingSkeleton";
import { Badge } from "../components/Badge";
import type { IconName } from "../components/Icon";
import { Button, Dialog, DialogTitle, DialogContent, Typography } from "@mui/material";
import { WizardProgress } from "../components/WizardProgress";
import { PageSection } from "../components/PageSection";
import { FormGrid, FormWide, FormActions } from "../components/Form";
import { Field } from "../components/Field";
import { Select } from "../components/Select";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter, EditorFieldset } from "../components/EditorShell";
import { RoutingSurface, SummaryPanel } from "../components/RoutingSurface";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InfoNote } from "../components/InfoNote";
import { ErrorNotice } from "../components/ErrorNotice";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { Card } from "../components/Card";
import { ValueTabs } from "../components/Tabs";
import { useConfiguration, useApplyCommands } from "../state";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { nameValid, addressValid, domainValid } from "../components/validators";
import { api, ApiError } from "../api";
import type {
  Configuration, RoutingExit, RoutingSubject, RoutingRule,
  Interface, Subscriber, Tunnel,
} from "../types";

type WizardStep = 0 | 1 | 2 | 3;
type MasterMode = "wizard" | "advanced";

/** Backend guard codes of the routing model, in the operator's language. */
const routingErrorTexts: Record<string, string> = {
  "routing.destination_required":
    "у правила нет назначения — укажите домен или IPv4-сеть",
  "routing.duplicate_name":
    "два правила имеют одинаковое имя — переименуйте одно из них",
  "routing.domain_invalid":
    "имя домена указано неверно",
  "routing.ip_cidr_invalid":
    "IPv4-сеть указана неверно",
  "routing.outbound_reference":
    "прокси-выход, выбранный в правиле, больше не объявлен",
  "routing.exit_group_reference":
    "группа выходов, выбранная в правиле, больше не объявлена",
  "routing.exit_group_member_missing":
    "в группе выходов есть участник, которого больше нет в конфигурации",
  "routing.exit_interface_reference":
    "интерфейс выхода больше не объявлен в конфигурации",
  "routing.exit_field_required":
    "для выбранного вида выхода не указан адресат",
  "routing.exit_fields_unexpected":
    "у выбранного вида выхода указан лишний адресат",
  "routing.subject_fields_unexpected":
    "у источника трафика указан лишний адресат",
  "routing.subject_interface_reference":
    "интерфейс-источник больше не объявлен в конфигурации",
  "routing.subject_interface_no_address":
    "у интерфейса-источника нет IPv4-адреса — выбрать его как источник нельзя",
  "routing.tunnel_reference":
    "туннель, выбранный в правиле, больше не объявлен",
  "routing.tunnel_client_required":
    "выходом может быть только клиентский туннель — серверный туннель наружу не выводит",
  "routing.subscriber_reference":
    "абонент, выбранный в правиле, больше не объявлен",
  "routing.device_reference":
    "устройство абонента, выбранное в правиле, больше не объявлено",
  "routing.device_ambiguous":
    "устройство абонента выбрано неоднозначно — переименуйте пир",
  "routing.domain_rule_own_resolvers":
    "у устройства свой DNS — доменные правила к нему не применяются",
  "routing.device_address_required":
    "у устройства абонента нет адреса в туннеле",
};

/** A guard code arrives as an ApiError whose message IS the code. */
export function routingErrorText(error: unknown): unknown {
  if (!(error instanceof ApiError)) return error;
  const known = routingErrorTexts[error.code];
  if (known) return new Error(`${known} · ${error.code}`);
  // A rejected document carries the failing guard inside `details`; the
  // operator needs that guard in words, not a JSON dump.
  const codes = (error.details ?? [])
    .map((entry) => (entry && typeof entry === "object" && "message" in entry
      ? String((entry as { message: unknown }).message)
      : typeof entry === "string" ? entry : ""))
    .filter((code) => code in routingErrorTexts);
  if (codes.length === 0) return error;
  const text = codes.map((code) => `${routingErrorTexts[code]} · ${code}`).join("; ");
  return new Error(text);
}

interface DevicePeer {
  subscriber: string;
  peer: string;
  addresses: string[];
  ownDns: boolean;
}

interface SubjectInterface {
  name: string;
  label: string;
  zone: string | null;
  addresses: string[];
}

interface ExitChoices {
  interfaces: { value: string; label: string }[];
  outbounds: { value: string; label: string }[];
  groups: { value: string; label: string }[];
  clientTunnels: { value: string; label: string }[];
}

function devicePeers(cfg: Configuration): DevicePeer[] {
  const subscribers: Subscriber[] = cfg.subscribers ?? [];
  return subscribers.flatMap((subscriber) =>
    (cfg.tunnels ?? []).flatMap((tunnel: Tunnel) =>
      (tunnel.peers ?? [])
        .filter((peer) => peer.subscriber === subscriber.name)
        .map((peer) => ({
          subscriber: subscriber.name,
          peer: peer.name,
          addresses: peer.allowed_ips ?? [],
          ownDns: peer.dns_mode === "own",
        }))));
}

/** Only an interface with an IPv4 address can be a subject (ADR-0029). */
function subjectInterfaces(cfg: Configuration): SubjectInterface[] {
  return (cfg.interfaces ?? [])
    .filter((item: Interface) =>
      (item.addresses ?? []).some((address) => !address.includes(":")))
    .map((item: Interface) => ({
      name: item.name,
      label: item.description ? `${item.name} — ${item.description}` : item.name,
      zone: item.zone,
      addresses: item.addresses,
    }));
}

function exitChoices(cfg: Configuration): ExitChoices {
  return {
    interfaces: (cfg.interfaces ?? []).map((item: Interface) => ({
      value: item.name,
      label: item.description ? `${item.name} — ${item.description}` : item.name,
    })),
    outbounds: (cfg.proxies?.outbounds ?? []).map((outbound) => ({
      value: outbound.tag,
      label: outbound.tag,
    })),
    groups: (cfg.proxies?.groups ?? []).map((group) => ({
      value: group.tag,
      label: group.tag,
    })),
    clientTunnels: (cfg.tunnels ?? [])
      .filter((tunnel: Tunnel) => tunnel.role === "client")
      .map((tunnel: Tunnel) => ({ value: tunnel.name, label: tunnel.name })),
  };
}

/** Short labels: a native select clips a long value, so the explanation of the
 * chosen kind is shown separately under the field. */
const exitExplanation: Record<RoutingExit["kind"], string> = {
  direct: "Мимо туннеля, обычный маршрут.",
  interface: "Трафик уходит с выбранного интерфейса хоста.",
  outbound: "Трафик проходит через выбранный прокси-выход.",
  group: "Трафик распределяется по участникам выбранной группы выходов.",
  tunnel: "Трафик уходит в выбранный клиентский VPN-туннель.",
  block: "Запрос отклоняется: трафик не уходит никуда.",
};

const exitKindOptions = [
  { value: "direct", label: "Напрямую" },
  { value: "interface", label: "Через интерфейс" },
  { value: "outbound", label: "Через прокси-выход" },
  { value: "group", label: "Через группу выходов" },
  { value: "tunnel", label: "Через туннель" },
  { value: "block", label: "Заблокировать" },
];

const subjectKindOptions = [
  { value: "server", label: "Весь трафик сервера" },
  { value: "device", label: "Устройство абонента" },
  { value: "interface", label: "Весь трафик интерфейса" },
];

export function subjectLabel(subject: RoutingSubject): string {
  if (subject.kind === "device")
    return `устройство ${subject.subscriber} / ${subject.peer}`;
  if (subject.kind === "interface") return `интерфейс ${subject.interface}`;
  return "трафик сервера";
}

export function exitLabel(exit: RoutingExit): string {
  switch (exit.kind) {
    case "direct": return "напрямую";
    case "interface": return `через интерфейс ${exit.interface}`;
    case "outbound": return `через прокси-выход ${exit.tag}`;
    case "group": return `через группу ${exit.tag}`;
    case "tunnel": return `через туннель ${exit.name}`;
    case "block": return "заблокировать";
  }
}

export function destinationLabel(rule: RoutingRule): string {
  const parts: string[] = [];
  // A long list must not fill the cell: the table would grow unreadable and
  // push the other columns off the screen.
  const brief = (items: string[], limit = 3) => items.length <= limit
    ? items.join(", ")
    : `${items.slice(0, limit).join(", ")} и ещё ${items.length - limit}`;
  if (rule.domain_suffix.length) parts.push(`домены ${brief(rule.domain_suffix)}`);
  if (rule.domain_exact.length) parts.push(`точный домен ${brief(rule.domain_exact)}`);
  if (rule.ip_cidr.length) parts.push(`сеть ${brief(rule.ip_cidr)}`);
  return parts.join("; ") || "назначение не задано";
}

export function ruleLabel(rule: RoutingRule): string {
  return `${subjectLabel(rule.subject)} → ${destinationLabel(rule)} → ${exitLabel(rule.exit)}`;
}

const domainListValid = (list: readonly string[]) =>
  list.every((item) => item.trim() !== "" && domainValid(item));
const cidrListValid = (list: readonly string[]) =>
  list.every((item) => !item.includes(":") && addressValid(item));

/** Russian plural for a counted noun: 1 домен, 2 домена, 5 доменов. */
function plural(count: number, one: string, few: string, many: string): string {
  const mod100 = Math.abs(count) % 100;
  const mod10 = mod100 % 10;
  if (mod100 >= 11 && mod100 <= 14) return many;
  if (mod10 === 1) return one;
  if (mod10 >= 2 && mod10 <= 4) return few;
  return many;
}

/** The exit names a target; an exit without one is not a rule. */
export function exitComplete(exit: RoutingExit): boolean {
  switch (exit.kind) {
    case "interface": return !!exit.interface;
    case "outbound":
    case "group": return !!exit.tag;
    case "tunnel": return !!exit.name;
    default: return true;
  }
}

export function ruleComplete(rule: RoutingRule): boolean {
  return nameValid(rule.name) &&
    (rule.domain_suffix.length + rule.domain_exact.length + rule.ip_cidr.length > 0) &&
    domainListValid(rule.domain_suffix) && domainListValid(rule.domain_exact) &&
    cidrListValid(rule.ip_cidr) && exitComplete(rule.exit);
}

function emptyRule(): RoutingRule {
  return {
    name: "",
    subject: { kind: "server" },
    domain_suffix: [],
    domain_exact: [],
    ip_cidr: [],
    exit: { kind: "direct" },
  };
}

/**
 * A name for a rule that says what it does and is free among the rules.
 *
 * The operator does not choose a name; a name that repeats is a data problem,
 * not a style question. The base comes from the destination (the first domain
 * or the first network), and a numeric suffix makes it unique.
 */
export function suggestRuleName(rule: RoutingRule, taken: readonly string[]): string {
  const domain = rule.domain_suffix[0] ?? rule.domain_exact[0];
  const network = rule.ip_cidr[0];
  let base = domain
    ? domain.replace(/^www\./, "").replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")
    : network
      ? `net_${network.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")}`
      : "rule";
  base = base.slice(0, 24) || "rule";
  // The backend accepts a name that starts with a letter only.
  if (!/^[a-zA-Z]/.test(base)) base = `rule_${base}`;
  const free = (candidate: string) => !taken.includes(candidate);
  if (free(base)) return base;
  for (let index = 2; index < 100; index++) {
    const candidate = `${base.slice(0, 28)}_${index}`;
    if (free(candidate)) return candidate;
  }
  return `${base.slice(0, 26)}_${Date.now().toString(36).slice(-4)}`;
}

/* ------------------------------------------------------------------ */
/* The three groups of one rule — one form, used by the wizard and the  */
/* per-rule editor window, so the two never drift.                       */
/* ------------------------------------------------------------------ */

function SubjectFields({ rule, change, peers, interfaces }: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
  peers: DevicePeer[];
  interfaces: SubjectInterface[];
}) {
  const subject = rule.subject;
  const peerIndex = peers.findIndex((peer) => subject.kind === "device" &&
    peer.subscriber === subject.subscriber && peer.peer === subject.peer);
  const summary = subject.kind === "device"
    ? `Трафик устройства «${subject.peer}» абонента «${subject.subscriber}»`
    : subject.kind === "interface" ? `Трафик интерфейса ${subject.interface}` : "Трафик всего сервера";
  const zones: Record<string, string> = { lan: "локальная сеть", wan: "интернет", dmz: "демилитаризованная зона" };
  return <FormGrid>
    <FormWide>
      <ChoiceCards label="Источник трафика" value={[subject.kind]}
        options={subjectKindOptions.map((item) => ({ ...item,
          description: item.value === "server" ? "Исходящий трафик самого сервера"
            : item.value === "device" ? peers.length ? "Одно устройство конкретного абонента" : "Абонентских устройств нет — добавьте абонента и его устройство на странице «Абоненты»."
              : interfaces.length ? "Трафик с IPv4-адресов выбранного интерфейса" : "Нет интерфейсов с IPv4-адресом — настройте их на странице «Подключения и адреса».",
          disabled: item.value === "device" && !peers.length || item.value === "interface" && !interfaces.length,
        }))}
        onChange={(value) => {
          if (value === "device") change({ subject: { kind: "device", subscriber: peers[0].subscriber, peer: peers[0].peer } });
          else if (value === "interface") change({ subject: { kind: "interface", interface: interfaces[0].name } });
          else change({ subject: { kind: "server" } });
        }} />
    </FormWide>
    <FormWide>
      <Typography variant="body2" className="routing-subject-summary">{summary}</Typography>
      <ChoiceCards label="Устройства и интерфейсы" layout="rows"
        value={[subject.kind === "device" ? `device:${peerIndex}` : subject.kind === "interface" ? `interface:${subject.interface}` : ""]}
        options={[
          ...peers.map((peer, index) => ({ value: `device:${index}`, label: peer.peer, icon: "device" as const,
            description: `${peer.addresses.join(", ") || "адресов нет"} · абонент «${peer.subscriber}» · пир ${peer.peer}` })),
          ...interfaces.map((item) => ({ value: `interface:${item.name}`, label: item.label, icon: "network" as const,
            description: `${item.addresses.join(", ")} · зона: ${item.zone ? zones[item.zone] ?? item.zone : "не назначена"}` })),
        ]}
        onChange={(value) => {
          if (value.startsWith("device:")) {
            const peer = peers[Number(value.slice(7))];
            change({ subject: { kind: "device", subscriber: peer.subscriber, peer: peer.peer } });
          } else change({ subject: { kind: "interface", interface: value.slice(10) } });
        }} />
    </FormWide>
    {peerIndex >= 0 && peers[peerIndex].ownDns && <FormWide><InfoNote severity="warning">
      У этого устройства собственный DNS — доменные правила к нему не применяются.
    </InfoNote></FormWide>}
  </FormGrid>;
}

const categoryIcons: Record<string, IconName> = {
  media: "media", video: "media", social: "social", messaging: "social", developer: "developer",
  dev: "developer", cloud: "cloud", gaming: "gaming", games: "gaming", ai: "ai", block: "block",
};

function DestinationFields({ rule, change }: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
}) {
  const catalog = useQuery({ queryKey: queryKeys.presetCatalog(), queryFn: api.presetCatalog });
  const services = (catalog.data?.services ?? []).filter((item) => item.dns_domains.length > 0 && item.covers.length === 0)
    .sort((a, b) => {
      const featured = ["youtube", "rutube"];
      const rank = (id: string) => featured.includes(id) ? featured.indexOf(id) : featured.length;
      return rank(a.id) - rank(b.id);
    });
  // A chosen service contributes its own domains; the operator adds nothing by
  // hand, so the list of domains is NOT shown under the tiles. Several services
  // can be chosen at once: their domains are alternatives (ADR-0029), so the
  // union of their domains is the rule's destination.
  const chosen = services.filter((item) => item.dns_domains.every((domain) => rule.domain_suffix.includes(domain)));
  const chosenIds = chosen.map((item) => item.id);
  const serviceDomains = new Set(chosen.flatMap((item) => item.dns_domains));
  // Domains the operator typed by hand: everything in the list that no chosen
  // service contributes.
  const manualDomains = rule.domain_suffix.filter((domain) => !serviceDomains.has(domain));
  const empty = rule.domain_suffix.length + rule.domain_exact.length + rule.ip_cidr.length === 0;
  const applyChosen = (ids: string[]) => {
    const next = new Set(services.filter((item) => ids.includes(item.id)).flatMap((item) => item.dns_domains));
    // Keep the hand-written domains, replace the service-contributed ones.
    const keep = rule.domain_suffix.filter((domain) => !chosen.some((item) => item.dns_domains.includes(domain)));
    change({ domain_suffix: [...new Set([...keep, ...next])] });
  };
  return <FormGrid>
    {catalog.isPending ? <FormWide><LoadingSkeleton height={110} /></FormWide>
      : !catalog.error && services.length > 0 && <FormWide>
        <ChoiceCards label="Готовые сервисы" layout="presets" multiple value={chosenIds}
          options={services.map((item) => ({ value: item.id, label: item.name,
            icon: item.icon_slug ? categoryIcons[item.category] ?? "network" : undefined,
            description: `${item.dns_domains.length} ${plural(item.dns_domains.length, "домен", "домена", "доменов")}`,
          }))}
          onChange={(_id, selected) => applyChosen(selected)} />
        {chosen.length > 0 && <Typography variant="body2" color="text.secondary" className="routing-subtitle">
          Выбрано сервисов: {chosen.length}. Их домены — альтернативы назначения; свой список — ниже.
        </Typography>}
      </FormWide>}
    <Field label="Свои домены (по одному в строке)" multiline value={manualDomains.join("\n")}
      valid={domainListValid(manualDomains)} hint="Совпадение по суффиксу: «rutube.ru» покроет и www.rutube.ru"
      onChange={(text) => {
        const typed = text.split("\n").map((item) => item.trim()).filter(Boolean);
        change({ domain_suffix: [...new Set([...typed, ...rule.domain_suffix.filter((domain) => serviceDomains.has(domain))])] });
      }} />
    <Field label="Свои адреса и сети (CIDR)" multiline value={rule.ip_cidr.join("\n")}
      valid={cidrListValid(rule.ip_cidr)} hint="Только IPv4. Оставьте пустым, если адреса не нужны"
      onChange={(text) => change({ ip_cidr: text.split("\n").map((item) => item.trim()).filter(Boolean) })} />
    <Field label="Точные домены (по строкам)" multiline value={rule.domain_exact.join("\n")}
      valid={domainListValid(rule.domain_exact)} hint="Только этот домен, без поддоменов"
      onChange={(text) => change({ domain_exact: text.split("\n").map((item) => item.trim()).filter(Boolean) })} />
    <FormWide><Typography variant="body2" color="text.secondary">
      Списки — альтернативы: достаточно совпадения с любым доменом или сетью из любого списка.
    </Typography></FormWide>
    {empty && <FormWide><InfoNote severity="warning">
      Правило без назначения не сработает — укажите домен или IPv4-сеть.
    </InfoNote></FormWide>}
  </FormGrid>;
}

function ExitFields({
  rule, change, choices,
}: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
  choices: ExitChoices;
}) {
  const exit = rule.exit;
  const reasons: Partial<Record<RoutingExit["kind"], string>> = {
    interface: choices.interfaces.length ? undefined : "Добавьте интерфейс на странице «Подключения и адреса».",
    outbound: choices.outbounds.length ? undefined : "Добавьте выход на вкладке «Прокси-выходы».",
    group: choices.groups.length ? undefined : "Добавьте группу на вкладке «Прокси-выходы».",
    tunnel: choices.clientTunnels.length ? undefined : "Добавьте клиентский туннель на странице «Туннели».",
  };
  const setKind = (value: string) => {
    if (value === "interface") change({ exit: { kind: "interface", interface: choices.interfaces[0]?.value ?? "" } });
    else if (value === "outbound") change({ exit: { kind: "outbound", tag: choices.outbounds[0]?.value ?? "" } });
    else if (value === "group") change({ exit: { kind: "group", tag: choices.groups[0]?.value ?? "" } });
    else if (value === "tunnel") change({ exit: { kind: "tunnel", name: choices.clientTunnels[0]?.value ?? "" } });
    else if (value === "block") change({ exit: { kind: "block" } });
    else change({ exit: { kind: "direct" } });
  };
  return (
      <FormGrid>
        <FormWide><ChoiceCards label="Выход" value={[exit.kind]}
          options={exitKindOptions.map((option) => ({ ...option,
            description: reasons[option.value as RoutingExit["kind"]] ?? exitExplanation[option.value as RoutingExit["kind"]],
            disabled: !!reasons[option.value as RoutingExit["kind"]],
          }))} onChange={setKind} /></FormWide>
        {exit.kind === "interface" && (
          <Select
            label="Интерфейс выхода"
            value={exit.interface}
            placeholder={{ label: "Выберите интерфейс" }}
            options={choices.interfaces}
            onChange={(value) => change({ exit: { kind: "interface", interface: value } })}
          />
        )}
        {exit.kind === "outbound" && (
          <Select
            label="Прокси-выход"
            value={exit.tag}
            placeholder={{ label: "Выберите прокси-выход" }}
            options={choices.outbounds}
            onChange={(value) => change({ exit: { kind: "outbound", tag: value } })}
          />
        )}
        {exit.kind === "group" && (
          <Select
            label="Группа выходов"
            value={exit.tag}
            placeholder={{ label: "Выберите группу" }}
            options={choices.groups}
            onChange={(value) => change({ exit: { kind: "group", tag: value } })}
          />
        )}
        {exit.kind === "tunnel" && (
          <Select
            label="Клиентский туннель"
            value={exit.name}
            placeholder={{ label: "Выберите туннель" }}
            options={choices.clientTunnels}
            onChange={(value) => change({ exit: { kind: "tunnel", name: value } })}
          />
        )}
        {exit.kind === "block" && (
          <FormWide>
            <InfoNote severity="warning">
              Трафик под это правило будет отклонён. Если выход недоступен, трафик тоже отклоняется —
              прямого выхода в интернет не будет.
            </InfoNote>
          </FormWide>
        )}
      </FormGrid>
  );
}

/* ------------------------------------------------------------------ */

/** Match the generator's final-outbound selection; never promise direct by default. */
function finalExit(configuration: Configuration): string {
  if (configuration.tproxy.final === "block") return "заблокировать";
  if (configuration.tproxy.final === "route") return configuration.tproxy.final_outbound
    ? `через выход ${configuration.tproxy.final_outbound}` : "напрямую";
  if (configuration.proxies.enabled) {
    const groups = [...configuration.proxies.groups].sort((a, b) => a.tag < b.tag ? -1 : a.tag > b.tag ? 1 : 0);
    const group = groups.find((item) => item.type === "selector") ?? groups.find((item) => item.type === "urltest");
    if (group) return `через группу ${group.tag}`;
  }
  return "напрямую";
}

const stepTitles = ["Шаг 1. Кому маршрутизируем", "Шаг 2. Что маршрутизировать", "Шаг 3. Куда направить", "Шаг 4. Проверка"];
const stepSubtitles = ["Выберите, чей трафик попадёт под правило", "Домены, сервисы или IPv4-сети — достаточно одного совпадения", "Выберите путь для выбранного трафика", "Проверьте цепочку и порядок перед сохранением"];

export default function RoutingMasterPage() {
  const { configuration, error: apiError, user, versions, busy } = useConfiguration();
  const apply = useApplyCommands();
  const navigate = useNavigate();
  const editor = useDraftEditor<RoutingRule[]>();
  const [mode, setMode] = useState<MasterMode>("wizard");
  const [step, setStep] = useState<WizardStep>(0);
  const [rule, setRule] = useState<RoutingRule>(() => emptyRule());
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<{ index: number; name: string } | null>(null);
  const [saveIntent, setSaveIntent] = useState<"draft" | "apply" | null>(null);
  const saveLock = useRef(false);
  // The operator may type a name of their own; then the automatic one stops
  // following the destination.
  const [nameEdited, setNameEdited] = useState(false);
  const peers = devicePeers(configuration);
  const interfaces = subjectInterfaces(configuration);
  const choices = exitChoices(configuration);
  const rules = editor.value ?? configuration.routing_rules ?? [];
  const readOnly = user?.role === "operator";
  const disabled = readOnly || editor.saving || busy || saveIntent !== null;
  const change = (update: Partial<RoutingRule>) => setRule((current) => {
    const next = { ...current, ...update };
    const destinationChanged = update.domain_suffix !== undefined ||
      update.domain_exact !== undefined || update.ip_cidr !== undefined;
    if (destinationChanged && !nameEdited) {
      // The name follows the destination until the operator writes their own.
      const taken = rules.filter((item) => item.name !== current.name).map((item) => item.name);
      next.name = suggestRuleName(next, taken);
    }
    return next;
  });
  const subject = rule.subject;
  const validSubject = subject.kind === "server" ||
    (subject.kind === "device" && peers.some((peer) => peer.subscriber === subject.subscriber && peer.peer === subject.peer)) ||
    (subject.kind === "interface" && interfaces.some((item) => item.name === subject.interface));
  const validDestination = rule.domain_suffix.length + rule.domain_exact.length + rule.ip_cidr.length > 0 &&
    domainListValid(rule.domain_suffix) && domainListValid(rule.domain_exact) && cidrListValid(rule.ip_cidr);
  const stepValid = [validSubject, validDestination, exitComplete(rule.exit), nameValid(rule.name)][step];
  const unique = !rules.some((item) => item.name === rule.name);
  const pageValid = rules.every((item, index) => ruleComplete(item) && rules.findIndex((other) => other.name === item.name) === index);
  const wizardValid = validSubject && ruleComplete(rule) && unique && pageValid;
  const resetWizard = () => {
    setStep(0);
    setRule(emptyRule());
    setEditingIndex(null);
    setNameEdited(false);
  };

  // useDraftEditor owns persistence and errors. Only a successful save clears
  // its working copy. Observe the saved version on the next render so a newly
  // CREATED draft (not the previous confirmed ID) reaches the global command.
  useEffect(() => {
    if (!saveIntent || editor.saving) return;
    if (editor.error) { setSaveIntent(null); saveLock.current = false; return; }
    if (editor.isEdit) return;
    const saved = versions.find((item) => item.status === "draft");
    if (!saved) return;
    const intent = saveIntent;
    setSaveIntent(null);
    saveLock.current = false;
    setStep(0);
    setRule(emptyRule());
    setNameEdited(false);
    if (intent === "apply") {
      // Reuse the same command, preferences, guards and shared observation as
      // the topbar. The Apply screen alone presents confirmation/countdown.
      void apply.command("apply", saved.id);
      navigate("/apply");
    }
  }, [saveIntent, editor.saving, editor.error, editor.isEdit, versions, apply, navigate]);

  const saveWizard = (intent: "draft" | "apply") => {
    if (disabled || !wizardValid || saveLock.current) return;
    saveLock.current = true;
    setSaveIntent(intent);
    void editor.save((items) => ({ ...configuration, routing_rules: [...items, rule] }));
  };
  const move = (index: number, direction: -1 | 1) => {
    if (readOnly || editor.saving) return;
    const target = index + direction;
    if (target < 0 || target >= rules.length) return;
    const reordered = [...rules];
    [reordered[index], reordered[target]] = [reordered[target], reordered[index]];
    editor.setValue(reordered);
  };
  const save = () => {
    if (readOnly || !pageValid) return;
    void editor.save((items) => ({ ...configuration, routing_rules: items }));
  };
  const final = finalExit(configuration);
  const fallback = "Трафик устройства абонента без совпадения блокируется; остальной трафик переходит к оставшимся правилам и конечному выходу.";
  // System rows are listed first as a reference, NOT as higher-priority
  // matches. Their condition explicitly says they execute after user rules.
  const systemRows = [
    [<Badge key="device" tone="amber">системное правило</Badge>, "Защита устройств абонентов", "После пользовательских правил, если ни одно не совпало", "заблокировать", ""],
    [<Badge key="final" tone="purple">системное правило</Badge>, "Конечный выход", "После всех правил, только для остального трафика", final, ""],
  ];
  const previewRules = wizardValid && step === 3 ? [...rules, rule] : rules;

  return <RoutingSurface>
    <ErrorNotice error={routingErrorText(apiError)} />
    <ErrorNotice error={routingErrorText(editor.error)} />
    <ValueTabs value={mode} change={(value) => { if (!disabled) setMode(value); }}
      tabs={[{ value: "wizard", label: "Мастер" }, { value: "advanced", label: "Расширенные настройки" }]} />
    {mode === "wizard" && <>
      <WizardProgress steps={["Кому", "Что", "Куда", "Проверка"]} current={step} />
      <Card title={stepTitles[step]}>
        <Typography variant="body2" color="text.secondary" className="routing-subtitle">{stepSubtitles[step]}</Typography>
        <EditorFieldset disabled={disabled}>
          {step === 0 && <SubjectFields rule={rule} change={change} peers={peers} interfaces={interfaces} />}
          {step === 1 && <DestinationFields rule={rule} change={change} />}
          {step === 2 && <ExitFields rule={rule} change={change} choices={choices} />}
          {step === 3 && <FormGrid>
            <FormWide><SummaryPanel>
              <FlowChain label="Путь выбранного трафика" items={[
                { text: subjectLabel(rule.subject) }, { text: "перехват sing-box" },
                { text: destinationLabel(rule), tone: "purple" }, { text: exitLabel(rule.exit), tone: rule.exit.kind === "block" ? "red" : "green" },
              ]} />
              <FlowChain label="Трафик без совпадения" items={[
                { text: "Устройства без совпадения" }, { text: "заблокировать", tone: "red" },
              ]} />
              <FlowChain label="Остальной трафик" items={[
                { text: "Остальной трафик" }, { text: "оставшиеся правила" }, { text: final },
              ]} />
              <Typography variant="body2" color="text.secondary">
                Правило {rules.length + 1} из {rules.length + 1}. Совпадение по первому правилу: «{rule.name}» проверяется после ранее добавленных правил.
              </Typography>
            </SummaryPanel></FormWide>
            <Field label="Имя правила" value={rule.name} valid={nameValid(rule.name) && unique}
              hint={unique
                ? nameEdited
                  ? "Латиница, цифры и _, до 31 символа"
                  : "Создано по назначению; можно изменить"
                : "Имя уже занято другим правилом"}
              onChange={(name) => { setNameEdited(true); change({ name }); }} />
            <FormWide><InfoNote severity="warning">
              Сохранение записывает только черновик. Изменения не действуют до отдельного применения.
              «Сохранить и применить» запускает общее применение всего черновика и открывает страницу «Применение».
            </InfoNote></FormWide>
          </FormGrid>}
        </EditorFieldset>
        <FormActions>
          {step > 0 && <Button disabled={disabled} onClick={() => setStep((step - 1) as WizardStep)}>Назад</Button>}
          {step < 3 && <Button variant="contained" disabled={!stepValid || disabled} onClick={() => {
            if (step === 2 && !editor.isEdit) editor.begin(rules);
            setStep((step + 1) as WizardStep);
          }}>Далее</Button>}
        </FormActions>
        {step === 3 && <EditorFooter saving={editor.saving || saveIntent !== null}
          valid={wizardValid && !readOnly && !busy} saveLabel="Сохранить черновик"
          cancel={() => { editor.cancel(); resetWizard(); }} save={() => saveWizard("draft")}
          action={<Button variant="outlined" disabled={!wizardValid || disabled || apply.active || !apply.timeoutValid}
            onClick={() => saveWizard("apply")}>Сохранить и применить</Button>} />}
      </Card>
      <Card title="Что будет дальше">
        <div className="routing-table-wide"><DataTable heads={["Порядок", "Кто / правило", "Условие", "Куда"]}
          rows={[...systemRows.map((row) => row.slice(0, 4)), ...previewRules.map((item, index) => [String(index + 1), `${item.name} · ${subjectLabel(item.subject)}`,
            destinationLabel(item), exitLabel(item.exit)])]} /></div>
        {!previewRules.length && <EmptyState>Правил маршрутизации пока нет. Создайте первое правило в мастере.</EmptyState>}
        <Typography variant="body2" color="text.secondary" className="routing-subtitle">{fallback}</Typography>
      </Card>
    </>}
    {mode === "advanced" && <>
      <Card title="Движок и источники">
        <Typography variant="body2" color="text.secondary" className="routing-subtitle">Что перехватывается и как обрабатывается</Typography>
        <SummaryPanel><FlowChain label="Порядок обработки" items={[
          { text: "источник трафика" }, { text: "sing-box" }, { text: "первое совпавшее правило" }, { text: "выход правила", tone: "green" },
        ]} />
          <Typography variant="body2">Источники из правил: {Array.from(new Set(rules.map((item) => subjectLabel(item.subject)))).join(", ") || "не заданы"}.</Typography>
          <Typography variant="body2" color="text.secondary">{fallback}</Typography>
          <FlowChain label="Конечный выход" items={[{ text: "Если ни одно правило не подошло (кроме устройств)" }, { text: final }]} />
        </SummaryPanel>
      </Card>
      <Card title="Правила маршрутизации">
        <Typography variant="body2" color="text.secondary" className="routing-subtitle">
          Первое совпадение выигрывает. Системные строки показаны для справки и не редактируются.
        </Typography>
        <div className="routing-table-wide"><DataTable heads={["# / правило", "Кто", "Что", "Куда", "Действия"]} rows={[
          ...systemRows,
          ...rules.map((item, index) => [ `${index + 1}. ${item.name}`, subjectLabel(item.subject), destinationLabel(item), exitLabel(item.exit),
            <FormActions key={item.name}>
              <Button disabled={disabled} onClick={() => { setRule({ ...item }); setEditingIndex(index); }}>Изменить</Button>
              <Button disabled={disabled || index === 0} onClick={() => move(index, -1)}>Вверх</Button>
              <Button disabled={disabled || index === rules.length - 1} onClick={() => move(index, 1)}>Вниз</Button>
              <DeleteButton label={`Удалить правило ${item.name}`} disabled={disabled} onClick={() => setDeleting({ index, name: item.name })} />
            </FormActions>,
          ]),
        ]} /></div>
        {!rules.length && <EmptyState>Правил маршрутизации пока нет. Создайте первое правило в мастере.</EmptyState>}
        {!readOnly && <FormActions><Button disabled={disabled} onClick={() => { resetWizard(); setMode("wizard"); }}>+ Правило</Button></FormActions>}
        {editor.isEdit && <EditorFooter saving={editor.saving} valid={pageValid && !readOnly} cancel={editor.cancel} save={save} />}
      </Card>
    </>}
    <Dialog open={editingIndex !== null} onClose={() => { setEditingIndex(null); resetWizard(); }} fullWidth maxWidth="md" aria-labelledby="routing-rule-title">
      <DialogTitle id="routing-rule-title">Правило: {editingIndex !== null ? rules[editingIndex]?.name ?? "" : ""}</DialogTitle>
      <DialogContent>{editingIndex !== null && rules[editingIndex] && <EditorFieldset disabled={disabled}>
        <PageSection title="Кому"><SubjectFields rule={rule} change={change} peers={peers} interfaces={interfaces} /></PageSection>
        <PageSection title="Что"><DestinationFields rule={rule} change={change} /></PageSection>
        <PageSection title="Куда"><ExitFields rule={rule} change={change} choices={choices} /></PageSection>
      </EditorFieldset>}</DialogContent>
      <EditorFooter saving={editor.saving} valid={!readOnly && ruleComplete(rule) && validSubject &&
        !rules.some((item, index) => index !== editingIndex && item.name === rule.name)}
        cancel={() => { setEditingIndex(null); resetWizard(); }} save={() => {
          if (readOnly || editingIndex === null || !ruleComplete(rule)) return;
          const next = [...rules]; next[editingIndex] = rule;
          editor.setValue(next); setEditingIndex(null); resetWizard();
        }} />
    </Dialog>
    <ConfirmDialog open={!!deleting} title={`Удалить правило ${deleting?.name ?? ""}?`}
      body="Правило будет удалено из рабочей копии. Изменения действуют только после сохранения и применения."
      confirmLabel="Удалить" cancelLabel="Отмена" danger
      onConfirm={() => { if (deleting && !readOnly) { editor.setValue(rules.filter((_, index) => index !== deleting.index)); setDeleting(null); } }}
      onCancel={() => setDeleting(null)} />
  </RoutingSurface>;
}
