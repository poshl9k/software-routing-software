/**
 * Master wizard for the product routing model (`Configuration.routing_rules`).
 *
 * The product model is the one that actually routes traffic on the panel
 * (ADR-0019); the legacy `tproxy` rules live in their own tab. This surface
 * therefore speaks the ADR-0029 vocabulary: a subject (server / subscriber
 * device / interface), a destination and one exit.
 */
import { useState } from "react";
import { Button, Dialog, DialogTitle, DialogContent, Typography } from "@mui/material";
import { WizardProgress } from "../components/WizardProgress";
import { PageSection } from "../components/PageSection";
import { FormGrid, FormWide, FormActions } from "../components/Form";
import { Field } from "../components/Field";
import { Select } from "../components/Select";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { InfoNote } from "../components/InfoNote";
import { ErrorNotice } from "../components/ErrorNotice";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { Card } from "../components/Card";
import { ValueTabs } from "../components/Tabs";
import { useConfiguration } from "../state";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { nameValid, addressValid, domainValid } from "../components/validators";
import { ApiError } from "../api";
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
  direct: "Трафик идёт напрямую, мимо проксирования.",
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
  if (rule.domain_suffix.length) parts.push(`домены ${rule.domain_suffix.join(", ")}`);
  if (rule.domain_exact.length) parts.push(`точный домен ${rule.domain_exact.join(", ")}`);
  if (rule.ip_cidr.length) parts.push(`сеть ${rule.ip_cidr.join(", ")}`);
  return parts.join("; ") || "назначение не задано";
}

export function ruleLabel(rule: RoutingRule): string {
  return `${subjectLabel(rule.subject)} → ${destinationLabel(rule)} → ${exitLabel(rule.exit)}`;
}

const domainListValid = (list: readonly string[]) =>
  list.every((item) => item.trim() !== "" && domainValid(item));
const cidrListValid = (list: readonly string[]) =>
  list.every((item) => !item.includes(":") && addressValid(item));

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

function emptyRule(index: number): RoutingRule {
  return {
    name: `rule_${index + 1}`,
    subject: { kind: "server" },
    domain_suffix: [],
    domain_exact: [],
    ip_cidr: [],
    exit: { kind: "direct" },
  };
}

/* ------------------------------------------------------------------ */
/* The three groups of one rule — one form, used by the wizard and the  */
/* per-rule editor window, so the two never drift.                       */
/* ------------------------------------------------------------------ */

function SubjectFields({
  rule, change, peers, interfaces,
}: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
  peers: DevicePeer[];
  interfaces: SubjectInterface[];
}) {
  const subject = rule.subject;
  return (
    <PageSection title="Кому" subtitle="Чей трафик попадёт под правило">
      <FormGrid>
        <Select
          label="Источник трафика"
          value={subject.kind}
          options={subjectKindOptions.map((option) => ({
            ...option,
            disabled: option.value === "device" && peers.length === 0 ||
              option.value === "interface" && interfaces.length === 0,
          }))}
          onChange={(value) => {
            if (value === "device")
              change({ subject: { kind: "device", subscriber: peers[0]?.subscriber ?? "", peer: peers[0]?.peer ?? "" } });
            else if (value === "interface")
              change({ subject: { kind: "interface", interface: interfaces[0]?.name ?? "" } });
            else change({ subject: { kind: "server" } });
          }}
        />
        {subject.kind === "device" && (
          <>
            <Select
              label="Абонент"
              value={subject.subscriber}
              placeholder={{ label: "Выберите абонента" }}
              options={peers.reduce<{ value: string; label: string }[]>((acc, peer) =>
                acc.some((item) => item.value === peer.subscriber)
                  ? acc
                  : [...acc, { value: peer.subscriber, label: peer.subscriber }], [])}
              onChange={(value) => change({
                subject: {
                  kind: "device",
                  subscriber: value,
                  peer: peers.find((peer) => peer.subscriber === value)?.peer ?? "",
                },
              })}
            />
            <Select
              label="Устройство"
              value={subject.peer}
              placeholder={{ label: "Выберите устройство" }}
              options={peers
                .filter((peer) => peer.subscriber === subject.subscriber)
                .map((peer) => ({ value: peer.peer, label: peer.peer }))}
              onChange={(value) => change({
                subject: { kind: "device", subscriber: subject.subscriber, peer: value },
              })}
            />
            <FormWide>
              <Field
                label="Адреса устройства"
                value={peers.find((peer) => peer.peer === subject.peer)?.addresses.join(", ") ?? ""}
                readOnly
              />
            </FormWide>
            {peers.find((peer) => peer.peer === subject.peer)?.ownDns && (
              <FormWide>
                <InfoNote severity="warning">
                  У этого устройства собственный DNS — доменные правила к нему не применяются.
                </InfoNote>
              </FormWide>
            )}
          </>
        )}
        {subject.kind === "interface" && (
          <Select
            label="Интерфейс-источник"
            value={subject.interface}
            placeholder={{ label: "Выберите интерфейс" }}
            options={interfaces.map((item) => ({ value: item.name, label: item.label }))}
            helperText={interfaces.find((item) => item.name === subject.interface)?.zone
              ? `Зона: ${interfaces.find((item) => item.name === subject.interface)!.zone}`
              : undefined}
            onChange={(value) => change({ subject: { kind: "interface", interface: value } })}
          />
        )}
        {peers.length === 0 && (
          <FormWide>
            <InfoNote severity="warning">
              Абонентских устройств нет — добавьте абонента и его устройство на странице «Абоненты».
            </InfoNote>
          </FormWide>
        )}
        {interfaces.length === 0 && (
          <FormWide>
            <InfoNote severity="warning">
              Нет интерфейсов с IPv4-адресом — их можно настроить на странице «Подключения и адреса».
            </InfoNote>
          </FormWide>
        )}
      </FormGrid>
    </PageSection>
  );
}

function DestinationFields({
  rule, change,
}: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
}) {
  const empty = rule.domain_suffix.length + rule.domain_exact.length + rule.ip_cidr.length === 0;
  return (
    <PageSection title="Что" subtitle="Куда этот трафик обращается">
      <FormGrid>
        <Field
          label="Домены (по строкам)"
          multiline
          value={rule.domain_suffix.join("\n")}
          valid={domainListValid(rule.domain_suffix)}
          hint="Совпадение по суффиксу: rutube.ru покроет и www.rutube.ru"
          onChange={(text) => change({ domain_suffix: text.split("\n").map((item) => item.trim()).filter(Boolean) })}
        />
        <Field
          label="Точные домены (по строкам)"
          multiline
          value={rule.domain_exact.join("\n")}
          valid={domainListValid(rule.domain_exact)}
          hint="Только этот домен, без поддоменов"
          onChange={(text) => change({ domain_exact: text.split("\n").map((item) => item.trim()).filter(Boolean) })}
        />
        <Field
          label="IPv4-сети (по строкам)"
          multiline
          value={rule.ip_cidr.join("\n")}
          valid={cidrListValid(rule.ip_cidr)}
          hint="Один CIDR на строку, например 203.0.113.0/24"
          onChange={(text) => change({ ip_cidr: text.split("\n").map((item) => item.trim()).filter(Boolean) })}
        />
        {empty && (
          <FormWide>
            <InfoNote severity="warning">
              Правило без назначения не сработает — укажите домен или IPv4-сеть.
            </InfoNote>
          </FormWide>
        )}
      </FormGrid>
    </PageSection>
  );
}

function ExitFields({
  rule, change, choices,
}: {
  rule: RoutingRule;
  change: (update: Partial<RoutingRule>) => void;
  choices: ExitChoices;
}) {
  const exit = rule.exit;
  const unavailable: string[] = [];
  if (choices.interfaces.length === 0) unavailable.push("через интерфейс");
  if (choices.outbounds.length === 0) unavailable.push("через прокси-выход");
  if (choices.groups.length === 0) unavailable.push("через группу выходов");
  if (choices.clientTunnels.length === 0) unavailable.push("через туннель");
  const setKind = (value: string) => {
    if (value === "interface") change({ exit: { kind: "interface", interface: choices.interfaces[0]?.value ?? "" } });
    else if (value === "outbound") change({ exit: { kind: "outbound", tag: choices.outbounds[0]?.value ?? "" } });
    else if (value === "group") change({ exit: { kind: "group", tag: choices.groups[0]?.value ?? "" } });
    else if (value === "tunnel") change({ exit: { kind: "tunnel", name: choices.clientTunnels[0]?.value ?? "" } });
    else if (value === "block") change({ exit: { kind: "block" } });
    else change({ exit: { kind: "direct" } });
  };
  return (
    <PageSection title="Куда" subtitle="Каким путём уходит выбранный трафик">
      <FormGrid>
        <Select
          label="Выход"
          value={exit.kind}
          options={exitKindOptions.map((option) => ({
            ...option,
            disabled: option.value === "interface" && choices.interfaces.length === 0 ||
              option.value === "outbound" && choices.outbounds.length === 0 ||
              option.value === "group" && choices.groups.length === 0 ||
              option.value === "tunnel" && choices.clientTunnels.length === 0,
          }))}
          onChange={setKind}
        />
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
        <FormWide>
          <Typography variant="body2" color="text.secondary">
            {exitExplanation[exit.kind]}
          </Typography>
        </FormWide>
        {exit.kind === "block" && (
          <FormWide>
            <InfoNote severity="warning">
              Трафик под это правило будет отклонён. Если выход недоступен, трафик тоже отклоняется —
              прямого выхода в интернет не будет.
            </InfoNote>
          </FormWide>
        )}
        {unavailable.length > 0 && (
          <FormWide>
            <InfoNote severity="warning">
              Недоступные виды выхода: {unavailable.join(", ")}. Добавьте их на вкладке
              «Прокси-выходы» или на странице «Туннели».
            </InfoNote>
          </FormWide>
        )}
      </FormGrid>
    </PageSection>
  );
}

/* ------------------------------------------------------------------ */

export default function RoutingMasterPage() {
  const { configuration, error: apiError, user } = useConfiguration();
  const editor = useDraftEditor<RoutingRule[]>();
  const [mode, setMode] = useState<MasterMode>("wizard");
  const [step, setStep] = useState<WizardStep>(0);
  const [rule, setRule] = useState<RoutingRule>(() => emptyRule(0));
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<{ index: number; name: string } | null>(null);
  const [added, setAdded] = useState<string | null>(null);

  const peers = devicePeers(configuration);
  const interfaces = subjectInterfaces(configuration);
  const choices = exitChoices(configuration);
  const rules = editor.value ?? configuration.routing_rules ?? [];
  const readOnly = user?.role === "operator";

  const change = (update: Partial<RoutingRule>) =>
    setRule((current) => ({ ...current, ...update }));

  const stepValid = [
    true,
    rule.domain_suffix.length + rule.domain_exact.length + rule.ip_cidr.length > 0 &&
      domainListValid(rule.domain_suffix) && domainListValid(rule.domain_exact) &&
      cidrListValid(rule.ip_cidr),
    exitComplete(rule.exit),
    nameValid(rule.name),
  ][step];

  const resetWizard = () => {
    setStep(0);
    setRule(emptyRule(rules.length));
    setEditingIndex(null);
  };

  const addRule = () => {
    if (!ruleComplete(rule)) return;
    if (rules.some((item) => item.name === rule.name)) return;
    editor.setValue([...rules, rule]);
    setAdded(rule.name);
    resetWizard();
  };

  const move = (index: number, direction: -1 | 1) => {
    const target = index + direction;
    if (target < 0 || target >= rules.length) return;
    const reordered = [...rules];
    [reordered[index], reordered[target]] = [reordered[target], reordered[index]];
    editor.setValue(reordered);
  };

  const removeRule = (index: number) => {
    const next = rules.filter((_, position) => position !== index);
    editor.setValue(next);
    setDeleting(null);
  };

  const duplicateNames = new Set(
    rules.map((item) => item.name).filter((name, index, all) => all.indexOf(name) !== index),
  );
  const pageValid = rules.every((item) => ruleComplete(item) && !duplicateNames.has(item.name));

  const save = () => {
    if (readOnly || !pageValid) return;
    void editor.save((items) => ({ ...configuration, routing_rules: items }));
  };

  const modes: { value: MasterMode; label: string }[] = [
    { value: "wizard", label: "Мастер" },
    { value: "advanced", label: "Расширенные настройки" },
  ];

  return (
    <>
      <ErrorNotice error={routingErrorText(apiError)} />
      <ErrorNotice error={routingErrorText(editor.error)} />
      <ValueTabs
        value={mode}
        change={(value) => { setMode(value); setAdded(null); }}
        tabs={modes}
      />

      {mode === "wizard" && (
        <Card title="Мастер маршрутизации">
          <WizardProgress steps={["Кому", "Что", "Куда", "Проверка"]} current={step} />
          {step === 0 && (
            <SubjectFields rule={rule} change={change} peers={peers} interfaces={interfaces} />
          )}
          {step === 1 && <DestinationFields rule={rule} change={change} />}
          {step === 2 && <ExitFields rule={rule} change={change} choices={choices} />}
          {step === 3 && (
            <PageSection title="Проверка" subtitle="Как это правило будет звучать">
              <FormGrid>
                <Field
                  label="Имя правила"
                  value={rule.name}
                  valid={nameValid(rule.name)}
                  hint="Латиница, цифры и _, до 31 символа"
                  onChange={(name) => change({ name })}
                />
                <FormWide>
                  <InfoNote>
                    {ruleLabel(rule)}
                    {rules.some((item) => item.name === rule.name) &&
                      " · имя уже занято другим правилом"}
                  </InfoNote>
                </FormWide>
              </FormGrid>
            </PageSection>
          )}
          <FormActions>
            {step > 0 && (
              <Button onClick={() => setStep((current) => (current - 1) as WizardStep)}>Назад</Button>
            )}
            {step < 3 ? (
              <Button
                variant="contained"
                disabled={!stepValid || readOnly}
                onClick={() => setStep((current) => (current + 1) as WizardStep)}
              >
                Далее
              </Button>
            ) : (
              <Button
                variant="contained"
                disabled={!ruleComplete(rule) || readOnly ||
                  rules.some((item) => item.name === rule.name)}
                onClick={addRule}
              >
                Добавить правило
              </Button>
            )}
          </FormActions>
          {added && (
            <InfoNote>Правило «{added}» добавлено в черновик. Сохраните страницу, чтобы правило не пропало.</InfoNote>
          )}
          <InfoNote>
            Устройство абонента, трафик которого не попал ни в одно правило, блокируется —
            прямого выхода в интернет по умолчанию нет.
          </InfoNote>
        </Card>
      )}

      {mode === "advanced" && (
        <PageSection
          title="Правила маршрутизации"
          subtitle="Порядок в списке — порядок применения: первое совпадение выигрывает"
          action={!readOnly ? (
            <Button onClick={() => { resetWizard(); setMode("wizard"); }}>+ Правило</Button>
          ) : undefined}
        >
          <DataTable
            heads={["#", "Кто", "Что", "Куда", "Действия"]}
            rows={rules.map((item, index) => [
              String(index + 1),
              subjectLabel(item.subject),
              destinationLabel(item),
              exitLabel(item.exit),
              <FormActions key={index}>
                <Button
                  onClick={() => {
                    setRule({ ...item });
                    setEditingIndex(index);
                  }}
                >
                  Изменить
                </Button>
                <Button disabled={index === 0} onClick={() => move(index, -1)}>Вверх</Button>
                <Button disabled={index === rules.length - 1} onClick={() => move(index, 1)}>Вниз</Button>
                <DeleteButton
                  label={`Удалить правило ${item.name}`}
                  onClick={() => setDeleting({ index, name: item.name })}
                />
              </FormActions>,
            ])}
            empty={
              <EmptyState>
                Правил маршрутизации пока нет. Создайте первое правило в мастере.
              </EmptyState>
            }
          />
        </PageSection>
      )}

      <Dialog
        open={editingIndex !== null}
        onClose={() => setEditingIndex(null)}
        fullWidth
        maxWidth="md"
        aria-labelledby="routing-rule-title"
      >
        <DialogTitle id="routing-rule-title">
          Правило: {editingIndex !== null ? rules[editingIndex]?.name ?? "" : ""}
        </DialogTitle>
        <DialogContent>
          {editingIndex !== null && rules[editingIndex] && (
            <>
              <SubjectFields
                rule={rule}
                change={change}
                peers={peers}
                interfaces={interfaces}
              />
              <DestinationFields rule={rule} change={change} />
              <ExitFields rule={rule} change={change} choices={choices} />
            </>
          )}
        </DialogContent>
        <EditorFooter
          saving={editor.saving}
          valid={ruleComplete(rule) &&
            !rules.some((item, index) => index !== editingIndex && item.name === rule.name)}
          cancel={() => { setEditingIndex(null); resetWizard(); }}
          save={() => {
            if (editingIndex === null || !ruleComplete(rule)) return;
            const next = [...rules];
            next[editingIndex] = rule;
            editor.setValue(next);
            setEditingIndex(null);
            resetWizard();
          }}
        />
      </Dialog>

      <ConfirmDialog
        open={!!deleting}
        title={`Удалить правило ${deleting?.name ?? ""}?`}
        body="Правило перестанет участвовать в маршрутизации. Отменить удаление нельзя."
        confirmLabel="Удалить"
        cancelLabel="Отмена"
        danger
        onConfirm={() => { if (deleting) removeRule(deleting.index); }}
        onCancel={() => setDeleting(null)}
      />

      {editor.isEdit && (
        <EditorFooter saving={editor.saving} valid={pageValid} cancel={editor.cancel} save={save} />
      )}
    </>
  );
}
