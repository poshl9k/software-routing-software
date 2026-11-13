/**
 * One segment's policy, edited as a list: what goes where, in the order the
 * engine evaluates it, with "everything else" always last.
 *
 * The panel stores one flat `routing_rules` list; this editor only owns the
 * slice that belongs to one subject. Reordering stays inside the segment, so a
 * segment can never silently jump ahead of another one's rules.
 */
import { useState } from "react";
import { Button, Dialog, DialogContent, DialogTitle } from "@mui/material";
import type { Configuration, RoutingExit, RoutingRule, RoutingSubject } from "../types";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { ErrorNotice } from "../components/ErrorNotice";
import { InfoNote } from "../components/InfoNote";
import { PageSection } from "../components/PageSection";
import { Select } from "../components/Select";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { useConfiguration } from "../state";
import type { SegmentGroup } from "./RoutingMaster";
import { destinationLabel, exitLabel } from "./RoutingMaster";

/** The catch-all rule: no destination matcher, IPv4 default only. */
const CATCH_ALL = "0.0.0.0/0";

const isCatchAll = (rule: RoutingRule) =>
  rule.ip_cidr.length === 1 && rule.ip_cidr[0] === CATCH_ALL &&
  rule.domain_suffix.length === 0 && rule.domain_exact.length === 0 &&
  rule.rule_sets.length === 0;

const hasDestination = (rule: RoutingRule) =>
  rule.ip_cidr.length + rule.domain_suffix.length +
  rule.domain_exact.length + rule.rule_sets.length > 0;

export function SegmentEditor({ configuration, group, disabled, onClose }: {
  configuration: Configuration;
  group: SegmentGroup | null;
  disabled: boolean;
  onClose: () => void;
}) {
  const { saveDraft, setNotice } = useConfiguration();
  const editor = useDraftEditor<RoutingRule[]>();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const rules = editor.value ?? [];
  const segmentName = group?.subject.kind === "interface"
    ? group.subject.interface ?? "segment"
    : group?.subject.kind === "device"
      ? group.subject.peer ?? "device"
      : "server";
  const clientTunnels = (configuration.tunnels ?? [])
    .filter((tunnel) => tunnel.role === "client")
    .map((tunnel) => ({ value: tunnel.name, label: tunnel.name }));
  const ruInterfaces = (configuration.interfaces ?? [])
    .filter((item) => item.zone && item.zone !== "wan")
    .map((item) => ({ value: item.name, label: item.name }));

  const begin = () => editor.begin(group?.rules.map((entry) => entry.rule) ?? []);
  const open = group !== null;
  const setRules = (next: RoutingRule[]) => editor.setValue(next);

  const move = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= rules.length) return;
    const next = [...rules];
    [next[index], next[target]] = [next[target], next[index]];
    setRules(next);
  };

  const withSubject = (name: string, exit: RoutingExit, ip: string[]): RoutingRule => ({
    name, subject: group?.subject as RoutingSubject, ip_cidr: ip,
    domain_suffix: [], domain_exact: [], rule_sets: [], exit,
  });

  const applyPreset = (preset: "ru-then-tunnel" | "blocked-only" | "all-tunnel" | "all-ru") => {
    const tunnel = clientTunnels[0]?.value;
    const ru = ruInterfaces[0]?.value;
    const ruExit: RoutingExit = ru
      ? { kind: "interface", interface: ru }
      : { kind: "direct" };
    const tunnelExit: RoutingExit = tunnel
      ? { kind: "tunnel", name: tunnel }
      : { kind: "direct" };
    const rest = withSubject(`${segmentName}_rest`, preset === "all-ru" ? ruExit
      : preset === "blocked-only" ? (tunnelExit) : tunnelExit, [CATCH_ALL]);
    const ruSet = [...new Set([
      ...(configuration.rule_sets ?? []).map((source) => source.name),
      ...rules.flatMap((rule) => rule.rule_sets),
    ])].find((name) => /ru/i.test(name));
    if (preset === "all-tunnel" || preset === "all-ru") {
      setRules([rest]);
      return;
    }
    if (!ruSet) {
      setError(new Error("Нет объявленного источника РФ-списка: добавьте его на вкладке «Источники списков»."));
      return;
    }
    const ruRule: RoutingRule = {
      ...withSubject(`${segmentName}_ru`, preset === "ru-then-tunnel" ? ruExit : { kind: "direct" }, []),
      rule_sets: [ruSet],
    };
    setRules([ruRule, rest]);
  };

  const restRule = rules.length > 0 && isCatchAll(rules[rules.length - 1]) ? rules[rules.length - 1] : null;
  const problems: string[] = [];
  rules.forEach((rule) => {
    if (!hasDestination(rule)) problems.push(`Правило «${rule.name}» без назначения.`);
    const exit = rule.exit;
    if (exit.kind === "tunnel" && !clientTunnels.some((item) => item.value === exit.name)) {
      problems.push(`Правило «${rule.name}»: туннель ${exit.name} не клиентский или не объявлен.`);
    }
  });
  if (!restRule) problems.push("Последним должно идти правило «Всё остальное» (0.0.0.0/0).");
  const valid = !!group && problems.length === 0;

  const save = async () => {
    if (!group || !valid) return;
    const others = configuration.routing_rules
      .map((rule, index) => ({ rule, index }))
      .filter(({ index }) => !group.rules.some((entry) => entry.index === index))
      .map(({ rule }) => rule);
    // Keep the segment where its first rule used to be, so moving rules inside
    // one segment never reorders the others.
    const anchor = group.rules.length ? group.rules[0].index : configuration.routing_rules.length;
    const merged = [...others.slice(0, anchor), ...rules, ...others.slice(anchor)];
    setSaving(true);
    setError(null);
    try {
      const saved = await saveDraft({ ...configuration, routing_rules: merged });
      setNotice(`Сегмент сохранён в черновике v${saved.id}`);
      editor.cancel();
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={saving ? undefined : () => { editor.cancel(); onClose(); }} fullWidth maxWidth="md">
      <DialogTitle>Сегмент: {group?.title ?? ""}</DialogTitle>
      <DialogContent>
        <ErrorNotice error={error ?? editor.error} />
        {group && !editor.isEdit && (
          <PageSection title="Правила сегмента">
            <InfoNote>
              Порядок внутри сегмента задаёт приоритет: первое совпавшее правило выигрывает.
              «Всё остальное» должно стоять последним.
            </InfoNote>
            <Button disabled={disabled} onClick={begin}>Изменить политику сегмента</Button>
          </PageSection>
        )}
        {editor.isEdit && (
          <>
            <PageSection title="Правила сегмента">
              <DataTable heads={["№", "Что", "Куда", "Действия"]}
                rows={rules.map((rule, index) => [
                  String(index + 1),
                  destinationLabel(rule),
                  exitLabel(rule.exit),
                  <div className="row-actions" key={`${rule.name}-${index}`}>
                    <Button disabled={index === 0} aria-label={`Выше ${index + 1}`} onClick={() => move(index, -1)}>↑</Button>
                    <Button disabled={index === rules.length - 1} aria-label={`Ниже ${index + 1}`} onClick={() => move(index, 1)}>↓</Button>
                    <DeleteButton label={`Удалить правило ${index + 1}`}
                      onClick={() => setRules(rules.filter((_, i) => i !== index))} />
                  </div>,
                ])}
                empty={<InfoNote>В сегменте нет правил — начните с пресета ниже.</InfoNote>} />
            </PageSection>
            <PageSection title="Всё остальное">
              {restRule ? <>
                <Select label="Выход для остального трафика" value={restRule.exit.kind === "tunnel"
                  ? `tunnel:${restRule.exit.name}` : restRule.exit.kind === "interface"
                    ? restRule.exit.interface ?? "" : restRule.exit.kind}
                  options={[
                    { value: "direct", label: "Напрямую (по маршруту)" },
                    ...clientTunnels.map((item) => ({ value: `tunnel:${item.value}`, label: `Туннель ${item.value}` })),
                    ...ruInterfaces.map((item) => ({ value: item.value, label: `Интерфейс ${item.label}` })),
                  ]}
                  onChange={(value) => {
                    const exit: RoutingExit = value.startsWith("tunnel:")
                      ? { kind: "tunnel", name: value.slice(7) }
                      : value === "direct" ? { kind: "direct" } : { kind: "interface", interface: value };
                    setRules(rules.map((rule, index) => index === rules.length - 1 ? { ...rule, exit } : rule));
                  }} />
                <InfoNote>«Всё остальное» всегда последнее: правило с 0.0.0.0/0 без доменных условий.</InfoNote>
              </> : <InfoNote severity="warning">
                Нет правила «Всё остальное» — трафик без совпадения останется без политики сегмента.
                Добавьте его, чтобы сегмент был описан полностью.
              </InfoNote>}
            </PageSection>
            <PageSection title="Пресеты">
              <div className="row-actions">
                <Button onClick={() => applyPreset("ru-then-tunnel")}>РФ напрямую, остальное в туннель</Button>
                <Button onClick={() => applyPreset("blocked-only")}>Только РФ-список в РФ-выход, остальное в туннель</Button>
                <Button onClick={() => applyPreset("all-tunnel")}>Весь сегмент в туннель</Button>
                <Button onClick={() => applyPreset("all-ru")}>Весь сегмент напрямую</Button>
              </div>
              <InfoNote>
                Пресет заменяет правила этого сегмента и использует первые объявленные выходы:
                туннель — {clientTunnels[0]?.label ?? "не объявлен"}, РФ-интерфейс — {ruInterfaces[0]?.label ?? "напрямую"}.
                Проверьте результат перед сохранением.
              </InfoNote>
            </PageSection>
            {problems.length > 0 && (
              <InfoNote severity="warning">{problems.join(" ")}</InfoNote>
            )}
            <EditorFooter saving={saving} valid={valid}
              cancel={() => { editor.cancel(); onClose(); }}
              save={() => void save()} />
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
