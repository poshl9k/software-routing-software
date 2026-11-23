/** Editor for the DNS policy used by the TProxy contour. */
import { useEffect, useState } from "react";
import { Button, Dialog, DialogContent, DialogTitle } from "@mui/material";
import type { TProxyDNS, TProxyDNSRule, TProxyDNSServer } from "../types";
import { useConfiguration } from "../state";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { Field } from "../components/Field";
import { FormGrid, FormWide } from "../components/Form";
import { Select } from "../components/Select";
import { InfoNote } from "../components/InfoNote";
import { ErrorNotice } from "../components/ErrorNotice";
import { PageSection } from "../components/PageSection";
import {
  domainValid,
  engineTagValid,
  ipValid,
  lines,
  portValid,
} from "../components/validators";

const transportOptions = [
  { value: "udp", label: "UDP" },
  { value: "tls", label: "DoT" },
  { value: "https", label: "DoH" },
] as const;

const loopback53 = (server: TProxyDNSServer): boolean => {
  const host = server.server.trim().replace(/^\[|\]$/g, "");
  return (host === "::1" || /^127\./.test(host)) && (server.server_port ?? 53) === 53;
};

const emptyServer = (): TProxyDNSServer => ({
  tag: "",
  type: "udp",
  server: "",
  server_port: 53,
  tls_name: null,
  path: null,
  domain_resolver: null,
  detour: null,
});

const emptyRule = (): TProxyDNSRule => ({
  name: "",
  server: "",
  domain_suffix: [],
  rule_sets: [],
});

export function DnsPolicyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { configuration, version } = useConfiguration();
  const editor = useDraftEditor<TProxyDNS>();
  const [serverIndex, setServerIndex] = useState<number | null>(null);
  const [ruleIndex, setRuleIndex] = useState<number | null>(null);

  useEffect(() => {
    if (open) editor.begin(configuration.tproxy.dns);
    // The dialog is opened from the segment warning, which owns the current
    // configuration; re-entering edit mode on close would discard local edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const policy = editor.value ?? configuration.tproxy.dns;
  const servers = policy.servers;
  const rules = policy.rules;
  const server = serverIndex === null ? null : servers[serverIndex] ?? null;
  const rule = ruleIndex === null ? null : rules[ruleIndex] ?? null;
  const tags = servers.map((item) => item.tag);
  const tagOptions = tags.filter(Boolean).map((tag) => ({ value: tag, label: tag }));

  const updateServers = (next: TProxyDNSServer[]) => editor.setValue({ ...policy, servers: next });
  const updateRules = (next: TProxyDNSRule[]) => editor.setValue({ ...policy, rules: next });
  const updateServer = (v: Partial<TProxyDNSServer>) => {
    if (serverIndex === null) return;
    updateServers(servers.map((item, index) => index === serverIndex ? { ...item, ...v } : item));
  };
  const updateRule = (v: Partial<TProxyDNSRule>) => {
    if (ruleIndex === null) return;
    updateRules(rules.map((item, index) => index === ruleIndex ? { ...item, ...v } : item));
  };

  const valid = servers.length > 0
    && servers.every((item) => engineTagValid(item.tag)
      && (ipValid(item.server) || domainValid(item.server))
      && !loopback53(item)
      && item.server_port !== null && portValid(item.server_port)
      && (item.type !== "tls" || !!item.tls_name)
      && (!item.domain_resolver || engineTagValid(item.domain_resolver)))
    && new Set(tags).size === tags.length
    && rules.every((item) => engineTagValid(item.name)
      && tags.includes(item.server)
      && (item.domain_suffix.length > 0 || item.rule_sets.length > 0)
      && item.domain_suffix.every(domainValid)
      && item.rule_sets.every(engineTagValid))
    && new Set(rules.map((item) => item.name)).size === rules.length
    && (!servers.some((item) => !ipValid(item.server)) || servers.some((item) => ipValid(item.server)));

  const save = () => editor.save((value) => ({
    ...configuration,
    tproxy: { ...configuration.tproxy, dns: value },
  }));

  return <>
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>DNS-политика перехвата</DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error} />
        <InfoNote>Без хотя бы одного сервера контур перехвата не применяется: генератор отклоняет конфигурацию.</InfoNote>
        <PageSection title="Серверы">
          <DataTable heads={["Тег", "Тип", "Сервер", "Действия"]} rows={servers.map((item, index) => [
            item.tag || "Новый сервер",
            item.type.toUpperCase(),
            item.server || "Не указан",
            <Button onClick={() => setServerIndex(index)}>Изменить</Button>,
          ])} />
          <Button onClick={() => { updateServers([...servers, emptyServer()]); setServerIndex(servers.length); }}>
            Добавить DNS-сервер
          </Button>
        </PageSection>
        <PageSection title="Правила">
          <InfoNote>Правило выбирает сервер для доменов. Пустой список правил допустим: все запросы идут на первый сервер.</InfoNote>
          <DataTable heads={["Имя", "Сервер", "Домены", "Действия"]} rows={rules.map((item, index) => [
            item.name || "Новое правило",
            item.server || "Не выбран",
            String(item.domain_suffix.length + item.rule_sets.length),
            <Button onClick={() => setRuleIndex(index)}>Изменить</Button>,
          ])} />
          <Button disabled={!tags.length} onClick={() => { updateRules([...rules, emptyRule()]); setRuleIndex(rules.length); }}>
            Добавить DNS-правило
          </Button>
        </PageSection>
        <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={() => { editor.cancel(); setServerIndex(null); setRuleIndex(null); onClose(); }}
          save={() => void save()} />
      </DialogContent>
    </Dialog>

    <Dialog open={server !== null} onClose={() => setServerIndex(null)} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>DNS-сервер: {server?.tag || "Новый сервер"}</span>
        {server && <DeleteButton label={`Удалить DNS-сервер ${serverIndex! + 1}`} onClick={() => {
          updateServers(servers.filter((_, index) => index !== serverIndex));
          setServerIndex(null);
        }} />}
      </DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error} />
        {server && <FormGrid>
          <Field label="Тег сервера" value={server.tag} valid={engineTagValid(server.tag) && tags.filter((tag) => tag === server.tag).length === 1}
            hint="Латиница, цифры, дефис и _, до 31 символа" onChange={(tag) => updateServer({ tag })} />
          <Select label="Транспорт" value={server.type} options={transportOptions}
            onChange={(type) => updateServer({ type: type as TProxyDNSServer["type"] })} />
          <Field label="Адрес сервера" value={server.server}
            valid={(ipValid(server.server) || domainValid(server.server)) && !loopback53(server)}
            hint={loopback53(server)
              ? "127.0.0.1:53 недоступен: в контуре перехвата там нет слушателя. Укажите адрес доступного DNS, например 192.168.10.9"
              : "IP или домен; при домене нужен хотя бы один сервер с IP"}
            onChange={(value) => updateServer({ server: value })} />
          <Field label="Порт" type="number" value={String(server.server_port ?? "")}
            valid={server.server_port !== null && portValid(server.server_port)}
            onChange={(value) => updateServer({ server_port: value ? Number(value) : null })} />
          {server.type === "tls" && <Field label="Имя TLS" value={server.tls_name ?? ""} valid={!!server.tls_name}
            onChange={(tls_name) => updateServer({ tls_name: tls_name || null })} />}
          {server.type === "https" && <Field label="Путь DoH" value={server.path ?? ""}
            onChange={(path) => updateServer({ path: path || null })} />}
          <Field label="Разрешитель доменов" value={server.domain_resolver ?? ""}
            valid={!server.domain_resolver || engineTagValid(server.domain_resolver)}
            hint="Необязательный тег другого DNS-сервера" onChange={(value) => updateServer({ domain_resolver: value || null })} />
          <FormWide><Field label="Выход (detour)" value={server.detour ?? ""}
            hint="Необязательный тег выхода из правил маршрутизации" onChange={(detour) => updateServer({ detour: detour || null })} /></FormWide>
        </FormGrid>}
        <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={() => setServerIndex(null)} save={() => void save()} />
      </DialogContent>
    </Dialog>

    <Dialog open={rule !== null} onClose={() => setRuleIndex(null)} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>DNS-правило: {rule?.name || "Новое правило"}</span>
        {rule && <DeleteButton label={`Удалить DNS-правило ${ruleIndex! + 1}`} onClick={() => {
          updateRules(rules.filter((_, index) => index !== ruleIndex));
          setRuleIndex(null);
        }} />}
      </DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error} />
        {rule && <FormGrid>
          <Field label="Имя правила" value={rule.name} valid={engineTagValid(rule.name)
            && rules.filter((item) => item.name === rule.name).length === 1}
            hint="Латиница, цифры, дефис и _, до 31 символа" onChange={(name) => updateRule({ name })} />
          <Select label="Сервер" value={rule.server} options={tagOptions}
            placeholder={{ label: "Выберите сервер", disabled: true }}
            error={!tags.includes(rule.server)} onChange={(value) => updateRule({ server: value })} />
          <Field label="Доменные суффиксы" multiline value={rule.domain_suffix.join("\n")}
            valid={rule.domain_suffix.every(domainValid)} hint="По одному домену в строке"
            onChange={(value) => updateRule({ domain_suffix: lines(value) })} />
          <Field label="Наборы правил" multiline value={rule.rule_sets.join("\n")}
            valid={rule.rule_sets.every(engineTagValid)} hint="Теги объявленных наборов, по одному в строке"
            onChange={(value) => updateRule({ rule_sets: lines(value) })} />
        </FormGrid>}
        <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={() => setRuleIndex(null)} save={() => void save()} />
      </DialogContent>
    </Dialog>
  </>;
}
