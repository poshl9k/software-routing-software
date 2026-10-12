import { Button, Checkbox, FormControlLabel, Typography } from "@mui/material";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useConfiguration } from "../state";
import { api } from "../api";
import { queryKeys } from "../query";
import type {
  ProxyGroup,
  ProxyOutbound,
  ProxySettings,
  ProxySubscription,
  SubscriptionMember, SubscriptionPreview, SubscriptionRefresh,
  RuleSetStatus,
} from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormActions, FormGrid, FormWide } from "../components/Form";
import { InfoNote } from "../components/InfoNote";
import { InlineStatus } from "../components/InlineStatus";
import { PageSection } from "../components/PageSection";
import { ValueTabs } from "../components/Tabs";
import { Select, SelectField } from "../components/Select";
import { Toggle } from "../components/Toggle";
import { hostValid, nameValid, portValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { parseShareLinks } from "../shareLinks";
import { SecretField } from "./ConnectionEditors";

const OUTBOUND_TYPES: ProxyOutbound["type"][] = [
  "direct",
  "block",
  "shadowsocks",
  "vmess",
  "vless",
  "trojan",
  "hysteria2",
  "tuic",
];
/** Local outbounds carry no server/port/secret (backend forbids the fields). */
const LOCAL_TYPES: ProxyOutbound["type"][] = ["direct", "block"];
const SUBSCRIPTION_FORMATS: ProxySubscription["format"][] = [
  "auto",
  "sing-box",
  "clash",
  "v2ray",
  "base64",
];
const GROUP_TYPES: ProxyGroup["type"][] = ["selector", "urltest"];
/** The generator always owns this tag for its implicit local direct outbound. */
const RESERVED_TAG = "direct";

const httpsValid = (v: string) => /^https:\/\/\S+$/.test(v.trim());
const loopbackValid = (v: string) =>
  /^(?:127(?:\.\d{1,3}){3}|\[::1\])(?::\d{1,5})?$/.test(v.trim());

const outboundValid = (o: ProxyOutbound) =>
  nameValid(o.tag) &&
  o.tag !== RESERVED_TAG &&
  (LOCAL_TYPES.includes(o.type) ||
    (!!o.server?.trim() && hostValid(o.server) && portValid(o.port ?? 0))) &&
  (!o.tls_server_name || hostValid(o.tls_server_name)) &&
  (!o.admin_listen || loopbackValid(o.admin_listen));

const optionalRange = (v: number | null | undefined, min: number, max: number) =>
  v == null || (Number.isInteger(v) && v >= min && v <= max);
const regexValid = (pattern: string | null | undefined) => {
  if (pattern == null) return true;
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
};
const headerValid = (header: string) =>
  /^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [^\r\n]*[^\s\r\n]$/.test(header);
const lines = (text: string) => text.split(/\r?\n/);
const filledLines = (items: string[]) => items.map((line) => line.trim()).filter(Boolean);

const subscriptionValid = (s: ProxySubscription) =>
  nameValid(s.name) &&
  (s.inline ? !!s.inline_content?.trim() : httpsValid(s.url)) &&
  Number.isInteger(s.interval_hours) &&
  s.interval_hours >= 1 &&
  s.interval_hours <= 168 &&
  (!s.url_test || httpsValid(s.url_test)) &&
  optionalRange(s.test_interval_minutes, 1, 1440) &&
  optionalRange(s.test_tolerance_ms, 0, 5000) &&
  (s.headers ?? []).every((header) => !header.trim() || headerValid(header.trim())) &&
  regexValid(s.filter_include) && regexValid(s.filter_exclude);

const groupValid = (g: ProxyGroup, allTags: string[]) =>
  nameValid(g.tag) &&
  g.tag !== RESERVED_TAG &&
  g.outbounds.length > 0 &&
  !g.outbounds.includes(g.tag) &&
  g.outbounds.every((t) => t !== g.tag && allTags.includes(t)) &&
  optionalRange(g.interval_minutes, 1, 1440) &&
  optionalRange(g.tolerance_ms, 0, 5000);

function localCleared(type: ProxyOutbound["type"]): Partial<ProxyOutbound> {
  return LOCAL_TYPES.includes(type)
    ? {
        type,
        server: null,
        port: null,
        secret: null,
        tls: false,
        tls_server_name: null,
        tls_insecure: false,
        admin_listen: null,
      }
    : { type };
}

function SubscriptionCard({ subscription, editable, canFetch = true, onChange, onProposal }: {
  subscription: ProxySubscription;
  editable: boolean;
  canFetch?: boolean;
  onChange?: (change: Partial<ProxySubscription>) => void;
  onProposal?: (outbounds: ProxyOutbound[], groups: ProxyGroup[]) => void;
}) {
  const [result, setResult] = useState<SubscriptionPreview | SubscriptionRefresh | null>(null);
  const [resultSource, setResultSource] = useState("");
  const proposal = resultSource === JSON.stringify(subscription) ? result : null;
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Не проверялась");
  const [lastError, setLastError] = useState<string | null>(null);
  const [delays, setDelays] = useState<Record<string, number | string>>({});
  const [stored, setStored] = useState<SubscriptionMember[]>([]);
  const members = proposal ? ("members" in proposal ? proposal.members : [
    ...proposal.added, ...proposal.updated, ...proposal.unchanged, ...proposal.orphans,
  ]) : stored;
  const excluded = subscription.excluded_members ?? [];
  const run = async (action: "preview" | "refresh") => {
    setBusy(true); setError(null);
    const source = JSON.stringify(subscription);
    try {
      const data = action === "preview"
        ? await api.subscriptionPreview(subscription)
        : await api.refreshSubscription(subscription.name);
      setResult(data);
      setLastError(null);
      setResultSource(source);
      setStatus(action === "preview" ? "Просмотр выполнен; черновик не изменён" : "Получено предложение обновления; движок не обновлён");
      if (action === "refresh" && !onProposal) setStatus("Получено предложение; откройте черновик для сохранения");
    } catch (err) {
      setError(err);
      setLastError(err instanceof Error ? err.message : "Недоступно");
      setStatus("Ошибка обновления / просмотра");
    } finally { setBusy(false); }
  };
  const checkOne = async (member: SubscriptionMember) => {
    setError(null);
    try {
      const value = await api.runtimeProxyDelay(member.tag, subscription.url_test || "https://www.gstatic.com/generate_204");
      setDelays((previous) => ({ ...previous, [member.tag]: value.delay }));
    } catch (err) {
      setError(err);
      setDelays((previous) => ({ ...previous, [member.tag]: err instanceof Error ? err.message : "Недоступно" }));
    }
  };
  const checkAll = async () => {
    setBusy(true); setError(null);
    try {
      let firstError: unknown = null;
      const rows = await Promise.all(members.filter((m) => !excluded.includes(m.tag)).map(async (m) => {
        try {
          const value = await api.runtimeProxyDelay(m.tag, subscription.url_test || "https://www.gstatic.com/generate_204");
          return [m.tag, value.delay] as const;
        } catch (err) {
          firstError ??= err;
          return [m.tag, err instanceof Error ? err.message : "Недоступно"] as const;
        }
      }));
      setDelays(Object.fromEntries(rows));
      if (firstError) setError(firstError);
    } finally { setBusy(false); }
  };
  const loadMembers = async () => {
    setError(null);
    try { setStored(await api.subscriptionMembers(subscription.name)); }
    catch (err) { setError(err); }
  };
  return <Card title={subscription.name || "Новая подписка"}>
    <InlineStatus tone={lastError ? "red" : proposal ? "green" : "unknown"}
      text={`${subscription.enabled ? "Включена" : "Выключена"} · ${result && !proposal ? "Настройки изменены — выполните просмотр снова" : status} · Серверов: ${members.length} · Активный: ${subscription.active_member || "не выбран"}${lastError ? ` · Ошибка: ${lastError}` : ""}`} />
    <ErrorNotice error={error} />
    <FormActions>
      <Button disabled={busy || !canFetch || !subscriptionValid(subscription)} onClick={() => void run("preview")}>Просмотр</Button>
      <Button disabled={busy || !canFetch || !subscription.name} onClick={() => void run("refresh")}>Обновить сейчас</Button>
      <Button disabled={busy || !subscription.name} onClick={() => void loadMembers()}>Участники</Button>
      <Button disabled={busy || !members.length} onClick={() => void checkAll()}>Проверить всё</Button>
      {editable && proposal && <Button onClick={() => { onProposal?.(proposal.outbounds, proposal.groups); setStatus("Предложение добавлено в черновик; сохраните черновик и примените конфигурацию отдельно"); }}>Применить предложение</Button>}
    </FormActions>
    {proposal && "added" in proposal && <InfoNote>Изменения: добавлено {proposal.added.length}, обновлено {proposal.updated.length}, без изменений {proposal.unchanged.length}, сирот {proposal.orphans.length}.</InfoNote>}
    {proposal && proposal.skipped.length > 0 && <InfoNote>Пропущено: {proposal.skipped.length}. {proposal.skipped.map((row) => `Строка ${row.line}: ${row.reason}`).join("; ")}</InfoNote>}
    {proposal && "orphans" in proposal && proposal.orphans.length > 0 &&
      <InfoNote>Сироты: {proposal.orphans.length}. Они сохранены в предложении; не удаляются автоматически.</InfoNote>}
    {members.length > 0 && <>
      <PageSection title={`Серверы (${members.length})`}>
      <DataTable heads={["Сервер", "Протокол", "Транспорт", "SNI / защита", "Задержка", "Действия"]}
        rows={members.filter((m) => !excluded.includes(m.tag)).map((m) => [
          m.label, m.protocol, m.transport || "—", `${m.sni || "—"} / ${m.security || "—"}`,
          delays[m.tag] == null ? "Не проверен" : typeof delays[m.tag] === "number" ? `${delays[m.tag]} мс` : `Недоступно: ${delays[m.tag]}`,
          <><Button disabled={busy} onClick={() => void checkOne(m)}>Проверить</Button>
            {editable && <Button onClick={() => onChange?.({ excluded_members: [...excluded, m.tag] })}>Исключить</Button>}</>,
        ])} />
      </PageSection>
      {editable && (subscription.mode ?? "selector") === "selector" && <Select label="Активный участник" value={subscription.active_member ?? ""}
        options={[{ value: "", label: "Не выбран" }, ...members.filter((m) => !excluded.includes(m.tag)).map((m) => ({ value: m.tag, label: m.label }))]}
        onChange={(value) => onChange?.({ active_member: value || null })} />}
    </>}
    {editable && <PageSection title={`Исключённые (${excluded.length})`}>
      {excluded.length ? excluded.map((tag) => <div key={tag}>{members.find((m) => m.tag === tag)?.label ?? tag}
        <Button onClick={() => onChange?.({ excluded_members: excluded.filter((x) => x !== tag) })}>Вернуть</Button></div>) : <InfoNote>Нет исключённых участников</InfoNote>}
    </PageSection>}
  </Card>;
}

function ProxiesView({ settings, readonly, onEdit }: { settings: ProxySettings; readonly: boolean; onEdit: () => void }) {
  const [tab, setTab] = useState<"outbounds" | "subscriptions">("outbounds");
  return (
    <>
      <ValueTabs value={tab} change={setTab} tabs={[
        { value: "outbounds", label: "Прокси-выходы" }, { value: "subscriptions", label: "Подписки" },
      ]} />
      <InfoNote>
        Секреты выходов и подписок не отображаются: они хранятся на сервере в
        зашифрованном виде и возвращаются замаскированными. Ввод нового секрета
        заменяет сохранённый; пустое поле оставляет прежний.
      </InfoNote>
      {tab === "outbounds" && <Card title="Прокси-выходы">
        <DataTable
          heads={["Тег", "Тип", "Сервер", "Действия"]}
          rows={settings.outbounds.map((o) => [
            o.tag,
            <Badge>{o.type}</Badge>,
            o.server ?? "—",
            <Button disabled={readonly} onClick={onEdit}>Изменить</Button>,
          ])}
          empty={
            <EmptyState title="Нет прокси-выходов">
              Добавьте выход (например, shadowsocks или vless), чтобы направить
              трафик через него.
            </EmptyState>
          }
        />
      </Card>}
      {tab === "subscriptions" && <Card title="Подписки">
        <InfoNote>Предпросмотр и ручной запрос не применяют изменения к движку. Заголовки пока не поддерживаются безопасным загрузчиком.</InfoNote>
        {settings.subscriptions.length ? settings.subscriptions.map((s) =>
          <SubscriptionCard key={s.name} subscription={s} editable={false} canFetch={!readonly} />) :
          <EmptyState title="Нет подписок">Добавьте подписку в черновике.</EmptyState>}
      </Card>}
      {tab === "outbounds" && <Card title="Группы выходов">
        <DataTable
          heads={["Тег", "Тип", "Выходы", "URL"]}
          rows={settings.groups.map((g) => [
            g.tag,
            <Badge>{g.type}</Badge>,
            g.outbounds.join(", "),
            g.url ? "https://•••" : "—",
          ])}
          empty={
            <EmptyState title="Нет групп">
              Группа selector или urltest собирает выходы по тегам и выбирает
              конечный выход для unmatched-трафика.
            </EmptyState>
          }
        />
      </Card>}
    </>
  );
}

/**
 * Draft-only editor for the `proxies` contract section (outbounds,
 * subscriptions, groups). Saves the whole configuration as a draft — nothing is
 * applied. Read-only for an operator.
 */
export function ProxiesEditor() {
  const { configuration, version, user } = useConfiguration();
  const editor = useDraftEditor<ProxySettings>();
  const readonly = user?.role === "operator";
  const [importText, setImportText] = useState("");
  const [importError, setImportError] = useState<Error | null>(null);
  const [importCount, setImportCount] = useState(0);
  const [selected, setSelected] = useState<number[]>([]);
  const [editedHeaders, setEditedHeaders] = useState<number[]>([]);
  const [editedInline, setEditedInline] = useState<number[]>([]);
  const [editedUrls, setEditedUrls] = useState<number[]>([]);
  const [pendingDelete, setPendingDelete] = useState<{ tags: string[]; refs: string[]; kind: "outbound" | "group"; indices: number[] } | null>(null);
  const current: ProxySettings = editor.value ?? configuration.proxies;
  const patch = (value: Partial<ProxySettings>) =>
    editor.setValue({ ...current, ...value });

  const importLinks = () => {
    const parsed = parseShareLinks(importText);
    const occupied = new Set([
      RESERVED_TAG,
      ...current.outbounds.map((o) => o.tag),
      ...current.groups.map((g) => g.tag),
    ]);
    const outbounds: ProxyOutbound[] = [];
    const errors: string[] = [];
    for (const item of parsed) {
      if (item.error || !item.outbound) {
        errors.push(item.error ?? "Некорректная ссылка");
        continue;
      }
      const outbound = item.outbound;
      // The parser already returns a contract-valid Name; only a collision with an
      // existing outbound/group tag needs a suffix here.
      const base = outbound.tag;
      let tag = base;
      for (let n = 1; occupied.has(tag);) {
        const suffix = `_${++n}`;
        tag = `${base.slice(0, 31 - suffix.length)}${suffix}`;
      }
      if (!nameValid(tag) || !outboundValid({ ...outbound, tag })) {
        errors.push("Некорректный тег или адрес выхода");
        continue;
      }
      occupied.add(tag);
      outbounds.push({ ...outbound, tag });
    }
    if (outbounds.length) {
      patch({ outbounds: [...current.outbounds, ...outbounds] });
      setImportText("");
    }
    setImportCount(outbounds.length);
    setImportError(errors.length ? new Error(`Не импортировано: ${errors.length}. ${errors[0]}`) : null);
  };

  const references = (tags: string[]) => [
    ...configuration.tproxy.rules.filter((r) => r.action === "route" && tags.includes(r.outbound ?? ""))
      .map((r) => `правило ${r.name}`),
    ...(configuration.tproxy.final === "route" && tags.includes(configuration.tproxy.final_outbound ?? "")
      ? ["конечное действие"] : []),
    ...current.groups.filter((g) => !tags.includes(g.tag) && g.outbounds.some((t) => tags.includes(t)))
      .map((g) => `группа ${g.tag}`),
  ];
  const requestDelete = (indices: number[], kind: "outbound" | "group") => {
    const tags = indices.map((i) => kind === "outbound" ? current.outbounds[i].tag : current.groups[i].tag);
    setPendingDelete({ tags, indices, kind, refs: references(tags) });
  };
  const removeSelected = () => {
    if (!selected.length) return;
    requestDelete(selected, "outbound");
  };
  const duplicateSelected = () => {
    if (!selected.length) return;
    const occupied = new Set([
      RESERVED_TAG,
      ...current.outbounds.map((o) => o.tag),
      ...current.groups.map((g) => g.tag),
    ]);
    const copies = current.outbounds.filter((_, index) => selected.includes(index)).map((o) => {
      let n = 1;
      let suffix = "_copy";
      let tag = `${o.tag.slice(0, 31 - suffix.length)}${suffix}`;
      while (occupied.has(tag)) {
        suffix = `_copy${++n}`;
        tag = `${o.tag.slice(0, 31 - suffix.length)}${suffix}`;
      }
      occupied.add(tag);
      return { ...o, tag };
    });
    patch({ outbounds: [...current.outbounds, ...copies] });
    setSelected([]);
  };

  const allTags = [
    ...current.outbounds.map((o) => o.tag),
    ...current.groups.map((g) => g.tag),
  ];
  const tagsUnique =
    new Set(allTags).size === allTags.length && !allTags.includes(RESERVED_TAG);
  const namesUnique =
    new Set(current.subscriptions.map((s) => s.name)).size ===
    current.subscriptions.length;
  const valid =
    tagsUnique &&
    namesUnique &&
    current.outbounds.every(outboundValid) &&
    current.subscriptions.every(subscriptionValid) &&
    current.groups.every((g) => groupValid(g, allTags));

  const begin = () => {
    setEditedHeaders([]);
    setEditedInline([]);
    setEditedUrls([]);
    setSelected([]);
    setImportText("");
    setImportError(null);
    setImportCount(0);
    editor.begin({
      enabled: configuration.proxies.enabled,
      outbounds: [...configuration.proxies.outbounds],
      subscriptions: [...configuration.proxies.subscriptions],
      groups: [...configuration.proxies.groups],
    });
  };
  const save = async () => {
    if (readonly || !valid) return;
    await editor.save((value) => ({
      ...configuration,
      proxies: {
        ...value,
        subscriptions: value.subscriptions.map((s) => ({
          ...s,
          headers: filledLines(s.headers ?? []),
          excluded_members: filledLines(s.excluded_members ?? []),
        })),
      },
    }));
  };

  const groupRefs = (tag: string) => allTags.filter((t) => t !== tag);

  return (
    <>
      <ErrorNotice error={editor.error} />
      <InfoNote>Прокси-выходы — конфигурация черновика, не проверка доступности. Секция выходов {current.enabled ? "задана включённой" : "выключена"}; TProxy настраивается отдельно и меняет трафик только после общего применения.</InfoNote>
      <ConfirmDialog open={!!pendingDelete} title="Удалить выходы из черновика?"
        body={`Ссылки на ${pendingDelete?.tags.join(", ")}: ${pendingDelete?.refs.join(", ") || "нет"}. Зависимые правила после удаления потребуют исправления.`}
        confirmLabel="Удалить" cancelLabel="Отмена" danger
        onCancel={() => setPendingDelete(null)} onConfirm={() => {
          if (pendingDelete?.kind === "outbound") {
            patch({ outbounds: current.outbounds.filter((_, i) => !pendingDelete.indices.includes(i)) });
            setSelected([]);
          } else if (pendingDelete) {
            patch({ groups: current.groups.filter((_, i) => !pendingDelete.indices.includes(i)) });
          }
          setPendingDelete(null);
        }} />
      {!editor.isEdit ? (
        <>
          <div className="toolbar-actions">
            <Button disabled={!version || readonly} onClick={begin}>
              Редактировать
            </Button>
          </div>
          {readonly && (
            <InfoNote>Режим оператора: прокси-выходы только для просмотра.</InfoNote>
          )}
          <ProxiesView settings={current} readonly={readonly} onEdit={begin} />
        </>
      ) : (
        <>
          <Card title="Прокси-выходы">
            <FormGrid>
              <FormWide>
                <FormControlLabel
                  label="Выбрать все выходы"
                  control={
                    <Checkbox
                      aria-label="Выбрать все выходы"
                      checked={current.outbounds.length > 0 && selected.length === current.outbounds.length}
                      indeterminate={selected.length > 0 && selected.length < current.outbounds.length}
                      onChange={(_, checked) => setSelected(checked ? current.outbounds.map((_, i) => i) : [])}
                    />
                  }
                />
              </FormWide>
              <FormActions>
                <Button disabled={!selected.length} onClick={removeSelected}>Удалить выбранные</Button>
                <Button disabled={!selected.length} onClick={duplicateSelected}>Дублировать выбранные</Button>
              </FormActions>
            </FormGrid>
            {current.outbounds.map((o, index) => {
              const update = (v: Partial<ProxyOutbound>) =>
                patch({
                  outbounds: current.outbounds.map((row, i) =>
                    i === index ? { ...row, ...v } : row,
                  ),
                });
              return (
                <div key={index} className="rule-row">
                  <FormGrid>
                    <FormWide>
                      <Checkbox
                        inputProps={{ "aria-label": `Выбрать выход ${o.tag}` }}
                        checked={selected.includes(index)}
                        onChange={(_, checked) => setSelected(checked ? [...selected, index] : selected.filter((i) => i !== index))}
                      />
                    </FormWide>
                    <Field
                      label="Тег выхода"
                      value={o.tag}
                      valid={nameValid(o.tag) && o.tag !== RESERVED_TAG}
                      hint={
                        o.tag === RESERVED_TAG
                          ? "Тег «direct» занят генератором"
                          : "Латиница, цифры, «_»"
                      }
                      onChange={(tag) => update({ tag })}
                    />
                    <SelectField
                      label="Тип"
                      value={o.type}
                      options={OUTBOUND_TYPES}
                      onChange={(type) => update(localCleared(type))}
                    />
                    {!LOCAL_TYPES.includes(o.type) && (
                      <>
                        <Field
                          label="Сервер"
                          value={o.server ?? ""}
                          valid={!!o.server?.trim() && hostValid(o.server)}
                          placeholder="example.com"
                          onChange={(server) => update({ server })}
                        />
                        <Field
                          label="Порт"
                          type="number"
                          value={o.port ?? ""}
                          valid={portValid(o.port ?? 0)}
                          onChange={(v) =>
                            update({ port: v === "" ? null : Number(v) })
                          }
                        />
                        <SecretField
                          label="Секрет (пароль / UUID)"
                          value={o.secret}
                          change={(secret) => update({ secret })}
                        />
                        {o.type === "shadowsocks" && (
                          <Field
                            label="Метод шифрования"
                            value={o.method ?? ""}
                            onChange={(method) => update({ method: method || null })}
                          />
                        )}
                        <Toggle
                          label="TLS"
                          value={o.tls}
                          onChange={(tls) => update({ tls })}
                        />
                        {o.tls && (
                          <>
                            <Field
                              label="TLS имя сервера (SNI)"
                              value={o.tls_server_name ?? ""}
                              valid={
                                !o.tls_server_name ||
                                hostValid(o.tls_server_name)
                              }
                              onChange={(v) =>
                                update({ tls_server_name: v || null })
                              }
                            />
                            <Toggle
                              label="Не проверять сертификат"
                              value={o.tls_insecure}
                              onChange={(tls_insecure) =>
                                update({ tls_insecure })
                              }
                            />
                            {o.tls_insecure && <InfoNote>Отключение проверки сертификата снижает защиту от подмены сервера.</InfoNote>}
                          </>
                        )}
                        <Field
                          label="Локальный admin_listen"
                          value={o.admin_listen ?? ""}
                          hint="Только loopback: 127.0.0.1[:port]"
                          valid={
                            !o.admin_listen || loopbackValid(o.admin_listen)
                          }
                          onChange={(v) =>
                            update({ admin_listen: v || null })
                          }
                        />
                      </>
                    )}
                    <FormActions>
                      <DeleteButton
                        label={`Удалить выход ${o.tag || index + 1}`}
                        onClick={() => requestDelete([index], "outbound")}
                      />
                    </FormActions>
                  </FormGrid>
                </div>
              );
            })}
            <FormActions>
              <Button
                onClick={() =>
                  patch({
                    outbounds: [
                      ...current.outbounds,
                      {
                        tag: "",
                        type: "shadowsocks",
                        server: "",
                        port: null,
                        secret: null,
                        method: null,
                        tls: false,
                        tls_server_name: null,
                        tls_insecure: false,
                        admin_listen: null,
                      },
                    ],
                  })
                }
              >
                + Добавить выход
              </Button>
            </FormActions>
          </Card>

          <Card title="Импорт ссылок">
            <FormGrid>
              <FormWide>
                <Field
                  label="Ссылки для импорта (по одной в строке)"
                  multiline
                  value={importText}
                  onChange={setImportText}
                />
              </FormWide>
              <FormActions>
                <Button disabled={!importText.trim()} onClick={importLinks}>Импортировать</Button>
              </FormActions>
              <FormWide>
                <ErrorNotice error={importError} />
                {importCount > 0 && <InfoNote>Импортировано выходов: {importCount}</InfoNote>}
              </FormWide>
            </FormGrid>
          </Card>

          <Card title="Подписки">
            <InfoNote>Предпросмотр и обновление возвращают предложение. Сохранение и применение — отдельные действия. Заголовки пока не принимаются безопасным загрузчиком.</InfoNote>
            {current.subscriptions.map((s, index) => {
              const update = (v: Partial<ProxySubscription>) => {
                const group = current.groups.find((g) => g.tag === s.name);
                const selected = v.active_member;
                const excluded = v.excluded_members;
                patch({
                  subscriptions: current.subscriptions.map((row, i) =>
                    i === index ? { ...row, ...v } : row,
                  ),
                  ...(group && (selected !== undefined || excluded !== undefined) ? {
                    groups: current.groups.map((g) => g.tag !== s.name ? g : {
                      ...g,
                      outbounds: [...new Set([...g.outbounds,
                        ...(s.excluded_members ?? []).filter((tag) => current.outbounds.some((o) => o.tag === tag)),
                      ])].filter((tag) => !(excluded ?? s.excluded_members ?? []).includes(tag))
                        .sort((a, b) => a === selected ? -1 : b === selected ? 1 : 0),
                    }),
                  } : {}),
                });
              };
              return (
                <div key={index} className="rule-row">
                  <SubscriptionCard subscription={s} editable onChange={update}
                    onProposal={(outbounds, groups) => {
                      if (!outbounds.length || !groups.some((g) => g.tag === s.name && g.outbounds.length)) {
                        editor.setError(new Error("Нет доступных серверов: предложение не содержит группу выхода."));
                        return;
                      }
                      const replacing = new Set(outbounds.map((o) => o.tag));
                      patch({
                        enabled: true,
                        subscriptions: current.subscriptions.map((row, i) => i === index ? { ...row, enabled: true } : row),
                        outbounds: [...current.outbounds.filter((o) => !replacing.has(o.tag)), ...outbounds],
                        groups: [...current.groups.filter((g) => !groups.some((incoming) => incoming.tag === g.tag)), ...groups],
                      });
                    }} />
                  <FormGrid>
                    <Field
                      label="Имя подписки"
                      value={s.name}
                      valid={nameValid(s.name)}
                      onChange={(name) => update({ name })}
                    />
                    <Toggle
                      label="Список вручную (inline)"
                      value={s.inline ?? false}
                      onChange={(inline) => update({ inline, inline_content: inline ? (s.inline_content ?? "") : null })}
                    />
                    {s.inline ? (
                      <FormWide>
                        <Field
                          label="Список вручную"
                          multiline
                          value={editedInline.includes(index) ? (s.inline_content ?? "") : ""}
                          hint={!editedInline.includes(index) && s.inline_content ? "Сохранённый список скрыт; ввод заменит его" : undefined}
                          valid={!!s.inline_content?.trim()}
                          onChange={(inline_content) => {
                            setEditedInline((indices) => indices.includes(index) ? indices : [...indices, index]);
                            update({ inline_content });
                          }}
                        />
                      </FormWide>
                    ) : s.url && !editedUrls.includes(index) ? (
                      <FormWide>
                        <InfoNote>URL подписки: https://••• (сохранён; адрес и токен скрыты)</InfoNote>
                        <Button onClick={() => { setEditedUrls((indices) => [...indices, index]); update({ url: "" }); }}>Заменить URL</Button>
                      </FormWide>
                    ) : (
                      <Field
                        label="URL подписки"
                        value={s.url && editedUrls.includes(index) ? s.url : ""}
                        valid={httpsValid(s.url)}
                        hint="Только https://; адрес с токеном не показывается после сохранения"
                        onChange={(url) => { setEditedUrls((indices) => indices.includes(index) ? indices : [...indices, index]); update({ url }); }}
                      />
                    )}
                    <SelectField
                      label="Формат"
                      value={s.format}
                      options={SUBSCRIPTION_FORMATS}
                      onChange={(format) => update({ format })}
                    />
                    <Field
                      label="Интервал, часов"
                      type="number"
                      value={s.interval_hours}
                      valid={
                        Number.isInteger(s.interval_hours) &&
                        s.interval_hours >= 1 &&
                        s.interval_hours <= 168
                      }
                      onChange={(v) =>
                        update({ interval_hours: Number(v) })
                      }
                    />
                    <Select
                      label="Режим выбора"
                      value={s.mode ?? "selector"}
                      options={[
                        { value: "selector", label: "Ручной выбор" },
                        { value: "urltest", label: "Автовыбор по скорости" },
                      ]}
                      onChange={(mode) => update({ mode: mode as ProxySubscription["mode"] })}
                    />
                    {s.mode === "urltest" && (
                      <>
                        <Field
                          label="URL проверки скорости"
                          value={s.url_test ?? ""}
                          placeholder="https://www.gstatic.com/generate_204"
                          valid={!s.url_test || httpsValid(s.url_test)}
                          onChange={(v) => update({ url_test: v || null })}
                        />
                        <Field
                          label="Интервал проверки, минут"
                          type="number"
                          value={s.test_interval_minutes ?? ""}
                          valid={optionalRange(s.test_interval_minutes, 1, 1440)}
                          onChange={(v) => update({ test_interval_minutes: v === "" ? null : Number(v) })}
                        />
                        <Field
                          label="Допуск проверки, мс"
                          type="number"
                          value={s.test_tolerance_ms ?? ""}
                          valid={optionalRange(s.test_tolerance_ms, 0, 5000)}
                          onChange={(v) => update({ test_tolerance_ms: v === "" ? null : Number(v) })}
                        />
                      </>
                    )}
                    <FormWide>
                      <Field
                        label="Заголовки (Name: value, по одному на строку)"
                        multiline
                        value={editedHeaders.includes(index) ? (s.headers ?? []).join("\n") : ""}
                        hint={!editedHeaders.includes(index) && s.headers?.length ? "Сохранённые заголовки скрыты; ввод заменит их" : "Name: value, по одному на строку"}
                        valid={(s.headers ?? []).every((header) => !header.trim() || headerValid(header.trim()))}
                        onChange={(v) => {
                          setEditedHeaders((indices) => indices.includes(index) ? indices : [...indices, index]);
                          update({ headers: lines(v) });
                        }}
                      />
                    </FormWide>
                    <Field
                      label="Включить по regex"
                      value={s.filter_include ?? ""}
                      valid={regexValid(s.filter_include)}
                      onChange={(v) => update({ filter_include: v || null })}
                    />
                    <Field
                      label="Исключить по regex"
                      value={s.filter_exclude ?? ""}
                      valid={regexValid(s.filter_exclude)}
                      onChange={(v) => update({ filter_exclude: v || null })}
                    />
                    <Field
                      label="Активный участник"
                      value={s.active_member ?? ""}
                      onChange={(v) => update({ active_member: v || null })}
                    />
                    <FormWide>
                      <Field
                        label="Исключённые участники (по одному на строку)"
                        multiline
                        value={(s.excluded_members ?? []).join("\n")}
                        onChange={(v) => update({ excluded_members: lines(v) })}
                      />
                    </FormWide>
                    <Toggle
                      label="Включена"
                      value={s.enabled}
                      onChange={(enabled) => update({ enabled })}
                    />
                    <FormActions>
                      <DeleteButton
                        label={`Удалить подписку ${s.name || index + 1}`}
                        onClick={() => {
                          setEditedHeaders((indices) => indices.filter((i) => i !== index).map((i) => i > index ? i - 1 : i));
                          setEditedInline((indices) => indices.filter((i) => i !== index).map((i) => i > index ? i - 1 : i));
                          patch({
                            subscriptions: current.subscriptions.filter(
                              (_, i) => i !== index,
                            ),
                          });
                        }}
                      />
                    </FormActions>
                  </FormGrid>
                </div>
              );
            })}
            <FormActions>
              <Button
                onClick={() =>
                  patch({
                    subscriptions: [
                      ...current.subscriptions,
                      {
                        name: "",
                        url: "",
                        format: "auto",
                        interval_hours: 24,
                        enabled: false,
                        mode: "selector",
                        url_test: null,
                        test_interval_minutes: null,
                        test_tolerance_ms: null,
                        headers: [],
                        filter_include: null,
                        filter_exclude: null,
                        active_member: null,
                        excluded_members: [],
                        inline: false,
                        inline_content: null,
                      },
                    ],
                  })
                }
              >
                + Подписка по URL
              </Button>
            </FormActions>
          </Card>

          <Card title="Группы выходов">
            {current.groups.map((g, index) => {
              const update = (v: Partial<ProxyGroup>) =>
                patch({
                  groups: current.groups.map((row, i) =>
                    i === index ? { ...row, ...v } : row,
                  ),
                });
              const refs = groupRefs(g.tag);
              return (
                <div key={index} className="rule-row">
                  <FormGrid>
                    <Field
                      label="Тег группы"
                      value={g.tag}
                      valid={nameValid(g.tag) && g.tag !== RESERVED_TAG}
                      onChange={(tag) => update({ tag })}
                    />
                    <SelectField
                      label="Тип группы"
                      value={g.type}
                      options={GROUP_TYPES}
                      onChange={(type) => update({ type })}
                    />
                    <FormWide>
                      <Typography variant="h2">Выходы группы</Typography>
                      {refs.length ? (
                        refs.map((t) => (
                          <FormControlLabel
                            key={t}
                            label={t}
                            control={
                              <Checkbox
                                checked={g.outbounds.includes(t)}
                                onChange={(_, checked) =>
                                  update({
                                    outbounds: checked
                                      ? [...g.outbounds, t]
                                      : g.outbounds.filter((x) => x !== t),
                                  })
                                }
                              />
                            }
                          />
                        ))
                      ) : (
                        <InfoNote>
                          Сначала добавьте выход или другую группу, чтобы выбрать
                          ссылки.
                        </InfoNote>
                      )}
                      {g.outbounds.filter((tag) => !allTags.includes(tag)).map((tag) =>
                        <InfoNote key={tag}>ссылка сломана: {tag}</InfoNote>)}
                    </FormWide>
                    {g.type === "urltest" && (
                      <>
                        <Field
                          label="URL проверки"
                          value={g.url ?? ""}
                          valid={!g.url || httpsValid(g.url)}
                          onChange={(v) => update({ url: v || null })}
                        />
                        <Field
                          label="Интервал проверки, минут"
                          type="number"
                          value={g.interval_minutes ?? ""}
                          valid={optionalRange(g.interval_minutes, 1, 1440)}
                          onChange={(v) => update({ interval_minutes: v === "" ? null : Number(v) })}
                        />
                        <Field
                          label="Допуск, мс"
                          type="number"
                          value={g.tolerance_ms ?? ""}
                          valid={optionalRange(g.tolerance_ms, 0, 5000)}
                          hint="Пусто — по умолчанию"
                          onChange={(v) => update({ tolerance_ms: v === "" ? null : Number(v) })}
                        />
                      </>
                    )}
                    <FormActions>
                      <DeleteButton
                        label={`Удалить группу ${g.tag || index + 1}`}
                        onClick={() => requestDelete([index], "group")}
                      />
                    </FormActions>
                  </FormGrid>
                </div>
              );
            })}
            <FormActions>
              <Button
                onClick={() =>
                  patch({
                    groups: [
                      ...current.groups,
                      {
                        tag: "",
                        type: "selector",
                        outbounds: [],
                        url: null,
                        interval_minutes: null,
                        tolerance_ms: null,
                      },
                    ],
                  })
                }
              >
                + Добавить группу
              </Button>
            </FormActions>
          </Card>

          {!valid && (
            <p role="status">
              Проверьте обязательные поля, https-URL, loopback-адрес
              admin_listen и уникальность тегов и имён.
            </p>
          )}
          <EditorFooter
            saving={editor.saving}
            valid={valid}
            cancel={editor.cancel}
            save={() => void save()}
          />
        </>
      )}
    </>
  );
}

const RULESET_STATUS: Record<
  RuleSetStatus["status"],
  { label: string; tone: "blue" | "green" | "amber" | "red" }
> = {
  never: { label: "не обновлялся", tone: "amber" },
  ok: { label: "ок", tone: "green" },
  failed: { label: "ошибка", tone: "red" },
  not_modified: { label: "не изменён", tone: "blue" },
};

/**
 * Read-only list of rule-set sources, joined with the agent-owned update status
 * (`GET /api/rulesets`). The privileged manual refresh goes through the typed
 * `update_source` RPC; an operator sees the list but cannot trigger an update.
 */
export function RuleSets() {
  const { user } = useConfiguration();
  const canUpdate = user?.role === "admin";
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const sources = useQuery({ queryKey: queryKeys.rulesets(), queryFn: api.rulesets });

  const refresh = async (row: RuleSetStatus) => {
    if (!canUpdate || !row.url) return;
    setError(null);
    setBusy(row.name);
    try {
      await api.updateRuleset({ name: row.name, url: row.url, authorized: true });
      await queryClient.invalidateQueries({ queryKey: queryKeys.rulesets() });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card title="Rule-set (источники списков)">
      <ErrorNotice error={error ?? sources.error} />
      <InfoNote>
        Источники списков: статус сообщает агент. Ручное обновление — действие агента, не сохранение черновика; успешная проверка может сменить рабочую версию без общего применения. Включение TProxy настраивается отдельно.
      </InfoNote>
      <DataTable
        heads={["Имя", "Формат", "Статус", "Актуальность", "Последняя попытка", "Последний успех", "Обновление"]}
        rows={(sources.data ?? []).map((row) => [
          row.name,
          row.format ?? "—",
          <Badge tone={RULESET_STATUS[row.status].tone}>
            {RULESET_STATUS[row.status].label}
          </Badge>,
          <Badge tone={row.stale ? "amber" : "blue"}>
            {row.stale ? "устарел" : "не устарел по данным агента"}
          </Badge>,
          row.last_attempt != null ? new Date(row.last_attempt * 1000).toLocaleString("ru-RU") : "состояние недоступно",
          row.last_success != null ? new Date(row.last_success * 1000).toLocaleString("ru-RU") : "состояние недоступно",
          row.url && canUpdate ? (
            <Button
              size="small"
              disabled={busy === row.name}
              aria-label={`Обновить ${row.name}`}
              onClick={() => void refresh(row)}
            >
              Обновить
            </Button>
          ) : (
            "—"
          ),
        ])}
        empty={
          <EmptyState title="Rule-set не подключены">
            Источники доменов/IP (rule-set) появятся здесь, когда их объявит
            контракт и агент вернёт статус обновления.
          </EmptyState>
        }
      />
    </Card>
  );
}
