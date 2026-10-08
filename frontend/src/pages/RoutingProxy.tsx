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
  RuleSetStatus,
} from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { FormActions, FormGrid, FormWide } from "../components/Form";
import { InfoNote } from "../components/InfoNote";
import { SelectField } from "../components/Select";
import { Toggle } from "../components/Toggle";
import { hostValid, nameValid, portValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
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

const subscriptionValid = (s: ProxySubscription) =>
  nameValid(s.name) &&
  httpsValid(s.url) &&
  Number.isInteger(s.interval_hours) &&
  s.interval_hours >= 1 &&
  s.interval_hours <= 168;

const groupValid = (g: ProxyGroup, allTags: string[]) =>
  nameValid(g.tag) &&
  g.tag !== RESERVED_TAG &&
  g.outbounds.length > 0 &&
  !g.outbounds.includes(g.tag) &&
  g.outbounds.every((t) => t !== g.tag && allTags.includes(t)) &&
  (g.interval_minutes === null ||
    (Number.isInteger(g.interval_minutes) &&
      g.interval_minutes >= 1 &&
      g.interval_minutes <= 1440));

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

function ProxiesView({ settings }: { settings: ProxySettings }) {
  return (
    <>
      <InfoNote>
        Секреты выходов и подписок не отображаются: они хранятся на сервере в
        зашифрованном виде и возвращаются замаскированными. Ввод нового секрета
        заменяет сохранённый; пустое поле оставляет прежний.
      </InfoNote>
      <Card title="Прокси-выходы">
        <DataTable
          heads={["Тег", "Тип", "Сервер", "Порт", "TLS"]}
          rows={settings.outbounds.map((o) => [
            o.tag,
            <Badge>{o.type}</Badge>,
            o.server ?? "—",
            o.port ?? "—",
            o.tls ? "да" : "нет",
          ])}
          empty={
            <EmptyState title="Нет прокси-выходов">
              Добавьте выход (например, shadowsocks или vless), чтобы направить
              трафик через него.
            </EmptyState>
          }
        />
      </Card>
      <Card title="Подписки">
        <DataTable
          heads={["Имя", "URL", "Формат", "Интервал, ч", "Статус"]}
          rows={settings.subscriptions.map((s) => [
            s.name,
            s.url,
            s.format,
            s.interval_hours,
            <Badge tone={s.enabled ? "green" : "amber"}>
              {s.enabled ? "включена" : "выключена"}
            </Badge>,
          ])}
          empty={
            <EmptyState title="Нет подписок">
              Укажите https-URL и формат подписки; интервал обновления — в часах.
            </EmptyState>
          }
        />
      </Card>
      <Card title="Группы выходов">
        <DataTable
          heads={["Тег", "Тип", "Выходы", "URL"]}
          rows={settings.groups.map((g) => [
            g.tag,
            <Badge>{g.type}</Badge>,
            g.outbounds.join(", "),
            g.url ?? "—",
          ])}
          empty={
            <EmptyState title="Нет групп">
              Группа selector или urltest собирает выходы по тегам и выбирает
              конечный выход для unmatched-трафика.
            </EmptyState>
          }
        />
      </Card>
    </>
  );
}

/**
 * Draft-only editor for the `proxies` contract section (outbounds,
 * subscriptions, groups). Saves the whole configuration as a draft — nothing is
 * applied and TProxy stays closed. Read-only for an operator.
 */
export function ProxiesEditor() {
  const { configuration, version, user } = useConfiguration();
  const editor = useDraftEditor<ProxySettings>();
  const readonly = user?.role === "operator";
  const current: ProxySettings = editor.value ?? configuration.proxies;
  const patch = (value: Partial<ProxySettings>) =>
    editor.setValue({ ...current, ...value });

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

  const begin = () =>
    editor.begin({
      enabled: configuration.proxies.enabled,
      outbounds: [...configuration.proxies.outbounds],
      subscriptions: [...configuration.proxies.subscriptions],
      groups: [...configuration.proxies.groups],
    });
  const save = async () => {
    if (readonly || !valid) return;
    await editor.save((value) => ({ ...configuration, proxies: value }));
  };

  const groupRefs = (tag: string) => allTags.filter((t) => t !== tag);

  return (
    <>
      <ErrorNotice error={editor.error} />
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
          <ProxiesView settings={current} />
        </>
      ) : (
        <>
          <Card title="Прокси-выходы">
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
                        onClick={() =>
                          patch({
                            outbounds: current.outbounds.filter(
                              (_, i) => i !== index,
                            ),
                          })
                        }
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

          <Card title="Подписки">
            {current.subscriptions.map((s, index) => {
              const update = (v: Partial<ProxySubscription>) =>
                patch({
                  subscriptions: current.subscriptions.map((row, i) =>
                    i === index ? { ...row, ...v } : row,
                  ),
                });
              return (
                <div key={index} className="rule-row">
                  <FormGrid>
                    <Field
                      label="Имя подписки"
                      value={s.name}
                      valid={nameValid(s.name)}
                      onChange={(name) => update({ name })}
                    />
                    <Field
                      label="URL подписки"
                      value={s.url}
                      valid={httpsValid(s.url)}
                      hint="Только https://"
                      onChange={(url) => update({ url })}
                    />
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
                    <Toggle
                      label="Включена"
                      value={s.enabled}
                      onChange={(enabled) => update({ enabled })}
                    />
                    <FormActions>
                      <DeleteButton
                        label={`Удалить подписку ${s.name || index + 1}`}
                        onClick={() =>
                          patch({
                            subscriptions: current.subscriptions.filter(
                              (_, i) => i !== index,
                            ),
                          })
                        }
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
                      },
                    ],
                  })
                }
              >
                + Добавить подписку
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
                          valid={
                            g.interval_minutes === null ||
                            (Number.isInteger(g.interval_minutes) &&
                              g.interval_minutes >= 1 &&
                              g.interval_minutes <= 1440)
                          }
                          onChange={(v) =>
                            update({
                              interval_minutes:
                                v === "" ? null : Number(v),
                            })
                          }
                        />
                      </>
                    )}
                    <FormActions>
                      <DeleteButton
                        label={`Удалить группу ${g.tag || index + 1}`}
                        onClick={() =>
                          patch({
                            groups: current.groups.filter(
                              (_, i) => i !== index,
                            ),
                          })
                        }
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
        Источники rule-set загружает агент (SSRF-защищённый downloader). Список —
        только для чтения: имя, формат, URL и статус обновления. Ручное
        обновление доступно администратору.
      </InfoNote>
      <DataTable
        heads={["Имя", "Формат", "URL", "Статус", "Актуальность", "Обновление"]}
        rows={(sources.data ?? []).map((row) => [
          row.name,
          row.format ?? "—",
          row.url ?? "—",
          <Badge tone={RULESET_STATUS[row.status].tone}>
            {RULESET_STATUS[row.status].label}
          </Badge>,
          <Badge tone={row.stale ? "amber" : "green"}>
            {row.stale ? "устарел" : "актуален"}
          </Badge>,
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
