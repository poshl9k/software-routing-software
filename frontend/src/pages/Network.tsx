import { useState } from "react";
import { Button, Tab, Tabs, TextField, Typography } from "@mui/material";
import { useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api } from "../api";
import type { Interface } from "../types";
import { Badge, Card, DataTable, Todo, ErrorNotice } from "../ui";

type Editable = Interface & { key: string };

const ZONES = ["wan", "lan", "guest", "iot", "vpn"];

const emptyInterface = (key: string): Editable => ({
  key,
  name: "",
  type: "physical",
  zone: null,
  addresses: [],
  parent: null,
  vlan_id: null,
  members: [],
});

export default function Network() {
  const { configuration: c, version, saveDraft, draftDirty } = useConfiguration();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "interfaces";
  const knownTab = ["interfaces", "wan", "routes", "diagnostics"].includes(tab)
    ? tab
    : "interfaces";

  // Локальная редактируемая копия; сохраняется только по кнопке «Сохранить черновик».
  const [editing, setEditing] = useState<Editable[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const rows: Editable[] = editing ?? c.interfaces.map((i) => ({ ...i, key: i.name }));
  const isEditMode = editing !== null;

  const setField = (key: string, patch: Partial<Editable>) =>
    setEditing(rows.map((i) => (i.key === key ? { ...i, ...patch } : i)));

  const addRow = () => setEditing([...rows, emptyInterface(`new-${Date.now()}`)]);
  const removeRow = (key: string) => setEditing(rows.filter((i) => i.key !== key));

  const save = async () => {
    if (!version) return;
    setSaving(true);
    setError(null);
    try {
      const interfaces: Interface[] = rows.map(({ key: _key, ...rest }) => ({
        ...rest,
        name: rest.name.trim(),
        addresses: rest.addresses.filter((a) => a.trim()),
        members: rest.members.filter((m) => m.trim()),
      }));
      await saveDraft({ ...c, interfaces });
      setEditing(null);
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  };

  const nameValid = (i: Editable) =>
    /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(i.name.trim());
  const allValid = rows.every((i) => nameValid(i));

  return (
    <>
      <Typography component="h1" variant="h1" className="page-title">
        Сеть
      </Typography>
      <Tabs
        value={knownTab}
        onChange={(_, value: string) => setParams({ tab: value })}
        variant="scrollable"
      >
        {[
          ["interfaces", "Интерфейсы"],
          ["wan", "WAN-адреса"],
          ["routes", "Статические маршруты"],
          ["diagnostics", "Диагностика"],
        ].map(([value, label]) => (
          <Tab key={value} value={value} label={label} />
        ))}
      </Tabs>

      {knownTab === "interfaces" && (
        <>
          <ErrorNotice error={error} />
          <Card
            title="Интерфейсы и зоны"
            action={
              isEditMode ? undefined : (
                <Button size="small" onClick={() => setEditing(rows)}>
                  Редактировать
                </Button>
              )
            }
          >
            {!isEditMode && (
              <p className="sub">
                {version?.status === "draft"
                  ? `Черновик v${version.id} — нажмите «Редактировать», чтобы изменить.`
                  : "Применённая конфигурация. Изменения потребуют создания черновика."}
              </p>
            )}
            <DataTable
              heads={
                isEditMode
                  ? ["Интерфейс", "Тип", "Зона", "Адреса (через запятую)", "VLAN ID", "Члены бриджа", ""]
                  : ["Интерфейс", "Тип", "Зона", "Адресация", "IP-адрес", "Состояние", "Назначение"]
              }
              rows={
                isEditMode
                  ? rows.map((i) => [
                      <TextField
                        size="small"
                        value={i.name}
                        error={i.name.length > 0 && !nameValid(i)}
                        helperText={
                          i.name.length > 0 && !nameValid(i)
                            ? "латиница/цифры/._- до 15 симв."
                            : undefined
                        }
                        onChange={(e) => setField(i.key, { name: e.target.value })}
                      />,
                      <TextField
                        select
                        size="small"
                        value={i.type}
                        SelectProps={{ native: true }}
                        onChange={(e) =>
                          setField(i.key, { type: e.target.value as Interface["type"] })
                        }
                      >
                        <option value="physical">physical</option>
                        <option value="bridge">bridge</option>
                        <option value="vlan">vlan</option>
                      </TextField>,
                      <TextField
                        select
                        size="small"
                        value={i.zone ?? ""}
                        SelectProps={{ native: true }}
                        onChange={(e) =>
                          setField(i.key, { zone: e.target.value || null })
                        }
                      >
                        <option value="">— (fail-closed)</option>
                        {ZONES.map((z) => (
                          <option key={z} value={z}>
                            {z}
                          </option>
                        ))}
                      </TextField>,
                      <TextField
                        size="small"
                        fullWidth
                        value={i.addresses.join(", ")}
                        placeholder="192.168.10.1/24, 192.168.10.20/32"
                        onChange={(e) =>
                          setField(i.key, {
                            addresses: e.target.value.split(",").map((a) => a.trim()),
                          })
                        }
                      />,
                      i.type === "vlan" ? (
                        <TextField
                          size="small"
                          type="number"
                          value={i.vlan_id ?? ""}
                          onChange={(e) =>
                            setField(i.key, {
                              vlan_id: Number(e.target.value) || null,
                            })
                          }
                        />
                      ) : (
                        "—"
                      ),
                      i.type === "bridge" ? (
                        <TextField
                          size="small"
                          fullWidth
                          value={i.members.join(", ")}
                          placeholder="eth2, eth3"
                          onChange={(e) =>
                            setField(i.key, {
                              members: e.target.value.split(",").map((m) => m.trim()),
                            })
                          }
                        />
                      ) : (
                        "—"
                      ),
                      <Button
                        size="small"
                        color="error"
                        onClick={() => removeRow(i.key)}
                      >
                        Удалить
                      </Button>,
                    ])
                  : c.interfaces.map((i) => [
                      <b>{i.name}</b>,
                      {
                        physical: "Физический",
                        bridge: "Мост",
                        vlan: `VLAN (${i.parent}.${i.vlan_id})`,
                      }[i.type],
                      <Badge
                        tone={
                          i.zone === "wan"
                            ? "red"
                            : i.zone === "iot"
                              ? "purple"
                              : i.zone === "guest"
                                ? "amber"
                                : "blue"
                        }
                      >
                        {i.zone ?? "без зоны (fail-closed)"}
                      </Badge>,
                      i.addresses.length ? "Статический" : "—",
                      i.addresses.join(", "),
                      "TODO-API",
                      i.zone ? i.members.join(", ") : "Транзит запрещён",
                    ])
              }
            />
            {isEditMode && (
              <div className="footer-actions">
                <Button size="small" onClick={addRow}>
                  + Добавить интерфейс
                </Button>
                <span className="spacer" />
                <Button size="small" onClick={() => setEditing(null)}>
                  Отмена
                </Button>
                <Button
                  size="small"
                  variant="contained"
                  disabled={saving || !allValid}
                  onClick={() => void save()}
                >
                  {saving ? "Сохранение…" : "Сохранить черновик"}
                </Button>
              </div>
            )}
          </Card>
          {draftDirty && version?.status === "draft" && (
            <p className="sub">
              Черновик изменён и ожидает применения (экран «Применение»).
            </p>
          )}
        </>
      )}

      {knownTab === "wan" && (
        <>
          {c.interfaces
            .filter((i) => i.zone === "wan")
            .map((i) => (
              <Card key={i.name} title={`WAN-адреса: ${i.name}`}>
                <DataTable
                  heads={["Порядок", "Адрес", "Роль", "Использование"]}
                  rows={i.addresses.map((a, index) => [
                    index + 1,
                    a,
                    <Badge tone={index ? "purple" : "blue"}>
                      {index ? "дополнительный" : "основной"}
                    </Badge>,
                    index
                      ? "Firewall, port forward, outbound NAT"
                      : "default исходящий трафик, masquerade",
                  ])}
                />
                <p className="sub">
                  Дополнительные адреса — обычные адреса интерфейса. Все адреса
                  равноценны в firewall и NAT. Редактирование — на вкладке
                  «Интерфейсы».
                </p>
              </Card>
            ))}
          {!c.interfaces.some((i) => i.zone === "wan") && (
            <Card title="WAN-адреса">
              <Todo>Нет интерфейсов в зоне wan.</Todo>
            </Card>
          )}
        </>
      )}

      {knownTab === "routes" && (
        <Card title="Статические маршруты">
          <Todo>Маршруты отсутствуют в текущей модели API.</Todo>
          <DataTable
            heads={["Сеть назначения", "Шлюз", "Интерфейс", "Метрика"]}
            rows={[]}
          />
        </Card>
      )}

      {knownTab === "diagnostics" && (
        <Card title="Диагностика (последние запуски)">
          <Todo />
          <DataTable
            heads={["Время", "Тип", "Интерфейс", "Цель", "Результат"]}
            rows={diagnostics.map((d) => [
              d.time,
              d.kind,
              d.interface,
              d.target,
              <Badge tone={d.success ? "green" : "red"}>{d.result}</Badge>,
            ])}
          />
        </Card>
      )}
    </>
  );
}
interface Diagnostic {
  time: string;
  kind: string;
  interface: string;
  target: string;
  result: string;
  success: boolean;
}
const diagnostics: Diagnostic[] = [
  {
    time: "14:18:02",
    kind: "ping",
    interface: "br0",
    target: "192.168.10.45",
    result: "ok · 1.2 мс",
    success: true,
  },
  {
    time: "14:10:11",
    kind: "ping",
    interface: "eth1",
    target: "203.0.113.1",
    result: "timeout",
    success: false,
  },
];
