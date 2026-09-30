import { useEffect, useState } from "react";
import { Button, Tab, Tabs, TextField, Typography } from "@mui/material";
import { useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api } from "../api";
import type { HostInterface, Interface } from "../types";
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
  const { configuration: c, version, saveDraft, draftDirty, setNotice } =
    useConfiguration();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "interfaces";
  const knownTab = ["interfaces", "wan", "routes", "diagnostics"].includes(tab)
    ? tab
    : "interfaces";

  // Локальная редактируемая копия; сохраняется только по кнопке «Сохранить».
  const [editing, setEditing] = useState<Editable[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const [hostInterfaces, setHostInterfaces] = useState<HostInterface[]>([]);
  const [hostError, setHostError] = useState<unknown>(null);
  useEffect(() => {
    let active = true;
    api.hostInterfaces().then(
      (interfaces) => { if (active) setHostInterfaces(interfaces); },
      (err: unknown) => { if (active) setHostError(err); },
    );
    return () => { active = false; };
  }, []);
  const physicalNics = hostInterfaces.filter((i) => i.kind === "physical");
  const allRealNics = hostInterfaces;

  const rows: Editable[] = editing ?? c.interfaces.map((i) => ({ ...i, key: i.name }));
  const isEditMode = editing !== null;

  const candidates = (i: Editable, host: HostInterface[]) =>
    [...new Set([
      ...rows.filter((p) => p.key !== i.key && p.type === "physical").map((p) => p.name),
      ...host.map((p) => p.name),
    ])].filter((name) => name && name !== i.name);

  const setField = (key: string, patch: Partial<Editable>) => {
    const updated = rows.map((i) => (i.key === key ? { ...i, ...patch } : i));
    // References must also exist in the draft; zones remain explicitly assigned.
    for (const name of [patch.parent, ...(patch.members ?? [])]) {
      if (name && !updated.some((i) => i.name === name))
        updated.push({ ...emptyInterface(`host-${name}`), name });
    }
    setEditing(updated);
  };

  const addVirtual = (type: "vlan" | "bridge", parent: string | null = null) => {
    const prefix = type === "vlan" ? "vlan" : "br";
    let id = 1;
    while ([...rows, ...allRealNics].some((i) => i.name === `${prefix}${id}`)) id++;
    const next = [...rows];
    if (parent && !next.some((i) => i.name === parent))
      next.push({ ...emptyInterface(`host-${parent}`), name: parent });
    next.push({ ...emptyInterface(`new-${Date.now()}`), name: `${prefix}${id}`,
      type, parent, vlan_id: type === "vlan" ? 1 : null });
    setEditing(next);
  };

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
      const saved = await saveDraft({ ...c, interfaces });
      setNotice(`Черновик v${saved.id} сохранён`);
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
          <ErrorNotice error={hostError} />
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
                        select
                        SelectProps={{ native: true }}
                        value={i.name}
                        error={i.name.length > 0 && !nameValid(i)}
                        helperText={
                          i.name.length > 0 && !nameValid(i)
                            ? "латиница/цифры/._- до 15 симв."
                            : undefined
                        }
                        onChange={(e) => setField(i.key, { name: e.target.value })}
                      >
                        <option value="">— выберите интерфейс —</option>
                        {i.name && !allRealNics.some((p) => p.name === i.name) && (
                          <option value={i.name} disabled={i.type === "physical"}>
                            {i.name} ({i.type === "physical" ? "нет в ОС" : "в черновике"})
                          </option>
                        )}
                        {allRealNics.map((p) => (
                          <option key={p.name} value={p.name}>{p.name} ({p.operstate})</option>
                        ))}
                      </TextField>,
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
                      i.type === "vlan" ? (
                        <TextField
                          size="small"
                          select
                          SelectProps={{ native: true }}
                          value={i.parent ?? ""}
                          onChange={(e) => setField(i.key, { parent: e.target.value || null })}
                        >
                          <option value="">— выберите —</option>
                          {candidates(i, physicalNics).map((name) => (
                            <option key={name} value={name}>{name}</option>
                          ))}
                        </TextField>
                      ) : (
                        "—"
                      ),
                      i.type === "bridge" ? (
                        <div className="members-edit">
                          {i.members.map((m, index) => {
                            const member = rows.find(
                              (p) => p.key !== i.key && p.name === m,
                            );
                            return (
                              <div key={m + index} className="members-row">
                                <TextField
                                  select
                                  size="small"
                                  SelectProps={{ native: true }}
                                  value={m}
                                  error={!m || !member || !member.zone}
                                  onChange={(e) =>
                                    setField(i.key, {
                                      members: i.members.map((row, r) =>
                                        r === index ? e.target.value : row,
                                      ),
                                    })
                                  }
                                >
                                  <option value="">— выберите —</option>
                                  {candidates(i, allRealNics)
                                    .filter((name) => name === m || !i.members.includes(name))
                                    .map((name) => (
                                      <option key={name} value={name}>
                                        {name}
                                        {rows.find((p) => p.name === name)?.zone ? "" : " (без зоны!)"}
                                      </option>
                                    ))}
                                </TextField>
                                <Button
                                  size="small"
                                  color="error"
                                  onClick={() =>
                                    setField(i.key, {
                                      members: i.members.filter(
                                        (_, r) => r !== index,
                                      ),
                                    })
                                  }
                                >
                                  ✕
                                </Button>
                              </div>
                            );
                          })}
                          {candidates(i, allRealNics).some((name) => !i.members.includes(name)) && (
                            <Button
                              size="small"
                              onClick={() => {
                                const free = candidates(i, allRealNics).find(
                                  (name) => !i.members.includes(name),
                                );
                                if (free)
                                  setField(i.key, {
                                    members: [...i.members, free],
                                  });
                              }}
                            >
                              + участник
                            </Button>
                          )}
                        </div>
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
                {physicalNics.map((p) => (
                  <Button key={p.name} size="small" onClick={() => addVirtual("vlan", p.name)}>
                    + VLAN на {p.name}
                  </Button>
                ))}
                <Button size="small" onClick={() => addVirtual("bridge")}>
                  + Мост
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
                  {saving ? "Сохранение…" : "Сохранить"}
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
