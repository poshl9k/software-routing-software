import { Button } from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import type { HostInterface, Interface } from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ValueTabs } from "../components/Tabs";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { PageHeader } from "../components/PageHeader";
import { Field } from "../components/Field";
import { Select, type SelectOption } from "../components/Select";
import { ifaceNameValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";

type Editable = Interface & { key: string };

const ZONES = ["wan", "lan", "guest", "iot", "vpn"];

const emptyInterface = (key: string): Editable => ({
  key,
  name: "",
  type: "physical",
  zone: null,
  description: null,
  addressing: "static",
  addresses: [],
  parent: null,
  vlan_id: null,
  members: [],
});

export default function Network() {
  const { configuration: c, version, draftDirty } = useConfiguration();
  const editor = useDraftEditor<Editable[]>();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "interfaces";
  const knownTab = ["interfaces", "wan", "routes", "diagnostics"].includes(tab)
    ? tab
    : "interfaces";

  const hostInterfaces = useQuery({ queryKey: queryKeys.hostInterfaces(), queryFn: api.hostInterfaces });
  const hostError = hostInterfaces.error;
  const allRealNics = Array.isArray(hostInterfaces.data) ? hostInterfaces.data : [];
  const physicalNics = allRealNics.filter((i) => i.kind === "physical");

  const rows: Editable[] = editor.value ?? c.interfaces.map((i) => ({ ...i, key: i.name }));
  const isEditMode = editor.isEdit;

  const candidates = (i: Editable, host: HostInterface[]) =>
    [...new Set([
      ...rows.filter((p) => p.key !== i.key && p.type === "physical").map((p) => p.name),
      ...host.map((p) => p.name),
    ])].filter((name) => name && name !== i.name);

  // Имена интерфейсов, уже занятые другими строками конфигурации.
  const usedByOtherRows = (i: Editable) =>
    new Set(rows.filter((r) => r.key !== i.key && r.name).map((r) => r.name));

  // Текст опции: имя плюс описание из строки черновика.
  const optLabel = (name: string) => {
    const description = rows.find((r) => r.name === name)?.description?.trim();
    return description ? `${name} — ${description}` : name;
  };

  // Живые адреса с хоста: что реально получил интерфейс (важно для DHCP).
  const hostAddresses = useQuery({
    queryKey: queryKeys.hostAddresses(),
    queryFn: api.hostAddresses,
    enabled: !isEditMode,
  });
  const liveAddresses = hostAddresses.data ?? {};

  const setField = (key: string, patch: Partial<Editable>) => {
    const updated = rows.map((i) => (i.key === key ? { ...i, ...patch } : i));
    // References must also exist in the draft; zones remain explicitly assigned.
    for (const name of [patch.parent, ...(patch.members ?? [])]) {
      if (name && !updated.some((i) => i.name === name))
        updated.push({ ...emptyInterface(`host-${name}`), name });
    }
    editor.setValue(updated);
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
    editor.setValue(next);
  };

  const addRow = () => editor.setValue([...rows, emptyInterface(`new-${Date.now()}`)]);
  const removeRow = (i: Editable) => {
    if (!window.confirm(`Удалить интерфейс ${i.name || "без имени"} (зона: ${i.zone ?? "без зоны"})?`)) return;
    try {
      editor.setValue(rows.filter((row) => row.key !== i.key));
    } catch (error) {
      editor.setError(error);
    }
  };

  const save = async () => {
    await editor.save((value) => ({
      ...c,
      interfaces: value.map(({ key: _key, ...rest }) => ({
        ...rest,
        name: rest.name.trim(),
        description: rest.description?.trim() || null,
        // A DHCP client owns no static address: never send the address a row
        // held before it was switched to DHCP (avoids interface.dhcp_with_addresses
        // and a stale-address conflict at apply time).
        addresses:
          rest.addressing === "dhcp"
            ? []
            : rest.addresses.filter((a) => a.trim()),
        members: rest.members.filter((m) => m.trim()),
      })),
    }));
  };

  const validName = (i: Editable) => ifaceNameValid(i.name.trim());
  const allValid = rows.every(validName);

  const nameOptions = (i: Editable): SelectOption[] => {
    const options: SelectOption[] = [];
    if (i.name && !allRealNics.some((p) => p.name === i.name))
      options.push({
        value: i.name,
        label: `${optLabel(i.name)} (${i.type === "physical" ? "нет в ОС" : "в черновике"})`,
        disabled: i.type === "physical",
      });
    for (const p of allRealNics.filter((p) => !usedByOtherRows(i).has(p.name)))
      options.push({ value: p.name, label: `${p.name} (${p.operstate})` });
    return options;
  };

  return (
    <>
      <PageHeader>Сеть</PageHeader>
      <ValueTabs
        value={knownTab}
        change={(value) => setParams({ tab: value })}
        tabs={[
          { value: "interfaces", label: "Интерфейсы" },
          { value: "wan", label: "WAN-адреса" },
          { value: "routes", label: "Статические маршруты" },
          { value: "diagnostics", label: "Диагностика" },
        ]}
      />

      {knownTab === "interfaces" && (
        <>
          <ErrorNotice error={editor.error} />
          <ErrorNotice error={hostError} />
          <Card
            title="Интерфейсы и зоны"
            action={
              isEditMode ? undefined : (
                <Button size="small" onClick={() => editor.begin(rows)}>
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
                  ? ["Интерфейс", "Описание", "Тип", "Зона", "Режим", "Адреса (через запятую)", "VLAN ID", "Родитель / члены", ""]
                  : ["Интерфейс", "Описание", "Тип", "Зона", "Адресация", "IP-адрес", "Состояние", "Назначение"]
              }
              rows={
                isEditMode
                  ? rows.map((i) => [
                      <Select
                        ariaLabel={`Интерфейс ${i.key}`}
                        value={i.name}
                        sx={{ minWidth: 170 }}
                        error={i.name.length > 0 && !validName(i)}
                        helperText={
                          i.name.length > 0 && !validName(i)
                            ? "латиница/цифры/._- до 15 симв."
                            : undefined
                        }
                        placeholder={{ label: "— выберите интерфейс —" }}
                        options={nameOptions(i)}
                        onChange={(name) => setField(i.key, { name })}
                      />,
                      <Field
                        value={i.description ?? ""}
                        ariaLabel={`Описание интерфейса ${i.key}`}
                        placeholder="напр. «оптика провайдера»"
                        maxLength={64}
                        onChange={(v) =>
                          setField(i.key, { description: v || null })
                        }
                      />,
                      <Select
                        ariaLabel={`Тип ${i.key}`}
                        value={i.type}
                        options={[
                          { value: "physical", label: "physical" },
                          { value: "bridge", label: "bridge" },
                          { value: "vlan", label: "vlan" },
                        ]}
                        onChange={(v) =>
                          setField(i.key, { type: v as Interface["type"] })
                        }
                      />,
                      <Select
                        ariaLabel={`Зона ${i.key}`}
                        value={i.zone ?? ""}
                        placeholder={{ label: "— (fail-closed)" }}
                        options={ZONES.map((z) => ({ value: z, label: z }))}
                        onChange={(v) => setField(i.key, { zone: v || null })}
                      />,
                      <Select
                        ariaLabel={`Режим ${i.key}`}
                        value={i.addressing}
                        options={[
                          { value: "static", label: "static" },
                          { value: "dhcp", label: "DHCP" },
                        ]}
                        onChange={(v) =>
                          setField(
                            i.key,
                            v === "dhcp"
                              ? { addressing: "dhcp", addresses: [] }
                              : { addressing: "static" },
                          )
                        }
                      />,
                      <Field
                        value={i.addressing === "dhcp" ? "" : i.addresses.join(", ")}
                        ariaLabel={`Адреса ${i.key}`}
                        disabled={i.addressing === "dhcp"}
                        placeholder={i.addressing === "dhcp" ? "адрес по DHCP" : "192.168.10.1/24, 192.168.10.20/32"}
                        onChange={(v) =>
                          setField(i.key, {
                            addresses: v.split(",").map((a) => a.trim()),
                          })
                        }
                      />,
                      i.type === "vlan" ? (
                        <Field
                          type="number"
                          ariaLabel={`VLAN ID ${i.key}`}
                          value={i.vlan_id ?? ""}
                          onChange={(v) =>
                            setField(i.key, { vlan_id: Number(v) || null })
                          }
                        />
                      ) : (
                        "—"
                      ),
                      i.type === "vlan" ? (
                        <Select
                          ariaLabel={`Родитель ${i.key}`}
                          value={i.parent ?? ""}
                          placeholder={{ label: "— выберите —" }}
                          options={candidates(i, physicalNics)
                            .filter((name) => name === i.parent || !usedByOtherRows(i).has(name))
                            .map((name) => ({ value: name, label: optLabel(name) }))}
                          onChange={(v) => setField(i.key, { parent: v || null })}
                        />
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
                                <Select
                                  ariaLabel={`Участник ${i.key} ${index}`}
                                  value={m}
                                  error={!m || !member || !member.zone}
                                  placeholder={{ label: "— выберите —" }}
                                  options={candidates(i, allRealNics)
                                    .filter((name) => i.members.includes(name) || (!i.members.includes(name) && !usedByOtherRows(i).has(name)))
                                    .map((name) => ({
                                      value: name,
                                      label: `${optLabel(name)}${rows.find((p) => p.name === name)?.zone ? "" : " (без зоны!)"}`,
                                    }))}
                                  onChange={(v) =>
                                    setField(i.key, {
                                      members: i.members.map((row, r) =>
                                        r === index ? v : row,
                                      ),
                                    })
                                  }
                                />
                                <DeleteButton
                                  label={`Удалить участника ${m}`}
                                  onClick={() =>
                                    setField(i.key, {
                                      members: i.members.filter(
                                        (_, r) => r !== index,
                                      ),
                                    })
                                  }
                                />
                              </div>
                            );
                          })}
                          {candidates(i, allRealNics).some((name) => !i.members.includes(name) && !usedByOtherRows(i).has(name)) && (
                            <Button
                              size="small"
                              onClick={() => {
                                const free = candidates(i, allRealNics).find(
                                  (name) => !i.members.includes(name) && !usedByOtherRows(i).has(name),
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
                      <DeleteButton
                        label={`Удалить интерфейс ${i.name}`}
                        onClick={() => removeRow(i)}
                      />,
                    ])
                  : c.interfaces.map((i) => [
                      <b>{i.name}</b>,
                      i.description ? (
                        <span className="sub">{i.description}</span>
                      ) : (
                        <span className="sub">—</span>
                      ),
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
                      i.addressing === "dhcp" ? "DHCP" : "Статический",
                      i.addressing === "dhcp"
                        ? ((liveAddresses[i.name] ?? []).join(", ") || "ожидание…")
                        : i.addresses.join(", "),
                      i.addressing === "dhcp"
                        ? ((liveAddresses[i.name] ?? []).length ? "адрес получен" : "нет адреса")
                        : "—",
                      i.type === "vlan"
                        ? `на ${i.parent ?? "—"}`
                        : i.zone
                          ? i.members.join(", ")
                          : "Транзит запрещён",
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
                <Button size="small" onClick={editor.cancel}>
                  Отмена
                </Button>
                <Button
                  size="small"
                  variant="contained"
                  disabled={editor.saving || !allValid}
                  onClick={() => void save()}
                >
                  {editor.saving ? "Сохранение…" : "Сохранить"}
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
              <EmptyState>Нет интерфейсов в зоне wan.</EmptyState>
            </Card>
          )}
        </>
      )}

      {knownTab === "routes" && (
        <Card title="Статические маршруты">
          <EmptyState>Статические маршруты пока нельзя настроить в панели</EmptyState>
        </Card>
      )}

      {knownTab === "diagnostics" && (
        <Card title="Диагностика">
          <EmptyState
            action={<Button component={Link} to="/maintenance">Перейти в «Обслуживание»</Button>}
          >
            Диагностика доступна в разделе «Обслуживание». История запусков пока не сохраняется.
          </EmptyState>
        </Card>
      )}
    </>
  );
}