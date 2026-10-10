import { Button } from "@mui/material";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { api } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import type { HostInterface, Interface, StaticRoute } from "../types";
import { Badge } from "../components/Badge";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { DeleteButton } from "../components/DeleteButton";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { QuickConnectDialog } from "../components/QuickConnectDialog";
import { EditorFooter } from "../components/EditorShell";
import { FormActions, FormGrid, FormWide } from "../components/Form";
import { InfoNote } from "../components/InfoNote";
import { InlineStatus } from "../components/InlineStatus";
import { ValueTabs } from "../components/Tabs";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { PageHeader } from "../components/PageHeader";
import { Field } from "../components/Field";
import { Select, InterfaceSelect, type SelectOption } from "../components/Select";
import { Toggle } from "../components/Toggle";
import { addressValid, ifaceNameValid, ipValid, secretValid } from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";
import { SecretField } from "./ConnectionEditors";

type Editable = Interface & { key: string };

const ZONES = ["wan", "lan", "guest", "iot", "vpn"];

function destinationValid(value: string): boolean {
  if (!value.includes("/") || !addressValid(value)) return false;
  const [ip, length] = value.split("/");
  if (ip.includes(":")) return true; // The server checks canonical IPv6 network alignment.
  const bits = Number(length);
  const address = ip.split(".").reduce((n, octet) => (n << 8) | Number(octet), 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (address & mask) >>> 0 === address;
}

function StaticRoutes({ configuration: c }: { configuration: ReturnType<typeof useConfiguration>["configuration"] }) {
  const editor = useDraftEditor<StaticRoute[]>();
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [deleteIndex, setDeleteIndex] = useState<number | null>(null);
  const routes = editor.value ?? c.static_routes ?? [];
  const selected = selectedIndex === null ? null : routes[selectedIndex] ?? null;
  const valid = routes.every((route) => destinationValid(route.destination.trim()) &&
    c.interfaces.some((i) => i.name === route.interface && !!i.zone) &&
    (!route.gateway || ipValid(route.gateway.trim())) &&
    Number.isInteger(route.metric) && route.metric >= 0);
  const open = (index: number) => {
    if (!editor.isEdit) editor.begin([...routes]);
    setSelectedIndex(index);
  };
  const add = () => {
    const next = [...routes, { destination: "", interface: "", gateway: null, metric: 0, enabled: true }];
    if (editor.isEdit) editor.setValue(next);
    else editor.begin(next);
    setSelectedIndex(next.length - 1);
  };
  const update = (patch: Partial<StaticRoute>) => {
    if (selectedIndex === null) return;
    editor.setValue(routes.map((r, index) => index === selectedIndex ? { ...r, ...patch } : r));
  };
  const cancel = () => { editor.cancel(); setSelectedIndex(null); };
  const save = async () => {
    await editor.save((value) => ({ ...c, static_routes: value.map((r) => ({
      ...r, destination: r.destination.trim(), gateway: r.gateway?.trim() || null,
    })) }));
    // The hook owns persistence and errors; keep selection only while editing.
  };
  return <>
    <ErrorNotice error={editor.error} />
    <Card title="Статические маршруты" action={<Button onClick={add}>Добавить маршрут</Button>}>
      {!routes.length ? <EmptyState>Статических маршрутов нет. Добавьте маршрут в черновик.</EmptyState> :
        <DataTable heads={["Куда", "Через шлюз", "Интерфейс", "Метрика", "Состояние", "Действия"]}
          rows={routes.map((r, index) => [
            r.destination || "Не указано", r.gateway || "Напрямую", r.interface || "Не выбран", r.metric,
            <Badge tone={r.enabled ? "blue" : "amber"}>{r.enabled ? "Включён в черновике" : "Выключен"}</Badge>,
            <><Button onClick={() => open(index)} aria-label={`Редактировать маршрут ${r.destination || index + 1}`}>Изменить</Button>
              <DeleteButton label={`Удалить маршрут ${r.destination || index + 1}`} onClick={() => setDeleteIndex(index)} /></>,
          ])} />}
      <InfoNote>Это настройки черновика, не состояние таблицы маршрутизации на устройстве. Сохранение не применяет изменения.</InfoNote>
    </Card>
    {editor.isEdit && <Card title={selected ? "Редактирование маршрута" : "Изменения маршрутов"}>
      {selected && <FormGrid>
        <Field label="Куда (CIDR)" value={selected.destination} required placeholder="192.0.2.0/24"
          valid={destinationValid(selected.destination)} hint="Сеть назначения с префиксом, например 192.0.2.0/24"
          onChange={(destination) => update({ destination })} />
        <InterfaceSelect label="Интерфейс" value={selected.interface} interfaces={c.interfaces.filter((i) => !!i.zone)}
          emptyLabel="Выберите интерфейс" error={!c.interfaces.some((i) => i.name === selected.interface && !!i.zone)}
          onChange={(value) => update({ interface: value })} />
        <Field label="Через шлюз" value={selected.gateway ?? ""} placeholder="Необязательно"
          valid={!selected.gateway || ipValid(selected.gateway.trim())} hint="IP-адрес; пусто — маршрут напрямую"
          onChange={(gateway) => update({ gateway: gateway || null })} />
        <Field label="Метрика" type="number" value={selected.metric} inputProps={{ min: 0, step: 1 }}
          valid={Number.isInteger(selected.metric) && selected.metric >= 0} hint="Неотрицательное целое число"
          onChange={(metric) => update({ metric: metric === "" ? 0 : Number(metric) })} />
        <FormWide><Toggle label="Включён" value={selected.enabled} onChange={(enabled) => update({ enabled })} /></FormWide>
      </FormGrid>}
      <EditorFooter saving={editor.saving} valid={valid} cancel={cancel} save={() => void save()} />
    </Card>}
    <ConfirmDialog open={deleteIndex !== null} title="Удалить маршрут?"
      body={`Маршрут ${deleteIndex === null ? "" : routes[deleteIndex]?.destination || "без назначения"} будет удалён из черновика после сохранения.`}
      confirmLabel="Удалить" cancelLabel="Отмена" danger
      onConfirm={() => {
        if (deleteIndex !== null) {
          const next = routes.filter((_, index) => index !== deleteIndex);
          if (editor.isEdit) editor.setValue(next);
          else editor.begin(next);
          if (selectedIndex !== null) setSelectedIndex(selectedIndex === deleteIndex ? null : selectedIndex > deleteIndex ? selectedIndex - 1 : selectedIndex);
        }
        setDeleteIndex(null);
      }} onCancel={() => setDeleteIndex(null)} />
  </>;
}

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
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState("general");
  const [deleteKey, setDeleteKey] = useState<string | null>(null);
  const [quickOpen, setQuickOpen] = useState(false);
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
  const selected = rows.find((i) => i.key === selectedKey) ?? null;
  useEffect(() => { if (!editor.isEdit && selectedKey) setSelectedKey(null); }, [editor.isEdit, selectedKey]);
  const open = (key: string) => {
    if (!editor.isEdit) editor.begin(rows);
    setSelectedKey(key);
    setDetailTab("general");
  };
  const cancel = () => { editor.cancel(); setSelectedKey(null); };

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
    const key = `new-${Date.now()}`;
    next.push({ ...emptyInterface(key), name: `${prefix}${id}`,
      type, parent, vlan_id: type === "vlan" ? 1 : null });
    if (editor.isEdit) editor.setValue(next);
    else editor.begin(next);
    setSelectedKey(key);
    setDetailTab("general");
  };

  const addQuick = (entry: Interface, references: string[]) => {
    const next = [...rows];
    for (const name of references) {
      if (!next.some((i) => i.name === name))
        next.push({ ...emptyInterface(`host-${name}`), name });
    }
    const key = `new-${Date.now()}`;
    next.push({ ...entry, key });
    if (editor.isEdit) editor.setValue(next);
    else editor.begin(next);
    setSelectedKey(key);
    setDetailTab("general");
  };

  const addRow = () => {
    const key = `new-${Date.now()}`;
    const next = [...rows, emptyInterface(key)];
    if (editor.isEdit) editor.setValue(next);
    else editor.begin(next);
    setSelectedKey(key);
    setDetailTab("general");
  };
  const removeRow = (i: Editable) => {
    try {
      editor.setValue(rows.filter((row) => row.key !== i.key));
      if (selectedKey === i.key) setSelectedKey(rows.find((row) => row.key !== i.key)?.key ?? i.key);
      setDeleteKey(null);
    } catch (error) {
      editor.setError(error);
    }
  };

  const save = async () => {
    await editor.save((value) => ({
      ...c,
      interfaces: value.map(({ key: _key, ...rest }) => ({
        ...rest,
        pppoe_username: rest.addressing === "pppoe" ? rest.pppoe_username?.trim() : undefined,
        pppoe_password: rest.addressing === "pppoe" ? rest.pppoe_password : undefined,
        name: rest.name.trim(),
        description: rest.description?.trim() || null,
        // A DHCP client owns no static address: never send the address a row
        // held before it was switched to DHCP (avoids interface.dhcp_with_addresses
        // and a stale-address conflict at apply time).
        addresses:
          rest.addressing !== "static"
            ? []
            : rest.addresses.filter((a) => a.trim()),
        members: rest.members.filter((m) => m.trim()),
      })),
    }));
  };

  const validName = (i: Editable) => ifaceNameValid(i.name.trim());
  const names = rows.map((i) => i.name.trim());
  const staticAddresses = rows.flatMap((i) => i.addressing === "static" ? i.addresses.map((a) => a.trim().toLowerCase()) : []);
  const allValid = new Set(names).size === names.length &&
    new Set(staticAddresses).size === staticAddresses.length &&
    rows.every((i) => validName(i) &&
      (i.addressing !== "static" || i.addresses.every((a) => a.includes("/") && addressValid(a.trim()))) &&
      (i.addressing !== "pppoe" || (i.type === "physical" && i.zone === "wan" && !i.parent && !i.members.length && !rows.some((other) => other.type === "vlan" && other.parent === i.name) && !!i.pppoe_username?.trim() && secretValid(i.pppoe_password ?? null) && !c.dhcp_subnets?.some((subnet) => subnet.interface === i.name))) &&
      (i.type !== "vlan" || (i.vlan_id !== null && Number.isInteger(i.vlan_id) && i.vlan_id >= 1 && i.vlan_id <= 4094)));

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

      {knownTab === "interfaces" && <>
        <ErrorNotice error={editor.error} /><ErrorNotice error={hostError} />
        <Card title="Интерфейсы и зоны" action={<FormActions><Button onClick={() => setQuickOpen(true)}>Быстро подключить</Button>{rows.length > 0 && <><Button onClick={addRow}>Добавить интерфейс</Button>{physicalNics.map((p) => <Button key={p.name} onClick={() => addVirtual("vlan", p.name)}>+ VLAN на {p.name}</Button>)}<Button onClick={() => addVirtual("bridge")}>+ Мост</Button></>}</FormActions>}>
          {!rows.length && <EmptyState action={<Button onClick={addRow}>Добавить интерфейс</Button>}>Нет назначенных интерфейсов</EmptyState>}
          {!!rows.length && <DataTable heads={["Название", "Системное имя", "Роль", "IP", "Черновик", "Состояние"]}
            rows={rows.map((i) => {
              const host = allRealNics.find((h) => h.name === i.name);
              const live = liveAddresses[i.name] ?? [];
              return [
                <Button onClick={() => open(i.key)}>{i.description?.trim() || "Без названия"}</Button>,
                i.name || "Не выбрано",
                <Badge tone={!i.zone ? "amber" : i.zone === "wan" ? "red" : "blue"}>{i.zone === "wan" ? "Интернет (WAN)" : i.zone === "lan" ? "Домашняя сеть (LAN)" : i.zone ? i.zone.toUpperCase() : "Не назначен"}</Badge>,
                i.addressing === "pppoe" ? <InlineStatus tone="unknown" text="PPPoE: состояние подключения недоступно" /> : i.addressing === "dhcp" ? <InlineStatus tone={hostAddresses.isPending || hostAddresses.isError ? "unknown" : live.length ? "green" : "amber"} text={hostAddresses.isPending ? "DHCP: загрузка" : hostAddresses.isError ? "DHCP: данные недоступны" : live.length ? `DHCP: ${live.join(", ")}` : "DHCP: адрес не получен"} /> : i.addresses.join(", ") || "Адрес не задан",
                <Badge tone={version?.status === "draft" || isEditMode ? "amber" : version ? "blue" : "amber"}>{version?.status === "draft" || isEditMode ? "Черновик" : version ? "Применено" : "Статус неизвестен"}</Badge>,
                hostInterfaces.isPending ? <InlineStatus tone="unknown" text="Состояние хоста: загрузка" /> : hostInterfaces.isError || !host ? <InlineStatus tone="unknown" text="Состояние хоста недоступно" /> : host.kind !== "physical" ? <InlineStatus tone="unknown" text={`Состояние ${host.operstate}; данные о кабеле недоступны`} /> : <InlineStatus tone={host.operstate === "UP" ? "green" : host.operstate === "DOWN" ? "red" : "unknown"} text={`Кабель: ${host.operstate === "UP" ? "подключён" : host.operstate === "DOWN" ? "отключён" : host.operstate}`} />,
              ];
            })} />}
        </Card>
        {(selected || isEditMode && selectedKey) && <Card title={`Интерфейс: ${selected?.description?.trim() || selected?.name || "удалён"}`} action={selected && <DeleteButton label={`Удалить интерфейс ${selected.name || "без имени"}`} onClick={() => setDeleteKey(selected.key)} />}>
          {selected && <ValueTabs value={detailTab} change={setDetailTab} tabs={[
            {value:"general",label:"Общие"},{value:"ip",label:"IP"},{value:"connection",label:"Подключение"},{value:"advanced",label:"Дополнительно"}
          ]} />}
          {selected && detailTab === "general" && <FormGrid>
            <Field label="Дружественное имя" value={selected.description ?? ""} placeholder="напр. «оптика провайдера»" maxLength={64} onChange={(v) => setField(selected.key,{description:v || null})} />
            <Select label="Системное имя" value={selected.name} error={!!selected.name && !validName(selected)} placeholder={{label:"— выберите интерфейс —"}} options={nameOptions(selected)} onChange={(name) => setField(selected.key,{name})} />
            <Field label="Описание" value={selected.description ?? ""} readOnly hint="Хранится как дружественное имя интерфейса." />
            <Select label="Тип" value={selected.type} options={[{value:"physical",label:"Физический"},{value:"bridge",label:"Мост"},{value:"vlan",label:"VLAN"}]} onChange={(v) => setField(selected.key,{type:v as Interface["type"], ...(selected.addressing === "pppoe" && v !== "physical" ? {addressing:"static",pppoe_username:undefined,pppoe_password:undefined} : {})})} />
            <Select label="Роль / зона" value={selected.zone ?? ""} placeholder={{label:"Не назначен — транзит запрещён"}} options={ZONES.map((z) => ({value:z,label:z === "wan" ? "Интернет (WAN)" : z === "lan" ? "Домашняя сеть (LAN)" : z.toUpperCase()}))} onChange={(v) => setField(selected.key,{zone:v || null, ...(selected.addressing === "pppoe" && v !== "wan" ? {addressing:"static",pppoe_username:undefined,pppoe_password:undefined} : {})})} />
            <Field label="MAC хоста" value={allRealNics.find((h) => h.name === selected.name)?.mac ?? "Данные недоступны"} readOnly />
            <FormWide><InfoNote>Без зоны транзит запрещён. Изменения вступят в силу только после применения черновика.</InfoNote></FormWide>
          </FormGrid>}
          {selected && detailTab === "ip" && <FormGrid>
            <Select label="Режим адресации" value={selected.addressing} options={[{value:"static",label:"Статический IP"},{value:"dhcp",label:"DHCP"},...(selected.type === "physical" && selected.zone === "wan" ? [{value:"pppoe",label:"PPPoE"}] : [])]} onChange={(v) => setField(selected.key,v === "pppoe" ? {addressing:"pppoe",addresses:[],parent:null,members:[]} : v === "dhcp" ? {addressing:"dhcp",addresses:[],pppoe_username:undefined,pppoe_password:undefined} : {addressing:"static",pppoe_username:undefined,pppoe_password:undefined})} />
            {selected.addressing === "pppoe" ? <>
              <Field label="Логин" value={selected.pppoe_username ?? ""} valid={!!selected.pppoe_username?.trim()} onChange={(v) => setField(selected.key,{pppoe_username:v})} />
              <SecretField key={selected.key} label="Пароль" value={selected.pppoe_password ?? null} change={(pppoe_password) => setField(selected.key,{pppoe_password})} />
            </> : <Field label="Основной адрес (CIDR)" value={selected.addressing === "dhcp" ? "" : selected.addresses[0] ?? ""} disabled={selected.addressing === "dhcp"} placeholder={selected.addressing === "dhcp" ? "адрес по DHCP" : "192.168.10.1/24"} valid={selected.addressing === "dhcp" || !selected.addresses.length || (selected.addresses[0].includes("/") && addressValid(selected.addresses[0]) && staticAddresses.filter((a) => a === selected.addresses[0].trim().toLowerCase()).length === 1)} hint="/24 = маска 255.255.255.0. Первый WAN-адрес основной для исходящего трафика." onChange={(v) => setField(selected.key,{addresses:[v,...selected.addresses.slice(1)]})} />}
            {selected.addressing === "static" && <FormWide>{selected.addresses.slice(1).map((address,index) => <FormActions key={index}><Field ariaLabel={`Дополнительный адрес ${index + 1} (CIDR)`} value={address} valid={address.includes("/") && addressValid(address) && staticAddresses.filter((a) => a === address.trim().toLowerCase()).length === 1} hint="Укажите уникальный IP/CIDR" onChange={(v) => setField(selected.key,{addresses:selected.addresses.map((a,n) => n === index + 1 ? v : a)})} /><DeleteButton label={`Удалить дополнительный адрес ${index + 1}`} onClick={() => setField(selected.key,{addresses:selected.addresses.filter((_,n) => n !== index + 1)})} /></FormActions>)}<Button onClick={() => setField(selected.key,{addresses:[...(selected.addresses.length ? selected.addresses : [""]),""]})}>Добавить адрес</Button></FormWide>}
            <FormWide><InfoNote>{selected.addressing === "dhcp" ? hostAddresses.isPending ? "Полученный адрес: загрузка…" : hostAddresses.isError ? "Полученный адрес: состояние недоступно" : `Полученный адрес: ${(liveAddresses[selected.name] ?? []).join(", ") || "адрес не получен"}` : selected.addressing === "pppoe" ? "PPPoE: запуск подключения после применения черновика." : "Статические адреса показаны из конфигурации."}</InfoNote></FormWide>
          </FormGrid>}
          {selected && detailTab === "connection" && <FormGrid>
            {selected.type === "vlan" && <><Select label="Родительский интерфейс" value={selected.parent ?? ""} placeholder={{label:"— выберите —"}} options={candidates(selected,physicalNics).filter((name) => name === selected.parent || !usedByOtherRows(selected).has(name)).map((name) => ({value:name,label:optLabel(name)}))} onChange={(v) => setField(selected.key,{parent:v || null})} /><Field label="VLAN ID" type="number" value={selected.vlan_id ?? ""} onChange={(v) => setField(selected.key,{vlan_id:Number(v) || null})} /></>}
            {selected.type === "bridge" && <FormWide>{selected.members.map((m,index) => <FormActions key={`${m}-${index}`}><Select ariaLabel={`Участник ${selected.key} ${index}`} value={m} error={!m || !rows.some((r) => r.key !== selected.key && r.name === m && r.zone)} placeholder={{label:"— выберите —"}} options={candidates(selected,allRealNics).filter((name) => selected.members.includes(name) || !usedByOtherRows(selected).has(name)).map((name) => ({value:name,label:optLabel(name)}))} onChange={(v) => setField(selected.key,{members:selected.members.map((row,r) => r === index ? v : row)})} /><DeleteButton label={`Удалить участника ${m}`} onClick={() => setField(selected.key,{members:selected.members.filter((_,r) => r !== index)})} /></FormActions>)}
              {candidates(selected,allRealNics).some((name) => !selected.members.includes(name) && !usedByOtherRows(selected).has(name)) && <Button onClick={() => {const free=candidates(selected,allRealNics).find((name) => !selected.members.includes(name) && !usedByOtherRows(selected).has(name));if(free)setField(selected.key,{members:[...selected.members,free]});}}>+ участник</Button>}
            </FormWide>}
            {selected.type === "physical" && <FormWide><InfoNote>Физический порт выбран на вкладке «Общие».</InfoNote></FormWide>}
          </FormGrid>}
          {selected && detailTab === "advanced" && <FormGrid><Field label="Родитель" value={selected.parent ?? "—"} readOnly /><Field label="Участники" value={selected.members.join(", ") || "—"} readOnly /><Field label="VLAN ID" value={selected.vlan_id ?? "—"} readOnly /><Field label="Состояние хоста" value={hostInterfaces.isPending ? "Загрузка…" : hostInterfaces.isError ? "Состояние недоступно" : allRealNics.find((h) => h.name === selected.name)?.operstate ?? "Данные недоступны"} readOnly /><FormWide><InfoNote>Первичный LAN и адрес панели не определяются по этой конфигурации. Проверьте доступ перед применением.</InfoNote></FormWide></FormGrid>}
          <EditorFooter saving={editor.saving} valid={allValid} cancel={cancel} save={() => void save()} />
        </Card>}
        {draftDirty && version?.status === "draft" && <p className="sub">Черновик изменён и ожидает применения (экран «Применение»).</p>}
        <QuickConnectDialog open={quickOpen} onClose={() => setQuickOpen(false)} onAdd={addQuick}
          ports={allRealNics} existing={rows} loading={hostInterfaces.isPending} unavailable={hostInterfaces.isError} />
        <ConfirmDialog open={deleteKey !== null} title="Удалить интерфейс?" body={`Интерфейс ${rows.find((i) => i.key === deleteKey)?.name || "без имени"} будет удалён из черновика. Проверьте зависимости и доступ к панели перед применением.`} confirmLabel="Удалить" cancelLabel="Отмена" danger onConfirm={() => {const target=rows.find((i) => i.key === deleteKey);if(target)removeRow(target);}} onCancel={() => setDeleteKey(null)} />
      </>}

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

      {knownTab === "routes" && <StaticRoutes configuration={c} />}

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
