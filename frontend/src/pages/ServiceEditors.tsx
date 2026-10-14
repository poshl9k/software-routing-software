import { useState, type ReactNode } from "react";
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from "@mui/material";
import type { DHCPSubnet, Reservation, DNS as DNSConfig, DNSUpstream } from "../types";
import { useConfiguration } from "../state";
import { DataTable } from "../components/DataTable";
import { ErrorNotice } from "../components/ErrorNotice";
import { DeleteButton } from "../components/DeleteButton";
import { EditorFooter } from "../components/EditorShell";
import { Field } from "../components/Field";
import { FormGrid } from "../components/Form";
import { PageSection } from "../components/PageSection";
import { Select, SelectField, InterfaceSelect } from "../components/Select";
import { InfoNote } from "../components/InfoNote";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Toggle } from "../components/Toggle";
import {
  ipValid,
  addressValid,
  domainValid,
  lines,
  listValid,
  macValid,
} from "../components/validators";
import { useDraftEditor } from "../hooks/useDraftEditor";

const ipv4 = (v: string) => ipValid(v) && !v.includes(":");
const integer = (v: number) => Number.isInteger(v) && v > 0;
const ipNumber = (v: string) =>
  v.split(".").reduce((n, p) => n * 256 + Number(p), 0);
const poolValid = (p: { start: string; end: string }) =>
  ipv4(p.start) && ipv4(p.end) && ipNumber(p.start) <= ipNumber(p.end);
const normalize = (v: string[]) => lines(v.join("\n"));
const upstreamModes = [
  { value: "udp", label: "UDP" },
  { value: "tls", label: "DoT" },
  { value: "https", label: "DoH" },
] as const satisfies readonly { value: "udp" | "tls" | "https"; label: string }[];

const normalizeUpstreamOnModeChange = (
  u: DNSUpstream,
  mode: "udp" | "tls" | "https",
): DNSUpstream => {
  switch (mode) {
    case "https":
      return { ...u, mode, address: "", port: 53, tls_name: null, doh_server: u.doh_server ?? "" };
    case "tls":
      return { ...u, mode, address: u.address, port: u.port, tls_name: u.tls_name ?? "", doh_server: null };
    default:
      return { ...u, mode, address: u.address, port: u.port, tls_name: null, doh_server: null };
  }
};

const newUpstreamRow = (mode: "udp" | "tls" | "https"): DNSUpstream => ({
  address: "",
  port: 53,
  mode,
  tls_name: null,
  doh_server: null,
});

/** Structured DNS upstream list with a separate editor for each server. */
function UpstreamRows({ upstreams, onChange, saving, valid, cancel, save, error }: {
  upstreams: DNSUpstream[];
  onChange: (upstreams: DNSUpstream[]) => void;
  saving: boolean; valid: boolean; cancel: () => void; save: () => void; error: unknown;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const u = selected === null ? null : upstreams[selected];
  const updateUp = (v: Partial<DNSUpstream>) => {
    if (selected === null) return;
    onChange(upstreams.map((row, i) => i === selected ? { ...row, ...v } : row));
  };
  return <>
    <DataTable heads={["Адрес", "Транспорт", "Действия"]} rows={upstreams.map((row, index) => [
      row.mode === "https" ? row.doh_server || "Новый сервер" : row.address || "Новый сервер",
      row.mode === "udp" ? "UDP" : row.mode === "tls" ? "DoT" : "DoH",
      <Button onClick={() => setSelected(index)}>Изменить</Button>,
    ])} />
    <Button onClick={() => { onChange([...upstreams, newUpstreamRow("udp")]); setSelected(upstreams.length); }}>Добавить DNS-сервер</Button>
    <Dialog open={!!u} onClose={saving ? undefined : () => setSelected(null)} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>DNS-сервер: {u?.mode === "https" ? u.doh_server || "Новый сервер" : u?.address || "Новый сервер"}</span>
        {u && <DeleteButton label={`Удалить upstream ${selected! + 1}`} onClick={() => { onChange(upstreams.filter((_, i) => i !== selected)); setSelected(null); }} />}
      </DialogTitle>
      <DialogContent>
        <ErrorNotice error={error} />
        {u && <>
          <PageSection title="Идентификация"><FormGrid>
            {u.mode === "https" ? <Field label="Сервер DoH (dnscrypt-proxy)" value={u.doh_server ?? ""} valid={!!u.doh_server} onChange={(doh_server) => updateUp({ doh_server: doh_server || null })} />
              : <Field label="Адрес DNS-сервера" value={u.address} valid={ipValid(u.address)} onChange={(address) => updateUp({ address })} />}
            {u.mode === "tls" && <Field label="Имя TLS (DoT)" value={u.tls_name ?? ""} valid={!!u.tls_name} onChange={(tls_name) => updateUp({ tls_name: tls_name || null })} />}
          </FormGrid></PageSection>
          <PageSection title="Транспорт"><FormGrid>
            <Select label="Протокол DNS-сервера" value={u.mode} options={upstreamModes} onChange={(mode) => updateUp(normalizeUpstreamOnModeChange(u, mode as "udp" | "tls" | "https"))} />
            {u.mode !== "https" && <Field label="Порт DNS-сервера" type="number" value={String(u.port)} onChange={(port) => updateUp({ port: Number(port) || 53 })} />}
          </FormGrid></PageSection>
          <EditorFooter saving={saving} valid={valid} cancel={cancel} save={save} />
        </>}
      </DialogContent>
    </Dialog>
  </>;
}

const upstreamsValid = (list: DNSUpstream[]) =>
  list.every((u) =>
    u.mode === "https" ? !!u.doh_server
      : ipValid(u.address) && (u.mode !== "tls" || !!u.tls_name));

export function DHCPEditor({ children }: { children: (actions: {
  addDevice: () => void; editDevice: (subnet: number, reservation: number) => void;
  editSubnets: () => void;
}) => ReactNode }) {
  const { configuration: c, version } = useConfiguration();
  const editor = useDraftEditor<DHCPSubnet[]>();
  const rows = editor.value ?? c.dhcp_subnets;
  const [device, setDevice] = useState<{ subnet: number; reservation: number } | null>(null);
  const [removeDevice, setRemoveDevice] = useState<{ subnet: number; reservation: number } | null>(null);
  const [subnetListOpen, setSubnetListOpen] = useState(false);
  const [selectedSubnet, setSelectedSubnet] = useState<number | null>(null);
  const beginDevice = (subnet: number, reservation: number) => {
    editor.begin(c.dhcp_subnets);
    setDevice({ subnet, reservation });
  };
  const updateDevice = (reservation: Reservation, subnet: number) => {
    if (!device) return;
    const next = rows.map((s) => ({ ...s, reservations: [...s.reservations] }));
    if (device.reservation >= 0) next[device.subnet].reservations.splice(device.reservation, 1);
    next[subnet].reservations.push(reservation);
    editor.setValue(next);
    setDevice({ subnet, reservation: next[subnet].reservations.length - 1 });
  };
  const isEditMode = editor.isEdit;
  const interfaces = c.interfaces.map((i) => i.name);
  const update = (index: number, value: Partial<DHCPSubnet>) =>
    editor.setValue(rows.map((s, i) => (i === index ? { ...s, ...value } : s)));
  const valid = rows.every(
    (s) =>
      integer(s.id) &&
      rows.filter((r) => r.id === s.id).length === 1 &&
      interfaces.includes(s.interface) &&
      s.subnet.includes("/") &&
      addressValid(s.subnet) &&
      !s.subnet.includes(":") &&
      s.pools.every(poolValid) &&
      listValid(s.routers, ipv4) &&
      listValid(s.dns_servers, ipv4) &&
      s.reservations.every(
        (r) =>
          ipv4(r.ip_address) &&
          macValid(r.hw_address) &&
          (!r.hostname || /^[a-zA-Z0-9.-]+$/.test(r.hostname)),
      ) &&
      s.valid_lifetime > 0 && Number.isInteger(s.valid_lifetime),
  ) && new Set(rows.flatMap((s) => s.reservations.map((r) => r.hw_address.toLowerCase()))).size === rows.reduce((n, s) => n + s.reservations.length, 0) &&
  new Set(rows.flatMap((s) => s.reservations.map((r) => r.ip_address))).size === rows.reduce((n, s) => n + s.reservations.length, 0);
  const save = () =>
    editor.save((value) => ({
      ...c,
      dhcp_subnets: value.map((s) => ({
        ...s,
        routers: normalize(s.routers),
        dns_servers: normalize(s.dns_servers),
      })),
    }));
  const cancel = () => { editor.cancel(); setDevice(null); setSelectedSubnet(null); setSubnetListOpen(false); };
  const saveAndClose = async () => { await save(); };
  const addSubnet = () => {
    editor.setValue([...rows, { id: Math.max(0, ...rows.map((s) => s.id)) + 1,
      interface: interfaces[0] ?? "", subnet: "", pools: [], reservations: [],
      routers: [], dns_servers: [], valid_lifetime: 3600 }]);
    setSelectedSubnet(rows.length);
  };
  const selected = selectedSubnet === null ? null : rows[selectedSubnet];
  return <>
    {!isEditMode && <ErrorNotice error={editor.error} />}
    {children({
      addDevice: () => beginDevice(0, -1),
      editDevice: beginDevice,
      editSubnets: () => { setDevice(null); setSelectedSubnet(null); setSubnetListOpen(true); editor.begin(c.dhcp_subnets); },
    })}
    <Dialog open={isEditMode && subnetListOpen && selectedSubnet === null && !device} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle>Подсети DHCP</DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error} />
        <DataTable heads={["Подсеть", "Интерфейс", "Действия"]} rows={rows.map((s, index) => [
          s.subnet || `Подсеть ${s.id}`, s.interface,
          <Button onClick={() => setSelectedSubnet(index)}>Изменить</Button>,
        ])} />
        <Button onClick={addSubnet}>Добавить подсеть</Button>
        <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void saveAndClose()} />
      </DialogContent>
    </Dialog>
    <Dialog open={isEditMode && !!selected} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>Подсеть {selected?.subnet || selected?.id}</span>
        {selected && <DeleteButton label={`Удалить подсеть ${selected.id}`} onClick={() => { editor.setValue(rows.filter((_, i) => i !== selectedSubnet)); setSelectedSubnet(null); }} />}
      </DialogTitle>
      <DialogContent>
        <ErrorNotice error={editor.error} />
        {selected && selectedSubnet !== null && <>
          <PageSection title="Идентификация"><FormGrid>
            {selectedSubnet < c.dhcp_subnets.length
              ? <Field label="ID подсети" value={selected.id} readOnly hint="Положительное уникальное число" />
              : <Field label="ID подсети" type="number" value={selected.id} valid={integer(selected.id) && rows.filter((r) => r.id === selected.id).length === 1} hint="Положительное уникальное число" onChange={(v) => update(selectedSubnet, { id: Number(v) })} />}
            {selectedSubnet < c.dhcp_subnets.length
              ? <Field label="Интерфейс подсети" value={selected.interface} readOnly />
              : <InterfaceSelect label="Интерфейс подсети" value={selected.interface} interfaces={c.interfaces} emptyLabel="Выберите интерфейс" error={!selected.interface} helperText={!selected.interface ? "Выберите значение" : undefined} onChange={(value) => update(selectedSubnet, { interface: value })} />}
            {selectedSubnet < c.dhcp_subnets.length
              ? <Field label="Подсеть CIDR" value={selected.subnet} readOnly hint="Например, 192.168.10.0/24" />
              : <Field label="Подсеть CIDR" value={selected.subnet} valid={selected.subnet.includes("/") && addressValid(selected.subnet) && !selected.subnet.includes(":")} hint="Например, 192.168.10.0/24" onChange={(subnet) => update(selectedSubnet, { subnet })} />}
          </FormGrid></PageSection>
          <PageSection title="Диапазон">
            <InfoNote>Диапазон адресов может включать несколько пулов. Постоянный IP может быть вне пула.</InfoNote>
            <DataTable heads={["Начало диапазона", "Конец диапазона", ""]} rows={selected.pools.map((p, pi) => {
              const pool = (v: Partial<typeof p>) => update(selectedSubnet, { pools: selected.pools.map((r, i) => i === pi ? { ...r, ...v } : r) });
              return [<Field ariaLabel="Начало пула" value={p.start} valid={poolValid(p)} hint="IPv4; начало ≤ конец" onChange={(start) => pool({ start })} />,
                <Field ariaLabel="Конец пула" value={p.end} valid={poolValid(p)} onChange={(end) => pool({ end })} />,
                <DeleteButton label={`Удалить пул ${pi + 1}`} onClick={() => update(selectedSubnet, { pools: selected.pools.filter((_, i) => i !== pi) })} />];
            })} />
            <Button onClick={() => update(selectedSubnet, { pools: [...selected.pools, { start: "", end: "" }] })}>Добавить пул</Button>
          </PageSection>
          <PageSection title="Параметры"><FormGrid>
            <Field label="Адрес роутера" multiline value={selected.routers.join("\n")} valid={listValid(selected.routers, ipv4)} onChange={(v) => update(selectedSubnet, { routers: v.split("\n") })} />
            <Field label="DNS для клиентов" multiline value={selected.dns_servers.join("\n")} valid={listValid(selected.dns_servers, ipv4)} onChange={(v) => update(selectedSubnet, { dns_servers: v.split("\n") })} />
            <Field label="Срок аренды, с" type="number" value={selected.valid_lifetime} valid={integer(selected.valid_lifetime)} hint="Время, на которое DHCP выдаёт клиенту IP-адрес (в секундах); больше нуля" inputProps={{ min: 1, step: 1 }} onChange={(v) => update(selectedSubnet, { valid_lifetime: Number(v) })} />
          </FormGrid></PageSection>
          <PageSection title="Резервирования">
            <DataTable heads={["Имя", "MAC", "Адрес", "Действия"]} rows={selected.reservations.map((r, ri) => [r.hostname || "—", r.hw_address, r.ip_address,
              <Button onClick={() => setDevice({ subnet: selectedSubnet, reservation: ri })}>Изменить</Button>])} />
            <Button onClick={() => setDevice({ subnet: selectedSubnet, reservation: -1 })}>Добавить устройство</Button>
          </PageSection>
        </>}
      </DialogContent>
      {selected && <DialogActions><EditorFooter saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void saveAndClose()} /></DialogActions>}
    </Dialog>
    <Dialog open={isEditMode && !!device && !!rows[device?.subnet ?? -1]} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>Устройство: {device && rows[device.subnet]?.reservations[device.reservation]?.hostname || "Новое устройство"}</span>
        {device && device.reservation >= 0 && <DeleteButton label="Удалить устройство" onClick={() => setRemoveDevice(device)} />}
      </DialogTitle>
      <DialogContent><ErrorNotice error={editor.error} />{device && rows[device.subnet] && <>
        <PageSection title="Идентификация"><FormGrid>
          <Field label="Имя устройства" value={rows[device.subnet].reservations[device.reservation]?.hostname ?? ""} hint="Имя хоста в DHCP" onChange={(hostname) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], hostname: hostname || null, hw_address: rows[device.subnet].reservations[device.reservation]?.hw_address ?? "", ip_address: rows[device.subnet].reservations[device.reservation]?.ip_address ?? "" }, device.subnet)} />
          <Field label="MAC" value={rows[device.subnet].reservations[device.reservation]?.hw_address ?? ""} valid={macValid(rows[device.subnet].reservations[device.reservation]?.hw_address ?? "")} onChange={(hw_address) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], hw_address, ip_address: rows[device.subnet].reservations[device.reservation]?.ip_address ?? "", hostname: rows[device.subnet].reservations[device.reservation]?.hostname ?? null }, device.subnet)} />
        </FormGrid></PageSection>
        <PageSection title="Адрес"><FormGrid>
          <Field label="Постоянный IP" value={rows[device.subnet].reservations[device.reservation]?.ip_address ?? ""} valid={ipv4(rows[device.subnet].reservations[device.reservation]?.ip_address ?? "")} onChange={(ip_address) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], ip_address, hw_address: rows[device.subnet].reservations[device.reservation]?.hw_address ?? "", hostname: rows[device.subnet].reservations[device.reservation]?.hostname ?? null }, device.subnet)} />
          <Select label="Подсеть" value={String(device.subnet)} options={rows.map((s, i) => ({ value: String(i), label: s.subnet || `Подсеть ${s.id}` }))} onChange={(value) => updateDevice(rows[device.subnet].reservations[device.reservation] ?? { hostname: null, hw_address: "", ip_address: "" }, Number(value))} />
        </FormGrid></PageSection>
        <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void saveAndClose()} />
      </>}</DialogContent>
    </Dialog>
    <ConfirmDialog open={!!removeDevice} title="Удалить устройство?" body="Резервация будет удалена из черновика после сохранения." confirmLabel="Удалить" cancelLabel="Отмена" danger onCancel={() => setRemoveDevice(null)} onConfirm={() => { if (removeDevice) editor.setValue(rows.map((s, i) => i === removeDevice.subnet ? { ...s, reservations: s.reservations.filter((_, j) => j !== removeDevice.reservation) } : s)); setRemoveDevice(null); setDevice(null); }} />
  </>;

}

export function DNSEditor({ children }: { children: (actions: { addRecord: () => void; addForward: () => void; edit: () => void }) => ReactNode }) {
  const { configuration: c, version } = useConfiguration();
  const editor = useDraftEditor<DNSConfig>();
  const dns = editor.value ?? c.dns;
  const isEditMode = editor.isEdit;
  const update = (v: Partial<DNSConfig>) => editor.setValue({ ...dns, ...v });
  const interfaces = c.interfaces.map((i) => i.name);
  const recordValid = (r: DNSConfig["records"][number]) =>
    r.type === "A"
      ? ipv4(r.value)
      : r.type === "AAAA"
        ? ipValid(r.value) && r.value.includes(":")
        : r.type === "CNAME"
          ? domainValid(r.value)
          : !!r.value;
  const valid =
    dns.records.every(
      (r) =>
        domainValid(r.name) &&
        Number.isInteger(r.ttl) &&
        r.ttl >= 0 &&
        recordValid(r),
    ) &&
    dns.forwards.every(
      (f) =>
        (f.domain === "." || domainValid(f.domain)) &&
        f.upstreams.length > 0 &&
        upstreamsValid(f.upstreams),
    ) &&
    upstreamsValid(dns.upstreams) &&
    dns.interfaces.every((i) => interfaces.includes(i)) &&
    new Set(dns.interfaces).size === dns.interfaces.length;
  const save = () => editor.save((value) => ({ ...c, dns: value }));
  const [surface, setSurface] = useState<"records" | "forwards" | "settings" | null>(null);
  const [selectedRecord, setSelectedRecord] = useState<number | null>(null);
  const [selectedForward, setSelectedForward] = useState<number | null>(null);
  const cancel = () => { editor.cancel(); setSurface(null); setSelectedRecord(null); setSelectedForward(null); };
  const record = selectedRecord === null ? null : dns.records[selectedRecord];
  const forward = selectedForward === null ? null : dns.forwards[selectedForward];
  const updateRecord = (v: Partial<DNSConfig["records"][number]>) => {
    if (selectedRecord === null) return;
    update({ records: dns.records.map((row, i) => i === selectedRecord ? { ...row, ...v } : row) });
  };
  const updateForward = (v: Partial<DNSConfig["forwards"][number]>) => {
    if (selectedForward === null) return;
    update({ forwards: dns.forwards.map((row, i) => i === selectedForward ? { ...row, ...v } : row) });
  };
  const footer = <EditorFooter saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void save()} />;
  return <>
    {!isEditMode && <ErrorNotice error={editor.error} />}
    {children({
      addRecord: () => { editor.begin({ ...c.dns, records: [...c.dns.records, { name: "", type: "A", ttl: 300, value: "" }] }); setSurface("records"); setSelectedRecord(c.dns.records.length); },
      addForward: () => { editor.begin({ ...c.dns, forwards: [...c.dns.forwards, { domain: "", upstreams: [] }] }); setSurface("forwards"); setSelectedForward(c.dns.forwards.length); },
      edit: () => { editor.begin(c.dns); setSurface("settings"); },
    })}
    <Dialog open={isEditMode && surface === "records"} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle>Локальные имена</DialogTitle><DialogContent>
        <ErrorNotice error={editor.error} />
        <DataTable heads={["Имя", "Тип", "TTL", "Значение", "Действия"]} rows={dns.records.map((r, index) => [r.name, r.type, r.ttl, r.value,
          <Button onClick={() => setSelectedRecord(index)}>Изменить</Button>])} />
        <Button onClick={() => { update({ records: [...dns.records, { name: "", type: "A", ttl: 300, value: "" }] }); setSelectedRecord(dns.records.length); }}>Добавить запись</Button>
        {footer}
      </DialogContent>
    </Dialog>
    <Dialog open={isEditMode && !!record} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><span>DNS-запись: {record?.name || "Новая запись"}</span>
        {record && <DeleteButton label={`Удалить запись ${selectedRecord! + 1}`} onClick={() => { update({ records: dns.records.filter((_, i) => i !== selectedRecord) }); setSelectedRecord(null); }} />}</DialogTitle>
      <DialogContent><ErrorNotice error={editor.error} />{record && <>
        <PageSection title="Идентификация"><FormGrid>
          <Field label="Имя DNS-записи" value={record.name} valid={domainValid(record.name)} hint="Латинское DNS-имя" onChange={(name) => updateRecord({ name })} />
          <SelectField label="Тип записи" value={record.type} options={["A", "CNAME"]} onChange={(type) => updateRecord({ type })} />
        </FormGrid></PageSection>
        <PageSection title="Значение"><FormGrid>
          <Field label="TTL" type="number" value={record.ttl} valid={Number.isInteger(record.ttl) && record.ttl >= 0} onChange={(v) => updateRecord({ ttl: Number(v) })} />
          <Field label="Значение записи" value={record.value} valid={recordValid(record)} hint={record.type === "A" ? "IPv4" : record.type === "CNAME" ? "DNS-имя" : undefined} onChange={(value) => updateRecord({ value })} />
        </FormGrid></PageSection>{footer}
      </>}</DialogContent>
    </Dialog>
    <Dialog open={isEditMode && surface === "forwards" && selectedForward === null} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle>Домены с отдельным DNS</DialogTitle><DialogContent>
        <ErrorNotice error={editor.error} />
        <DataTable heads={["Домен", "DNS-серверы", "Действия"]} rows={dns.forwards.map((f, index) => [f.domain || "Новый домен", String(f.upstreams.length),
          <Button onClick={() => setSelectedForward(index)}>Изменить</Button>])} />
        <Button onClick={() => { update({ forwards: [...dns.forwards, { domain: "", upstreams: [] }] }); setSelectedForward(dns.forwards.length); }}>Добавить переадресацию</Button>
        {footer}
      </DialogContent>
    </Dialog>
    <Dialog open={isEditMode && !!forward} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><span>DNS-правило: {forward?.domain || "Новый домен"}</span>
        {forward && <DeleteButton label={`Удалить переадресацию ${selectedForward! + 1}`} onClick={() => { update({ forwards: dns.forwards.filter((_, i) => i !== selectedForward) }); setSelectedForward(null); }} />}</DialogTitle>
      <DialogContent><ErrorNotice error={editor.error} />{forward && <>
        <PageSection title="Условие"><FormGrid><Field label="Домен переадресации" value={forward.domain} valid={forward.domain === "." || domainValid(forward.domain)} onChange={(domain) => updateForward({ domain })} /></FormGrid></PageSection>
        <PageSection title="Решение"><UpstreamRows upstreams={forward.upstreams} onChange={(upstreams) => updateForward({ upstreams })} saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void save()} error={editor.error} /></PageSection>
        {footer}
      </>}</DialogContent>
    </Dialog>
    <Dialog open={isEditMode && surface === "settings"} onClose={editor.saving ? undefined : cancel} fullWidth maxWidth="md">
      <DialogTitle>Режим и привязка DNS</DialogTitle><DialogContent>
        <ErrorNotice error={editor.error} />
        <PageSection title="Режим и привязка"><FormGrid>
          <Select label="Режим DNS" value={dns.recursive ? "recursive" : "forward"} options={[{ value: "forward", label: "Через указанные DNS-серверы" }, { value: "recursive", label: "Самостоятельный поиск" }]} onChange={(value) => update({ recursive: value === "recursive" })} />
          <Toggle label="Записывать DNS-запросы (для диагностики)" value={dns.log_queries} onChange={(log_queries) => update({ log_queries })} />
        </FormGrid></PageSection>
        <PageSection title="DNS-серверы"><UpstreamRows upstreams={dns.upstreams} onChange={(upstreams) => update({ upstreams })} saving={editor.saving} valid={valid && !!version} cancel={cancel} save={() => void save()} error={editor.error} /></PageSection>
        <PageSection title="Интерфейсы">
          <FormGrid>{dns.interfaces.map((value, index) => <div key={index}>
            <InterfaceSelect label="Где отвечает DNS" value={value} interfaces={c.interfaces.filter((i) => i.name === value || !dns.interfaces.includes(i.name))} emptyLabel="Выберите интерфейс" error={!value} helperText={!value ? "Выберите значение" : undefined} onChange={(v) => update({ interfaces: dns.interfaces.map((row, i) => i === index ? v : row) })} />
            <DeleteButton label={`Удалить привязку ${index + 1}`} onClick={() => update({ interfaces: dns.interfaces.filter((_, i) => i !== index) })} />
          </div>)}</FormGrid>
          <Button disabled={interfaces.every((i) => dns.interfaces.includes(i))} onClick={() => update({ interfaces: [...dns.interfaces, interfaces.find((i) => !dns.interfaces.includes(i))!] })}>Добавить привязку</Button>
          <InfoNote>Каким сетям разрешён доступ: {dns.access_control.join(", ") || "не задано"}. Выбор интерфейса сам по себе не меняет этот список.</InfoNote>
          <InfoNote>Просмотр DNS-запросов здесь пока недоступен.</InfoNote>
        </PageSection>{footer}
      </DialogContent>
    </Dialog>
  </>;
}
