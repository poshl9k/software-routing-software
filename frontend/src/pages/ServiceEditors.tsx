import { useState, type ReactNode } from "react";
import { Button } from "@mui/material";
import type { DHCPSubnet, Reservation, DNS as DNSConfig, DNSUpstream } from "../types";
import { useConfiguration } from "../state";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { ErrorNotice } from "../components/ErrorNotice";
import { DeleteButton } from "../components/DeleteButton";
import { EditorShell } from "../components/EditorShell";
import { Field } from "../components/Field";
import { FormGrid } from "../components/Form";
import { PageHeader } from "../components/PageHeader";
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

/** One structured DNS upstream row list, shared by the root and per-domain lists. */
function UpstreamRows({
  upstreams,
  onChange,
}: {
  upstreams: DNSUpstream[];
  onChange: (upstreams: DNSUpstream[]) => void;
}) {
  return (
    <div>
      {upstreams.map((u, uIndex) => {
        const updateUp = (v: Partial<DNSUpstream>) =>
          onChange(upstreams.map((row, i) => (i === uIndex ? { ...row, ...v } : row)));
        return (
          <Card
            key={uIndex}
            title={u.mode === "udp" ? "UDP" : u.mode === "tls" ? "DoT" : "DoH"}
            action={
              <DeleteButton
                label={`Удалить upstream ${uIndex + 1}`}
                onClick={() => onChange(upstreams.filter((_, i) => i !== uIndex))}
              />
            }
          >
            <FormGrid>
              <Select
                ariaLabel="Протокол DNS-сервера"
                value={u.mode}
                options={upstreamModes}
                onChange={(mode) =>
                  updateUp(normalizeUpstreamOnModeChange(u, mode as "udp" | "tls" | "https"))
                }
              />
              {(u.mode === "udp" || u.mode === "tls") && (
                <>
                  <Field
                    ariaLabel="Адрес DNS-сервера"
                    value={u.address}
                    valid={ipValid(u.address)}
                    onChange={(address) => updateUp({ address })}
                  />
                  <Field
                    ariaLabel="Порт DNS-сервера"
                    type="number"
                    value={String(u.port)}
                    onChange={(port) => updateUp({ port: Number(port) || 53 })}
                  />
                  {u.mode === "tls" && (
                    <Field
                      ariaLabel="Имя TLS (DoT)"
                      value={u.tls_name ?? ""}
                      valid={!!u.tls_name}
                      onChange={(tls_name) => updateUp({ tls_name: tls_name || null })}
                    />
                  )}
                </>
              )}
              {u.mode === "https" && (
                <Field
                  ariaLabel="Сервер DoH (dnscrypt-proxy)"
                  value={u.doh_server ?? ""}
                  valid={!!u.doh_server}
                  onChange={(doh_server) => updateUp({ doh_server: doh_server || null })}
                />
              )}
            </FormGrid>
          </Card>
        );
      })}
      <Button onClick={() => onChange([...upstreams, newUpstreamRow("udp")])}>
        Добавить DNS-сервер
      </Button>
    </div>
  );
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
  return (
    <EditorShell
      isEdit={isEditMode}
      saving={editor.saving}
      valid={valid && !!version}
      onCancel={editor.cancel}
      onSave={() => void save()}
      view={
        <>
          <ErrorNotice error={editor.error} />
          {children({
            addDevice: () => beginDevice(0, -1),
            editDevice: beginDevice,
            editSubnets: () => { setDevice(null); editor.begin(c.dhcp_subnets); },
          })}
        </>
      }
      edit={
        <>
          <PageHeader>DHCP (Kea)</PageHeader>
          {device && rows[device.subnet] ? (
            <Card title="Устройство с постоянным IP">
              <FormGrid>
                <Field label="Имя устройства" value={rows[device.subnet].reservations[device.reservation]?.hostname ?? ""}
                  hint="Имя хоста в DHCP" onChange={(hostname) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], hostname: hostname || null, hw_address: rows[device.subnet].reservations[device.reservation]?.hw_address ?? "", ip_address: rows[device.subnet].reservations[device.reservation]?.ip_address ?? "" }, device.subnet)} />
                <Field label="MAC" value={rows[device.subnet].reservations[device.reservation]?.hw_address ?? ""}
                  valid={macValid(rows[device.subnet].reservations[device.reservation]?.hw_address ?? "")}
                  onChange={(hw_address) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], hw_address, ip_address: rows[device.subnet].reservations[device.reservation]?.ip_address ?? "", hostname: rows[device.subnet].reservations[device.reservation]?.hostname ?? null }, device.subnet)} />
                <Field label="Постоянный IP" value={rows[device.subnet].reservations[device.reservation]?.ip_address ?? ""}
                  valid={ipv4(rows[device.subnet].reservations[device.reservation]?.ip_address ?? "")}
                  onChange={(ip_address) => updateDevice({ ...rows[device.subnet].reservations[device.reservation], ip_address, hw_address: rows[device.subnet].reservations[device.reservation]?.hw_address ?? "", hostname: rows[device.subnet].reservations[device.reservation]?.hostname ?? null }, device.subnet)} />
                <Select label="Подсеть" value={String(device.subnet)} options={rows.map((s, i) => ({ value: String(i), label: s.subnet || `Подсеть ${s.id}` }))}
                  onChange={(value) => updateDevice(rows[device.subnet].reservations[device.reservation] ?? { hostname: null, hw_address: "", ip_address: "" }, Number(value))} />
              </FormGrid>
              {device.reservation >= 0 && <Button color="error" onClick={() => setRemoveDevice(device)}>Удалить устройство</Button>}
              <ConfirmDialog open={!!removeDevice} title="Удалить устройство?" body="Резервация будет удалена из черновика после сохранения." confirmLabel="Удалить" cancelLabel="Отмена" danger
                onCancel={() => setRemoveDevice(null)} onConfirm={() => { if (removeDevice) editor.setValue(rows.map((s, i) => i === removeDevice.subnet ? { ...s, reservations: s.reservations.filter((_, j) => j !== removeDevice.reservation) } : s)); setRemoveDevice(null); setDevice(null); }} />
            </Card>
          ) : rows.map((s, index) => (
            <Card
              key={index}
              title={`Подсеть ${s.id}`}
              action={
                <DeleteButton
                  label={`Удалить подсеть ${s.id}`}
                  onClick={() => editor.setValue(rows.filter((_, i) => i !== index))}
                />
              }
            >
              <FormGrid>
              <Field
                label="ID подсети"
                type="number"
                value={s.id}
                valid={
                  integer(s.id) &&
                  rows.filter((r) => r.id === s.id).length === 1
                }
                hint="Положительное уникальное число"
                onChange={(v) => update(index, { id: Number(v) })}
              />
              <InterfaceSelect
                label="Интерфейс подсети"
                value={s.interface}
                interfaces={c.interfaces}
                emptyLabel="Выберите интерфейс"
                error={!s.interface}
                helperText={!s.interface ? "Выберите значение" : undefined}
                onChange={(value) => update(index, { interface: value })}
              />
              <Field
                label="Подсеть CIDR"
                value={s.subnet}
                valid={
                  s.subnet.includes("/") &&
                  addressValid(s.subnet) &&
                  !s.subnet.includes(":")
                }
                hint="Например, 192.168.10.0/24"
                onChange={(subnet) => update(index, { subnet })}
              />
              <Field
                label="Адрес роутера"
                multiline
                value={s.routers.join("\n")}
                valid={listValid(s.routers, ipv4)}
                onChange={(v) => update(index, { routers: v.split("\n") })}
              />
              <Field
                label="DNS для клиентов"
                multiline
                value={s.dns_servers.join("\n")}
                valid={listValid(s.dns_servers, ipv4)}
                onChange={(v) => update(index, { dns_servers: v.split("\n") })}
              />
              <Field
                label="Срок аренды, с"
                type="number"
                value={s.valid_lifetime}
                valid={integer(s.valid_lifetime)}
                hint="Время, на которое DHCP выдаёт клиенту IP-адрес (в секундах); больше нуля"
                inputProps={{ min: 1, step: 1 }}
                onChange={(v) => update(index, { valid_lifetime: Number(v) })}
              />
              </FormGrid>
              <InfoNote>Диапазон адресов может включать несколько пулов. Постоянный IP может быть вне пула.</InfoNote>
              <DataTable
                heads={["Начало диапазона", "Конец диапазона", ""]}
                rows={s.pools.map((p, pi) => {
                  const pool = (v: Partial<typeof p>) =>
                    update(index, {
                      pools: s.pools.map((r, i) =>
                        i === pi ? { ...r, ...v } : r,
                      ),
                    });
                  return [
                    <Field
                      ariaLabel="Начало пула"
                      value={p.start}
                      valid={poolValid(p)}
                      hint="IPv4; начало ≤ конец"
                      onChange={(start) => pool({ start })}
                    />,
                    <Field
                      ariaLabel="Конец пула"
                      value={p.end}
                      valid={poolValid(p)}
                      onChange={(end) => pool({ end })}
                    />,
                    <DeleteButton
                      label={`Удалить пул ${pi + 1}`}
                      onClick={() =>
                        update(index, {
                          pools: s.pools.filter((_, i) => i !== pi),
                        })
                      }
                    />,
                  ];
                })}
              />
              <Button
                onClick={() =>
                  update(index, {
                    pools: [...s.pools, { start: "", end: "" }],
                  })
                }
              >
                + Добавить пул
              </Button>
            </Card>
          ))}
          <Button
            onClick={() =>
              editor.setValue([
                ...rows,
                {
                  id: Math.max(0, ...rows.map((s) => s.id)) + 1,
                  interface: interfaces[0] ?? "",
                  subnet: "",
                  pools: [],
                  reservations: [],
                  routers: [],
                  dns_servers: [],
                  valid_lifetime: 3600,
                },
              ])
            }
          >
            + Добавить подсеть
          </Button>
        </>
      }
    />
  );
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
  return (
    <EditorShell
      isEdit={isEditMode}
      saving={editor.saving}
      valid={valid && !!version}
      onCancel={editor.cancel}
      onSave={() => void save()}
      view={
        <>
          <ErrorNotice error={editor.error} />
          {children({
            addRecord: () => { editor.begin({ ...c.dns, records: [...c.dns.records, { name: "", type: "A", ttl: 300, value: "" }] }); },
            addForward: () => { editor.begin({ ...c.dns, forwards: [...c.dns.forwards, { domain: "", upstreams: [] }] }); },
            edit: () => editor.begin(c.dns),
          })}
        </>
      }
      edit={
        <>
          <PageHeader>DNS (Unbound)</PageHeader>
          <Card title="Локальные имена">
            <DataTable
              heads={["Имя", "Тип", "TTL", "Значение", ""]}
              rows={dns.records.map((r, index) => {
                const record = (v: Partial<typeof r>) =>
                  update({
                    records: dns.records.map((row, i) =>
                      i === index ? { ...row, ...v } : row,
                    ),
                  });
                return [
                  <Field
                    ariaLabel="Имя DNS-записи"
                    value={r.name}
                    valid={domainValid(r.name)}
                    hint="Латинское DNS-имя"
                    onChange={(name) => record({ name })}
                  />,
                  <SelectField
                    ariaLabel="Тип записи"
                    value={r.type}
                    options={["A", "CNAME"]}
                    onChange={(type) => record({ type })}
                  />,
                  <Field
                    ariaLabel="TTL"
                    type="number"
                    value={r.ttl}
                    valid={Number.isInteger(r.ttl) && r.ttl >= 0}
                    onChange={(v) => record({ ttl: Number(v) })}
                  />,
                  <Field
                    ariaLabel="Значение записи"
                    value={r.value}
                    valid={recordValid(r)}
                    hint={
                      r.type === "A"
                        ? "IPv4"
                        : r.type === "CNAME"
                          ? "DNS-имя"
                          : undefined
                    }
                    onChange={(value) => record({ value })}
                  />,
                  <DeleteButton
                    label={`Удалить запись ${index + 1}`}
                    onClick={() =>
                      update({
                        records: dns.records.filter((_, i) => i !== index),
                      })
                    }
                  />,
                ];
              })}
            />
            <Button
              onClick={() =>
                update({
                  records: [
                    ...dns.records,
                    { name: "", type: "A", ttl: 300, value: "" },
                  ],
                })
              }
            >
              + Добавить запись
            </Button>
          </Card>
          <Card title="Домены с отдельным DNS">
            {dns.forwards.map((f, index) => {
              const forward = (v: Partial<typeof f>) => update({ forwards: dns.forwards.map((row, i) => i === index ? { ...row, ...v } : row) });
              return <Card key={index} title={f.domain || `Новый домен ${index + 1}`}
                action={<DeleteButton label={`Удалить переадресацию ${index + 1}`} onClick={() => update({ forwards: dns.forwards.filter((_, i) => i !== index) })} />}>
                <FormGrid><Field label="Домен переадресации" value={f.domain} valid={f.domain === "." || domainValid(f.domain)} onChange={(domain) => forward({ domain })} /></FormGrid>
                <UpstreamRows upstreams={f.upstreams} onChange={(upstreams) => forward({ upstreams })} />
              </Card>;
            })}
            <Button onClick={() => update({ forwards: [...dns.forwards, { domain: "", upstreams: [] }] })}>+ Добавить переадресацию</Button>
          </Card>
          <Card title="Режим и привязка">
            <FormGrid>
              <UpstreamRows
                upstreams={dns.upstreams}
                onChange={(upstreams) => update({ upstreams })}
              />
              <Select label="Режим DNS" value={dns.recursive ? "recursive" : "forward"}
                options={[{ value: "forward", label: "Через указанные DNS-серверы" }, { value: "recursive", label: "Самостоятельный поиск" }]}
                onChange={(value) => update({ recursive: value === "recursive" })} />
              <Toggle
                label="Записывать DNS-запросы (для диагностики)"
                value={dns.log_queries}
                onChange={(log_queries) => update({ log_queries })}
              />
            </FormGrid>
            {dns.interfaces.map((value, index) => (
              <div key={index}>
                <InterfaceSelect
                  label="Где отвечает DNS"
                  value={value}
                  interfaces={c.interfaces.filter(
                    (i) => i.name === value || !dns.interfaces.includes(i.name),
                  )}
                  emptyLabel="Выберите интерфейс"
                  error={!value}
                  helperText={!value ? "Выберите значение" : undefined}
                  onChange={(v) =>
                    update({
                      interfaces: dns.interfaces.map((row, i) =>
                        i === index ? v : row,
                      ),
                    })
                  }
                />
                <DeleteButton
                  label={`Удалить привязку ${index + 1}`}
                  onClick={() =>
                    update({
                      interfaces: dns.interfaces.filter((_, i) => i !== index),
                    })
                  }
                />
              </div>
            ))}
            <Button
              disabled={interfaces.every((i) => dns.interfaces.includes(i))}
              onClick={() =>
                update({
                  interfaces: [
                    ...dns.interfaces,
                    interfaces.find((i) => !dns.interfaces.includes(i))!,
                  ],
                })
              }
            >
              + Добавить привязку
            </Button>
            <InfoNote>Каким сетям разрешён доступ: {dns.access_control.join(", ") || "не задано"}. Выбор интерфейса сам по себе не меняет этот список.</InfoNote>
            <InfoNote>Просмотр DNS-запросов здесь пока недоступен.</InfoNote>
          </Card>
        </>
      }
    />
  );
}