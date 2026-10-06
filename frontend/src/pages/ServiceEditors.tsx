import { useState, type ReactNode } from "react";
import { Button, Typography } from "@mui/material";
import type { DHCPSubnet, DNS as DNSConfig } from "../types";
import { useConfiguration } from "../state";
import { Card, DataTable, ErrorNotice } from "../ui";
import {
  Field,
  SelectField,
  InterfaceSelect,
  Toggle,
  EditorFooter,
  ipValid,
  addressValid,
  domainValid,
  lines,
} from "../editor";

const ipv4 = (v: string) => ipValid(v) && !v.includes(":");
const integer = (v: number) => Number.isInteger(v) && v > 0;
const macValid = (v: string) =>
  /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v);
const listValid = (v: string[], check: (s: string) => boolean) =>
  v.filter(Boolean).every(check);
const ipNumber = (v: string) =>
  v.split(".").reduce((n, p) => n * 256 + Number(p), 0);
const poolValid = (p: { start: string; end: string }) =>
  ipv4(p.start) && ipv4(p.end) && ipNumber(p.start) <= ipNumber(p.end);
const normalize = (v: string[]) => lines(v.join("\n"));

export function DHCPEditor({ children }: { children: ReactNode }) {
  const { configuration: c, version, saveDraft, setNotice } = useConfiguration();
  const [editing, setEditing] = useState<DHCPSubnet[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const rows = editing ?? c.dhcp_subnets;
  const isEditMode = editing !== null;
  const interfaces = c.interfaces.map((i) => i.name);
  const update = (index: number, value: Partial<DHCPSubnet>) =>
    setEditing(rows.map((s, i) => (i === index ? { ...s, ...value } : s)));
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
      ),
  );
  const save = async () => {
    if (!version || !valid) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await saveDraft({
        ...c,
        dhcp_subnets: rows.map((s) => ({
          ...s,
          routers: normalize(s.routers),
          dns_servers: normalize(s.dns_servers),
        })),
      });
      setNotice(`Черновик v${saved.id} сохранён`);
      setEditing(null);
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  };
  return (
    <>
      <ErrorNotice error={error} />
      {!isEditMode ? (
        <>
          <Button
            disabled={!version}
            onClick={() => {
              setEditing(c.dhcp_subnets);
              setError(null);
            }}
          >
            Редактировать
          </Button>
          {children}
        </>
      ) : (
        <>
          <Typography component="h1" variant="h1" className="page-title">
            DHCP (Kea)
          </Typography>
          <fieldset
            disabled={saving}
            style={{ border: 0, padding: 0, minWidth: 0 }}
          >
            {rows.map((s, index) => (
              <Card
                key={index}
                title={`Подсеть ${s.id}`}
                action={
                  <Button
                    color="error"
                    onClick={() =>
                      setEditing(rows.filter((_, i) => i !== index))
                    }
                  >
                    Удалить подсеть
                  </Button>
                }
              >
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
                  label="Шлюзы (построчно)"
                  multiline
                  value={s.routers.join("\n")}
                  valid={listValid(s.routers, ipv4)}
                  onChange={(v) => update(index, { routers: v.split("\n") })}
                />
                <Field
                  label="DNS-серверы (построчно)"
                  multiline
                  value={s.dns_servers.join("\n")}
                  valid={listValid(s.dns_servers, ipv4)}
                  onChange={(v) =>
                    update(index, { dns_servers: v.split("\n") })
                  }
                />
                <DataTable
                  heads={["Начало пула", "Конец пула", ""]}
                  rows={s.pools.map((p, pi) => {
                    const pool = (v: Partial<typeof p>) =>
                      update(index, {
                        pools: s.pools.map((r, i) =>
                          i === pi ? { ...r, ...v } : r,
                        ),
                      });
                    return [
                      <Field
                        label="Начало пула"
                        value={p.start}
                        valid={poolValid(p)}
                        hint="IPv4; начало ≤ конец"
                        onChange={(start) => pool({ start })}
                      />,
                      <Field
                        label="Конец пула"
                        value={p.end}
                        valid={poolValid(p)}
                        onChange={(end) => pool({ end })}
                      />,
                      <Button
                        color="error"
                        onClick={() =>
                          update(index, {
                            pools: s.pools.filter((_, i) => i !== pi),
                          })
                        }
                      >
                        Удалить пул
                      </Button>,
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
                <DataTable
                  heads={["IP", "MAC", "Hostname", ""]}
                  rows={s.reservations.map((r, ri) => {
                    const reservation = (v: Partial<typeof r>) =>
                      update(index, {
                        reservations: s.reservations.map((row, i) =>
                          i === ri ? { ...row, ...v } : row,
                        ),
                      });
                    return [
                      <Field
                        label="IP резервации"
                        value={r.ip_address}
                        valid={ipv4(r.ip_address)}
                        onChange={(ip_address) => reservation({ ip_address })}
                      />,
                      <Field
                        label="MAC резервации"
                        value={r.hw_address}
                        valid={macValid(r.hw_address)}
                        hint="aa:bb:cc:dd:ee:ff"
                        onChange={(hw_address) => reservation({ hw_address })}
                      />,
                      <Field
                        label="Hostname"
                        value={r.hostname ?? ""}
                        valid={
                          !r.hostname || /^[a-zA-Z0-9.-]+$/.test(r.hostname)
                        }
                        onChange={(v) => reservation({ hostname: v || null })}
                      />,
                      <Button
                        color="error"
                        onClick={() =>
                          update(index, {
                            reservations: s.reservations.filter(
                              (_, i) => i !== ri,
                            ),
                          })
                        }
                      >
                        Удалить резервацию
                      </Button>,
                    ];
                  })}
                />
                <Button
                  onClick={() =>
                    update(index, {
                      reservations: [
                        ...s.reservations,
                        { ip_address: "", hw_address: "", hostname: null },
                      ],
                    })
                  }
                >
                  + Добавить резервацию
                </Button>
                <p className="sub">
                  Резервации допустимы внутри динамического пула и вне его.
                </p>
              </Card>
            ))}
            <Button
              onClick={() =>
                setEditing([
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
          </fieldset>
          <EditorFooter
            saving={saving}
            valid={valid && !!version}
            cancel={() => {
              setEditing(null);
              setError(null);
            }}
            save={() => void save()}
          />
        </>
      )}
    </>
  );
}

export function DNSEditor({ children }: { children: ReactNode }) {
  const { configuration: c, version, saveDraft, setNotice } = useConfiguration();
  const [editing, setEditing] = useState<DNSConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const dns = editing ?? c.dns;
  const isEditMode = editing !== null;
  const update = (v: Partial<DNSConfig>) => setEditing({ ...dns, ...v });
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
        normalize(f.upstreams).length > 0 &&
        listValid(f.upstreams, ipValid),
    ) &&
    listValid(dns.upstreams, ipValid) &&
    dns.interfaces.every((i) => interfaces.includes(i)) &&
    new Set(dns.interfaces).size === dns.interfaces.length;
  const save = async () => {
    if (!version || !valid) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await saveDraft({
        ...c,
        dns: {
          ...dns,
          upstreams: normalize(dns.upstreams),
          forwards: dns.forwards.map((f) => ({
            ...f,
            upstreams: normalize(f.upstreams),
          })),
        },
      });
      setNotice(`Черновик v${saved.id} сохранён`);
      setEditing(null);
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  };
  return (
    <>
      <ErrorNotice error={error} />
      {!isEditMode ? (
        <>
          <Button
            disabled={!version}
            onClick={() => {
              setEditing(c.dns);
              setError(null);
            }}
          >
            Редактировать
          </Button>
          {children}
        </>
      ) : (
        <>
          <Typography component="h1" variant="h1" className="page-title">
            DNS (Unbound)
          </Typography>
          <fieldset
            disabled={saving}
            style={{ border: 0, padding: 0, minWidth: 0 }}
          >
            <Card title="Локальные записи (host overrides)">
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
                      label="Имя DNS-записи"
                      value={r.name}
                      valid={domainValid(r.name)}
                      hint="Латинское DNS-имя"
                      onChange={(name) => record({ name })}
                    />,
                    <SelectField
                      label="Тип записи"
                      value={r.type}
                      options={["A", "CNAME"]}
                      onChange={(type) => record({ type })}
                    />,
                    <Field
                      label="TTL"
                      type="number"
                      value={r.ttl}
                      valid={Number.isInteger(r.ttl) && r.ttl >= 0}
                      onChange={(v) => record({ ttl: Number(v) })}
                    />,
                    <Field
                      label="Значение записи"
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
                    <Button
                      color="error"
                      onClick={() =>
                        update({
                          records: dns.records.filter((_, i) => i !== index),
                        })
                      }
                    >
                      Удалить запись
                    </Button>,
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
            <Card title="DNS-переадресация по доменам">
              <DataTable
                heads={["Домен", "Upstreams", ""]}
                rows={dns.forwards.map((f, index) => {
                  const forward = (v: Partial<typeof f>) =>
                    update({
                      forwards: dns.forwards.map((row, i) =>
                        i === index ? { ...row, ...v } : row,
                      ),
                    });
                  return [
                    <Field
                      label="Домен переадресации"
                      value={f.domain}
                      valid={f.domain === "." || domainValid(f.domain)}
                      onChange={(domain) => forward({ domain })}
                    />,
                    <Field
                      label="Upstreams домена (построчно)"
                      multiline
                      value={f.upstreams.join("\n")}
                      valid={
                        normalize(f.upstreams).length > 0 &&
                        listValid(f.upstreams, ipValid)
                      }
                      onChange={(v) => forward({ upstreams: v.split("\n") })}
                    />,
                    <Button
                      color="error"
                      onClick={() =>
                        update({
                          forwards: dns.forwards.filter((_, i) => i !== index),
                        })
                      }
                    >
                      Удалить переадресацию
                    </Button>,
                  ];
                })}
              />
              <Button
                onClick={() =>
                  update({
                    forwards: [...dns.forwards, { domain: "", upstreams: [] }],
                  })
                }
              >
                + Добавить переадресацию
              </Button>
              <p className="sub">
                Домен целиком уходит на указанные серверы (forward-zone).
              </p>
            </Card>
            <Card title="Режим и привязка">
              <Field
                label="Upstream-серверы (построчно)"
                multiline
                value={dns.upstreams.join("\n")}
                valid={listValid(dns.upstreams, ipValid)}
                onChange={(v) => update({ upstreams: v.split("\n") })}
              />
              <Toggle
                label="Рекурсия"
                value={dns.recursive}
                onChange={(recursive) => update({ recursive })}
              />
              <Toggle
                label="Журнал запросов"
                value={dns.log_queries}
                onChange={(log_queries) => update({ log_queries })}
              />
              {dns.interfaces.map((value, index) => (
                <div key={index}>
                  <InterfaceSelect
                    label="Слушает интерфейс"
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
                  <Button
                    color="error"
                    onClick={() =>
                      update({
                        interfaces: dns.interfaces.filter(
                          (_, i) => i !== index,
                        ),
                      })
                    }
                  >
                    Удалить привязку
                  </Button>
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
              <p className="sub">
                Доступ: {dns.access_control.join(", ") || "—"}. Resolver слушает
                только выбранные интерфейсы.
              </p>
            </Card>
          </fieldset>
          <EditorFooter
            saving={saving}
            valid={valid && !!version}
            cancel={() => {
              setEditing(null);
              setError(null);
            }}
            save={() => void save()}
          />
        </>
      )}
    </>
  );
}
