import { useState } from "react";
import { Button } from "@mui/material";
import { useConfiguration } from "../state";
import { ServiceStatusHeader } from "../components/ServiceStatusHeader";
import { InlineStatus } from "../components/InlineStatus";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { Field } from "../components/Field";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { PageTabs } from "../components/Tabs";
import { Badge } from "../components/Badge";
import { DHCPEditor, DNSEditor, type DHCPActions } from "./ServiceEditors";
import { DnsPolicyDialog } from "./TProxyDnsPolicy";
import { Sites, DDNS } from "./ConnectionEditors";
import { api, ApiError } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";
import { fmtRemaining } from "../components/format";
import { privacyMac } from "../components/validators";
import type { DNSUpstream, DHCPLease } from "../types";

export function useServiceTelemetry() {
  return useQuery({
    queryKey: queryKeys.serviceStatus(),
    queryFn: async ({ signal }) => {
      const result = await api.serviceStatus(signal);
      if (!Array.isArray(result.services) || typeof result.generated_at !== "string")
        throw new Error("Некорректный статус служб");
      return result;
    },
    refetchInterval: 30_000,
  });
}

type Telemetry = ReturnType<typeof useServiceTelemetry>;

export function RuntimeServiceInline({ name, telemetry, showAsOf = true }: { name: string; telemetry: Telemetry; showAsOf?: boolean }) {
  if (telemetry.isPending) return <InlineStatus tone="unknown" text="Статус загружается…" />;
  if (telemetry.isError) return <InlineStatus tone="unknown" text="Статус недоступен" />;
  const service = telemetry.data.services.find((item) => item.name === name);
  const state = service?.state ?? "unknown";
  const labels = { running: "Работает", stopped: "Остановлена", unknown: "Состояние неизвестно" };
  return <InlineStatus tone={state === "running" ? "green" : state === "stopped" ? "amber" : "unknown"}
    text={labels[state]} asOf={showAsOf ? telemetry.data.generated_at : undefined} />;
}

function RuntimeServiceHeader({ name, serviceName, telemetry }: { name: string; serviceName: string; telemetry: Telemetry }) {
  if (telemetry.isPending || telemetry.isError) return <RuntimeServiceInline name={serviceName} telemetry={telemetry} />;
  const service = telemetry.data.services.find((item) => item.name === serviceName);
  return <>
    <ServiceStatusHeader name={name} state={service?.state ?? "unknown"} asOf={telemetry.data.generated_at} />
    {service?.detail && <InfoNote>{service.detail}</InfoNote>}
  </>;
}

export function DHCP() {
  return (
    <DHCPEditor>{(actions) => <DHCPReadOnly actions={actions} />}</DHCPEditor>
  );
}
function DHCPReadOnly({ actions }: { actions: DHCPActions }) {
  const { configuration: c } = useConfiguration();
  const telemetry = useServiceTelemetry();
  const [tab, setTab] = useState(0);
  const [query, setQuery] = useState("");
  const [term, setTerm] = useState("");
  // Server state: cached, deduped, and only fetched while the leases tab is open.
  const leases = useQuery({
    queryKey: queryKeys.dhcpLeases(term),
    queryFn: () => (term ? api.searchLeases(term) : api.dhcpLeases()),
    enabled: tab === 0,
  });
  const leaseError = leases.error;
  const leaseEmpty = leases.isLoading ? "Загрузка аренд…"
    : leaseError instanceof ApiError && (leaseError.status === 502 || leaseError.status === 503)
      ? "Kea ctrl-agent недоступен — аренды не прочитаны"
      : leaseError ? "Не удалось получить аренды" : "Аренд пока нет";
  const noteOf = (mac: string) =>
    c.dhcp_client_notes?.find((item) => item.mac.toLowerCase() === mac.toLowerCase())?.note ?? "";
  const subnetFor = (lease: DHCPLease) => {
    const subnet = c.dhcp_subnets.find((s) => String(s.id) === String(lease.subnet));
    if (!subnet) return `Подсеть ${lease.subnet}`;
    const iface = c.interfaces.find((i) => i.name === subnet.interface);
    return iface?.description
      ? `${iface.description} (${iface.name}) · ${subnet.subnet}`
      : `${subnet.subnet} (${subnet.interface})`;
  };
  const isReserved = (lease: DHCPLease) => c.dhcp_subnets.some((s) =>
    s.reservations.some((r) => r.hw_address.toLowerCase() === lease.mac.toLowerCase()));
  const leaseList: DHCPLease[] = Array.isArray(leases.data) ? leases.data : [];
  const leaseRows = (leases.isError ? [] : leaseList).map((l) => {
    const privateMac = privacyMac(l.mac);
    const reserved = isReserved(l);
    const note = noteOf(l.mac);
    return [
      <>{l.ip}{reserved && <div><Badge tone="green">Зарезервирован</Badge></div>}</>,
      <span className="mac-value">{l.mac}</span>,
      l.hostname || "—",
      subnetFor(l),
      <>{note || "—"}<div><Button aria-label={`Заметка для ${l.ip}`}
        onClick={() => actions.openLease(l, "note")}>Заметка</Button></div></>,
      fmtRemaining(l.expires_in),
      <>{privateMac && <Badge tone="amber">Приватный MAC</Badge>}
        <Button disabled={privateMac} aria-label={reserved ? `Изменить резервацию ${l.ip}` : `Закрепить ${l.ip}`}
          onClick={() => actions.openLease(l, "bind")}>{reserved ? "Изменить" : "Закрепить"}</Button></>,
    ];
  });
  return (
    <>
      <PageHeader>DHCP (Kea)</PageHeader>
      <RuntimeServiceHeader name="DHCP" serviceName="kea" telemetry={telemetry} />
      <PageTabs values={["Аренды", "Устройства с постоянным IP", "Подсети и диапазоны"]} value={tab} change={setTab} />
      {tab === 0 && <Card title="Текущие аренды" action={<Button onClick={() => void leases.refetch()} disabled={leases.isFetching}>Обновить</Button>}>
        <div className="footer-actions"><Field label="Поиск: MAC, IP, hostname" value={query} onChange={setQuery} fullWidth={false}/><Button onClick={() => setTerm(query.trim())} disabled={leases.isFetching}>Найти</Button></div>
        {term && <div className="footer-actions">Показаны результаты по запросу «{term}» <Button onClick={() => { setQuery(""); setTerm(""); }}>Сбросить</Button></div>}
        <div className="table-wide">
          <DataTable heads={["IP-адрес", "MAC", "Hostname", "Подсеть", "Заметка", "Истекает через", "Действия"]}
            rows={leaseRows} empty={<EmptyState>{leaseEmpty}</EmptyState>}/>
        </div>
      </Card>}
      {tab === 1 && <Card title="Устройства с постоянным IP" action={<Button onClick={actions.addDevice} disabled={!c.dhcp_subnets.length}>Добавить устройство</Button>}>
        {!c.dhcp_subnets.length && <InfoNote>Сначала добавьте подсеть, затем назначьте устройству постоянный IP.</InfoNote>}
        <DataTable heads={["Устройство", "MAC", "Постоянный IP", "Подсеть", "Действия"]}
          rows={c.dhcp_subnets.flatMap((s, si) => s.reservations.map((r, ri) => [
            <>{r.hostname || "—"}{noteOf(r.hw_address) && <div><small>{noteOf(r.hw_address)}</small></div>}</>,
            r.hw_address, r.ip_address, s.subnet,
            <Button onClick={() => actions.editDevice(si, ri)} aria-label={`Изменить устройство ${r.hostname || r.hw_address}`}>Изменить</Button>,
          ]))}
          empty={<EmptyState>Устройств с постоянным IP пока нет</EmptyState>} />
      </Card>}
      {tab === 2 && <Card title="Подсети и диапазоны" action={<Button onClick={actions.editSubnets}>Настроить</Button>}>
        <DataTable heads={["Подсеть", "Интерфейс", "Диапазон адресов", "Адрес роутера", "DNS для клиентов", "Срок аренды"]}
          rows={c.dhcp_subnets.map((s) => [s.subnet, s.interface, s.pools.map((p) => `${p.start}–${p.end}`).join(", ") || "—", s.routers.join(", ") || "—", s.dns_servers.join(", ") || "—", `${s.valid_lifetime} с`])}
          empty={<EmptyState>Подсети DHCP не настроены.</EmptyState>} />
      </Card>}
    </>
  );
}
export function DNS() {
  return (
    <DNSEditor>{(actions) => <DNSReadOnly actions={actions} />}</DNSEditor>
  );
}
function DNSReadOnly({ actions }: { actions: { addRecord: () => void; addForward: () => void; edit: () => void } }) {
  const { configuration } = useConfiguration();
  const { dns, tproxy } = configuration;
  const [policyOpen, setPolicyOpen] = useState(false);
  const telemetry = useServiceTelemetry();
  const formatUpstream = (u: DNSUpstream) => {
    if (u.mode === "https") return `DoH · ${u.doh_server}`;
    const address = `${u.address}:${u.port}`;
    if (u.mode === "tls") return `DoT · ${u.tls_name ? `${u.tls_name} (${address})` : address}`;
    return `DNS (UDP) · ${address}`;
  };
  return (
    <>
      <PageHeader>DNS (Unbound)</PageHeader>
      <RuntimeServiceHeader name="DNS" serviceName="unbound" telemetry={telemetry} />
      <Card title="Локальные имена" action={<Button onClick={actions.addRecord}>Добавить имя</Button>}>
        <DataTable heads={["Имя", "Тип", "Значение", "TTL"]} rows={dns.records.map((r) => [r.name, r.type, r.value, r.ttl])}
          empty={<EmptyState>Локальных имён нет.</EmptyState>} />
      </Card>
      <Card title="Домены с отдельным DNS" action={<Button onClick={actions.addForward}>Добавить домен</Button>}>
        <DataTable heads={["Домен", "DNS-серверы"]} rows={dns.forwards.map((f) => [f.domain, f.upstreams.map(formatUpstream).join(", ")])}
          empty={<EmptyState>Доменов с отдельным DNS нет.</EmptyState>} />
      </Card>
      <Card title="Режим и доступ" action={<Button onClick={actions.edit}>Настроить</Button>}>
        <dl className="kv">
          <dt>Режим</dt><dd>{dns.recursive ? "Самостоятельный поиск" : "Через указанные DNS-серверы"}</dd>
          <dt>DNS-серверы</dt><dd>{dns.upstreams.map(formatUpstream).join(", ") || "—"}</dd>
          <dt>Где отвечает DNS</dt><dd>{dns.interfaces.join(", ") || "—"}</dd>
          <dt>Каким сетям разрешён доступ</dt><dd>{dns.access_control.join(", ") || "—"}</dd>
          <dt>Записывать DNS-запросы</dt><dd>{dns.log_queries ? "Да" : "Нет"}</dd>
          <dt>DNS-политика перехвата</dt><dd>{tproxy.dns.servers.map((s) => `${s.server}${s.server_port ? `:${s.server_port}` : ""}`).join(", ") || "Не задана"}</dd>
        </dl>
      </Card>
      <Card title="Политика DNS для перехвата" action={<Button onClick={() => setPolicyOpen(true)}>Настроить DNS-политику</Button>}>
        <InfoNote>Серверы и правила нужны движку перехвата. Указывайте доступный DNS-сервер: 127.0.0.1:53 в контуре перехвата не слушается.</InfoNote>
      </Card>
      <DnsPolicyDialog open={policyOpen} onClose={() => setPolicyOpen(false)} />
      <Card title="Журнал запросов DNS">
        <EmptyState>Просмотр DNS-запросов пока не подключён к API.</EmptyState>
      </Card>
    </>
  );
}
export { Tunnels } from "./ConnectionEditors";
export function Proxy() {
  const [tab, setTab] = useState(0);
  const telemetry = useServiceTelemetry();
  return (
    <>
      <PageHeader>Прокси (Caddy)</PageHeader>
      {tab === 0 ? <RuntimeServiceHeader name="Входящие сайты" serviceName="caddy" telemetry={telemetry} />
        : <RuntimeServiceHeader name="DDNS" serviceName="ddns" telemetry={telemetry} />}
      <PageTabs
        values={["Сайты", "DDNS", "Журнал"]}
        value={tab}
        change={setTab}
      />
      <div hidden={tab !== 0}>
        <Sites />
      </div>
      <div hidden={tab !== 1}>
        <DDNS />
      </div>
      {tab === 2 && (
        <Card title="Последние запросы к сайтам">
          <InfoNote>Просмотр пока недоступен.</InfoNote>
        </Card>
      )}
    </>
  );
}
