import { useState } from "react";
import { Button } from "@mui/material";
import { useConfiguration } from "../state";
import { Badge } from "../components/Badge";
import { ServiceStatusHeader } from "../components/ServiceStatusHeader";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorNotice } from "../components/ErrorNotice";
import { Field } from "../components/Field";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { PageTabs } from "../components/Tabs";
import { DHCPEditor, DNSEditor } from "./ServiceEditors";
import { Sites, DDNS } from "./ConnectionEditors";
import { api, ApiError } from "../api";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "../query";

export function DHCP() {
  return (
    <DHCPEditor>{(actions) => <DHCPReadOnly actions={actions} />}</DHCPEditor>
  );
}
function DHCPReadOnly({ actions }: { actions: { addDevice: () => void; editDevice: (subnet: number, reservation: number) => void; editSubnets: () => void } }) {
  const { configuration: c } = useConfiguration();
  const [tab, setTab] = useState(0);
  const [query, setQuery] = useState("");
  const [term, setTerm] = useState("");
  // Server state: cached, deduped, and only fetched while the tab is open.
  const leases = useQuery({
    queryKey: queryKeys.dhcpLeases(term),
    queryFn: () => (term ? api.searchLeases(term) : api.dhcpLeases()),
    enabled: tab === 2,
  });
  const leaseError = leases.error;
  return (
    <>
      <PageHeader>DHCP (Kea)</PageHeader>
      <ServiceStatusHeader name="DHCP" state="unknown" />
      <PageTabs values={["Устройства с постоянным IP", "Подсети и диапазоны", "Аренды"]} value={tab} change={setTab} />
      {tab === 0 && <Card title="Устройства с постоянным IP" action={<Button onClick={actions.addDevice} disabled={!c.dhcp_subnets.length}>Добавить устройство</Button>}>
        {!c.dhcp_subnets.length && <InfoNote>Сначала добавьте подсеть, затем назначьте устройству постоянный IP.</InfoNote>}
        <DataTable heads={["Устройство", "MAC", "Постоянный IP", "Подсеть", "Действия"]}
          rows={c.dhcp_subnets.flatMap((s, si) => s.reservations.map((r, ri) => [r.hostname || "—", r.hw_address, r.ip_address, s.subnet,
            <Button onClick={() => actions.editDevice(si, ri)} aria-label={`Изменить устройство ${r.hostname || r.hw_address}`}>Изменить</Button>]))}
          empty={<EmptyState>Устройств с постоянным IP пока нет</EmptyState>} />
      </Card>}
      {tab === 1 && <Card title="Подсети и диапазоны" action={<Button onClick={actions.editSubnets}>Настроить</Button>}>
        <DataTable heads={["Подсеть", "Интерфейс", "Диапазон адресов", "Адрес роутера", "DNS для клиентов", "Срок аренды"]}
          rows={c.dhcp_subnets.map((s) => [s.subnet, s.interface, s.pools.map((p) => `${p.start}–${p.end}`).join(", ") || "—", s.routers.join(", ") || "—", s.dns_servers.join(", ") || "—", `${s.valid_lifetime} с`])} />
      </Card>}
      {tab===2&&<Card title="Текущие аренды" action={<Button onClick={()=>void leases.refetch()} disabled={leases.isFetching}>Обновить</Button>}>
        <div className="footer-actions"><Field label="Поиск: MAC, IP, hostname" value={query} onChange={setQuery} fullWidth={false}/><Button onClick={()=>setTerm(query.trim())} disabled={leases.isFetching}>Найти</Button></div>
        {leaseError instanceof ApiError && (leaseError.status===502||leaseError.status===503) ? <Badge tone="amber">Kea ctrl-agent недоступен</Badge> : <ErrorNotice error={leaseError}/>}
        {leases.isSuccess && <InfoNote>Получено аренд: {leases.data.length}</InfoNote>}
        <DataTable heads={["IP-адрес","MAC","Hostname","Подсеть","Истекает"]} rows={(leases.isError ? [] : leases.data??[]).map(l=>[l.ip,l.mac,l.hostname??"—",l.subnet,l.expires_in])} empty={<EmptyState>{leases.isLoading?"Загрузка аренд…":leaseError?"Не удалось получить аренды":"Нет аренд"}</EmptyState>}/>
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
  const {
    configuration: { dns },
  } = useConfiguration();
  return (
    <>
      <PageHeader>DNS (Unbound)</PageHeader>
      <ServiceStatusHeader name="DNS" state="unknown" />
      <Card title="Локальные имена" action={<Button onClick={actions.addRecord}>Добавить имя</Button>}>
        <DataTable heads={["Имя", "Тип", "Значение", "TTL"]} rows={dns.records.map((r) => [r.name, r.type, r.value, r.ttl])} />
      </Card>
      <Card title="Домены с отдельным DNS" action={<Button onClick={actions.addForward}>Добавить домен</Button>}>
        <DataTable heads={["Домен", "DNS-серверы"]} rows={dns.forwards.map((f) => [f.domain, f.upstreams.map((u) => u.address || u.doh_server).join(", ")])} />
      </Card>
      <Card title="Режим и доступ" action={<Button onClick={actions.edit}>Настроить</Button>}>
        <dl className="kv">
          <dt>Режим</dt><dd>{dns.recursive ? "Самостоятельный поиск" : "Через указанные DNS-серверы"}</dd>
          <dt>DNS-серверы</dt><dd>{dns.upstreams.map((u) => u.address || u.doh_server).join(", ") || "—"}</dd>
          <dt>Где отвечает DNS</dt><dd>{dns.interfaces.join(", ") || "—"}</dd>
          <dt>Каким сетям разрешён доступ</dt><dd>{dns.access_control.join(", ") || "—"}</dd>
          <dt>Записывать DNS-запросы</dt><dd>{dns.log_queries ? "Да" : "Нет"}</dd>
        </dl>
        <InfoNote>Просмотр DNS-запросов здесь пока недоступен.</InfoNote>
      </Card>
    </>
  );
}
export { Tunnels } from "./ConnectionEditors";
export function Proxy() {
  const [tab, setTab] = useState(0);
  return (
    <>
      <PageHeader>Прокси (Caddy)</PageHeader>
      <ServiceStatusHeader name="Caddy" state="unknown" />
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
