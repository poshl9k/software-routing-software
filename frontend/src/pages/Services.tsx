import { useState } from "react";
import { Button } from "@mui/material";
import { useConfiguration } from "../state";
import { Badge } from "../components/Badge";
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
    <DHCPEditor>
      <DHCPReadOnly />
    </DHCPEditor>
  );
}
function DHCPReadOnly() {
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
      <PageTabs
        values={["Подсети", "Резервации", "Аренды"]}
        value={tab}
        change={setTab}
      />
      {tab === 0 && (
        <Card title="Подсети и пулы">
          <DataTable
            heads={[
              "Подсеть",
              "Интерфейс",
              "Пул",
              "Шлюз / DNS",
              "Резерваций",
            ]}
            rows={c.dhcp_subnets.map((s) => [
              s.subnet,
              s.interface,
              s.pools.map((p) => `${p.start}–${p.end}`).join(", "),
              `${s.routers.join(", ")} / ${s.dns_servers.join(", ")}`,
              s.reservations.length,
            ])}
          />
        </Card>
      )}
      {tab !== 2 && (
        <Card title="Резервации">
          <DataTable
            heads={["Имя", "Идентификатор", "IP-адрес", "Подсеть"]}
            rows={c.dhcp_subnets.flatMap((s) =>
              s.reservations.map((r) => [
                r.hostname,
                r.hw_address,
                r.ip_address,
                s.subnet,
              ]),
            )}
          />
          <p className="sub">
            Резервации допустимы внутри динамического пула и вне его. Конфликты
            с действующими арендами требуют runtime API.
          </p>
        </Card>
      )}
      {tab===2&&<Card title="Текущие аренды" action={<Button onClick={()=>void leases.refetch()} disabled={leases.isFetching}>Обновить</Button>}>
        <div className="footer-actions"><Field label="Поиск: MAC, IP, hostname" value={query} onChange={setQuery} fullWidth={false}/><Button onClick={()=>setTerm(query.trim())} disabled={leases.isFetching}>Найти</Button></div>
        {leaseError instanceof ApiError && (leaseError.status===502||leaseError.status===503) ? <Badge tone="amber">Kea ctrl-agent недоступен</Badge> : <ErrorNotice error={leaseError}/>}
        <DataTable heads={["IP-адрес","MAC","Hostname","Подсеть","Истекает"]} rows={(leases.data??[]).map(l=>[l.ip,l.mac,l.hostname??"—",l.subnet,l.expires_in])} empty={<EmptyState>{leases.isLoading?"Загрузка аренд…":leaseError?"Не удалось получить аренды":"Нет аренд"}</EmptyState>}/>
      </Card>}
    </>
  );
}
export function DNS() {
  return (
    <DNSEditor>
      <DNSReadOnly />
    </DNSEditor>
  );
}
function DNSReadOnly() {
  const {
    configuration: { dns },
  } = useConfiguration();
  const [tab, setTab] = useState(0);
  return (
    <>
      <PageHeader>DNS (Unbound)</PageHeader>
      <PageTabs
        values={[
          "Записи и переадресация",
          "Upstream и режим",
          "Журнал запросов",
        ]}
        value={tab}
        change={setTab}
      />
      <div className="grid-2">
        {tab === 0 && (
          <div>
            <Card title="Локальные записи (host overrides)">
              <DataTable
                heads={["Имя", "Тип", "Значение", "TTL"]}
                rows={dns.records.map((r) => [r.name, r.type, r.value, r.ttl])}
              />
            </Card>
            <Card title="DNS-переадресация по доменам">
              <DataTable
                heads={["Домен", "Upstream"]}
                rows={dns.forwards.map((f) => [
                  f.domain,
                  f.upstreams.map((u) => u.address).join(", "),
                ])}
              />
              <p className="sub">
                Домен целиком уходит на указанный сервер (forward-zone).
              </p>
            </Card>
          </div>
        )}
        {tab !== 2 && (
          <div>
            <Card title="Режим и привязка">
              <dl className="kv">
                <dt>Режим</dt>
                <dd>
                  <Badge>{dns.recursive ? "рекурсия" : "forwarding"}</Badge>
                </dd>
                <dt>Upstream</dt>
                <dd>{dns.upstreams.join(", ") || "—"}</dd>
                <dt>Слушает</dt>
                <dd>{dns.interfaces.join(", ") || "—"}</dd>
                <dt>Доступ</dt>
                <dd>{dns.access_control.join(", ") || "—"}</dd>
                <dt>Журнал запросов</dt>
                <dd>
                  <Badge tone={dns.log_queries ? "green" : "amber"}>
                    {dns.log_queries ? "вкл" : "выкл"}
                  </Badge>
                </dd>
              </dl>
            </Card>
            <Card title="Диагностика резолвинга">
              <InfoNote>Живая диагностика резолвинга пока недоступна.</InfoNote>
            </Card>
          </div>
        )}
      </div>
      {tab === 2 && (
        <Card title="Журнал запросов">
          <InfoNote>Просмотр пока недоступен.</InfoNote>
        </Card>
      )}
    </>
  );
}
export { Tunnels } from "./ConnectionEditors";
export function Proxy() {
  const [tab, setTab] = useState(0);
  return (
    <>
      <PageHeader>Прокси (Caddy)</PageHeader>
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
