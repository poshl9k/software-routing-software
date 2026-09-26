import { useState } from "react";
import { Tab, Tabs, TextField, Typography } from "@mui/material";
import { useConfiguration } from "../state";
import { Badge, Card, DataTable, Todo } from "../ui";
import { DHCPEditor, DNSEditor } from "./ServiceEditors";
import { Sites, DDNS } from "./ConnectionEditors";
import { demoLeases } from "../fixtures";
function PageTabs({
  values,
  value,
  change,
}: {
  values: string[];
  value: number;
  change: (n: number) => void;
}) {
  return (
    <Tabs
      value={value}
      onChange={(_, n: number) => change(n)}
      variant="scrollable"
    >
      {values.map((v) => (
        <Tab key={v} label={v} />
      ))}
    </Tabs>
  );
}
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
  return (
    <>
      <Typography component="h1" variant="h1" className="page-title">
        DHCP (Kea)
      </Typography>
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
              "Аренд",
              "Резерваций",
            ]}
            rows={c.dhcp_subnets.map((s) => [
              s.subnet,
              s.interface,
              s.pools.map((p) => `${p.start}–${p.end}`).join(", "),
              `${s.routers.join(", ")} / ${s.dns_servers.join(", ")}`,
              "TODO-API",
              s.reservations.length,
            ])}
          />
        </Card>
      )}
      {tab !== 2 && (
        <Card title="Резервации">
          <DataTable
            heads={["Имя", "Идентификатор", "IP-адрес", "Подсеть", "Конфликт"]}
            rows={c.dhcp_subnets.flatMap((s) =>
              s.reservations.map((r) => [
                r.hostname,
                r.hw_address,
                r.ip_address,
                s.subnet,
                "TODO-API",
              ]),
            )}
          />
          <p className="sub">
            Резервации допустимы внутри динамического пула и вне его. Конфликты
            с действующими арендами требуют runtime API.
          </p>
        </Card>
      )}
      {(tab === 0 || tab === 2) && (
        <Card
          title="Текущие аренды"
          action={
            <TextField
              label="Поиск: MAC, IP, hostname"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          }
        >
          <Todo />
          <DataTable
            heads={["IP-адрес", "MAC", "Hostname", "Подсеть", "Истекает"]}
            rows={demoLeases
              .filter((l) =>
                `${l.ip} ${l.mac} ${l.hostname}`
                  .toLowerCase()
                  .includes(query.toLowerCase()),
              )
              .map((l) => [l.ip, l.mac, l.hostname, l.subnet, l.expires])}
          />
        </Card>
      )}
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
      <Typography component="h1" variant="h1" className="page-title">
        DNS (Unbound)
      </Typography>
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
                  f.upstreams.join(", "),
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
              <Todo />
              <DataTable
                heads={["Время", "Запрос", "Результат"]}
                rows={dnsDiagnostics.map((d) => [
                  d.time,
                  d.query,
                  <Badge tone={d.ok ? "green" : "red"}>{d.result}</Badge>,
                ])}
              />
            </Card>
          </div>
        )}
      </div>
      {tab === 2 && (
        <Card title="Журнал запросов">
          <Todo>Чтение журнала DNS пока недоступно.</Todo>
          <DataTable heads={["Время", "Клиент", "Запрос", "Ответ"]} rows={[]} />
        </Card>
      )}
    </>
  );
}
interface DNSDiagnostic {
  time: string;
  query: string;
  result: string;
  ok: boolean;
}
const dnsDiagnostics: DNSDiagnostic[] = [
  {
    time: "14:21:02",
    query: "nas.home.lan",
    result: "192.168.10.10 (local)",
    ok: true,
  },
  { time: "14:18:12", query: "broken.invalid", result: "NXDOMAIN", ok: false },
];
export { Tunnels } from "./ConnectionEditors";
export function Proxy() {
  const [tab, setTab] = useState(0);
  return (
    <>
      <Typography component="h1" variant="h1" className="page-title">
        Прокси (Caddy)
      </Typography>
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
          <Todo />
          <DataTable
            heads={["Время", "Сайт", "Метод", "Путь", "Код", "Задержка"]}
            rows={proxyLogs.map((l) => [
              l.time,
              l.site,
              l.method,
              l.path,
              l.code,
              l.latency,
            ])}
          />
        </Card>
      )}
    </>
  );
}
interface ProxyLog {
  time: string;
  site: string;
  method: string;
  path: string;
  code: number;
  latency: string;
}
const proxyLogs: ProxyLog[] = [
  {
    time: "14:22:41",
    site: "home.example.ru",
    method: "GET",
    path: "/api/events",
    code: 200,
    latency: "34 мс",
  },
  {
    time: "14:22:12",
    site: "nastya.example.ru",
    method: "GET",
    path: "/",
    code: 502,
    latency: "backend недоступен",
  },
];
