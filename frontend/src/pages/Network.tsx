import { Tab, Tabs, Typography } from "@mui/material";
import { useSearchParams } from "react-router-dom";
import { useConfiguration } from "../state";
import { Badge, Card, DataTable, Todo } from "../ui";
export default function Network() {
  const { configuration: c } = useConfiguration();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "interfaces";
  const knownTab = ["interfaces", "wan", "routes", "diagnostics"].includes(tab)
    ? tab
    : "interfaces";
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
        <Card title="Интерфейсы и зоны">
          <DataTable
            heads={[
              "Интерфейс",
              "Тип",
              "Зона",
              "Адресация",
              "IP-адрес",
              "Состояние",
              "Назначение",
            ]}
            rows={c.interfaces.map((i) => [
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
            ])}
          />
        </Card>
      )}
      {(knownTab === "interfaces" || knownTab === "wan") &&
        c.interfaces
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
                равноценны в firewall и NAT.
              </p>
            </Card>
          ))}
      {knownTab === "routes" && (
        <Card title="Статические маршруты">
          <Todo>Маршруты отсутствуют в текущей модели API.</Todo>
          <DataTable
            heads={["Сеть назначения", "Шлюз", "Интерфейс", "Метрика"]}
            rows={[]}
          />
        </Card>
      )}
      {(knownTab === "interfaces" || knownTab === "diagnostics") && (
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
