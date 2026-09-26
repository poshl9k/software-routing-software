import { useState } from "react";
import { Tab, Tabs, Typography } from "@mui/material";
import { useConfiguration } from "../state";
import { Badge, Card, DataTable } from "../ui";
export default function Firewall() {
  const { configuration: c } = useConfiguration();
  const zones = [
    ...new Set([
      "wan",
      "lan",
      "router",
      ...c.interfaces.flatMap((i) => (i.zone ? [i.zone] : [])),
      ...c.firewall_rules.map((r) => r.ingress_zone),
    ]),
  ];
  const [tab, setTab] = useState("wan");
  const zone = zones.includes(tab);
  return (
    <>
      <Typography component="h1" variant="h1" className="page-title">
        Firewall
      </Typography>
      <Tabs
        value={tab}
        onChange={(_, value: string) => setTab(value)}
        variant="scrollable"
      >
        {[...zones, "Port Forward", "Outbound NAT", "Псевдонимы"].map((z) => (
          <Tab key={z} value={z} label={z} />
        ))}
      </Tabs>
      {zone && (
        <Card title={`Правила зоны ${tab}`}>
          <DataTable
            heads={[
              "Порядок",
              "Действие",
              "Протокол",
              "Источник",
              "Назначение",
              "Порт",
              "Счётчики (states / packets / bytes)",
              "Лог",
            ]}
            rows={c.firewall_rules
              .filter((r) => r.ingress_zone === tab)
              .sort((a, b) => a.order - b.order)
              .map((r) => [
                r.order,
                <span style={{ opacity: r.enabled ? 1 : 0.45 }}>
                  <Badge tone={r.action === "pass" ? "green" : "red"}>
                    {r.action}
                    {!r.enabled && " · выкл"}
                  </Badge>
                </span>,
                r.protocol,
                r.src,
                r.dst,
                r.destination_ports ?? "любой",
                "TODO-API · runtime",
                r.log ? "●" : "—",
              ])}
          />
          <p className="sub">
            First match wins. В конце набора — неявный default deny. Изменение
            порядка и редактирование: TODO-API.
          </p>
          <Badge>
            Anti-lockout: доступ к панели с lan —{" "}
            {c.anti_lockout ? "вкл" : "выкл"}
          </Badge>
        </Card>
      )}
      <div className={zone ? "grid-2" : undefined}>
        {(zone || tab === "Port Forward") && (
          <Card title="Port Forward">
            <DataTable
              heads={[
                "Интерфейс",
                "Протокол",
                "Внешний адрес",
                "Внешний порт",
                "Цель",
                "FW-правило",
              ]}
              rows={c.port_forwards.map((p) => [
                p.interface,
                p.protocol,
                p.wan_address ?? "основной",
                p.external_port,
                `${p.target}:${p.target_port}`,
                <Badge>авто{!p.enabled && " · выкл"}</Badge>,
              ])}
            />
            <p className="sub">
              Port forward приоритетнее локальных сервисов роутера на том же
              порту.
            </p>
          </Card>
        )}
        {(zone || tab === "Outbound NAT") && (
          <Card
            title="Outbound NAT"
            action={<Badge tone="amber">режим: {c.outbound_nat_mode}</Badge>}
          >
            <DataTable
              heads={[
                "Зона выхода",
                "Источник",
                "Назначение",
                "Протокол",
                "Translation",
                "Do not NAT",
              ]}
              rows={[...c.outbound_nat]
                .sort((a, b) => a.order - b.order)
                .map((n) => [
                  n.egress_zone,
                  n.src,
                  n.dst,
                  n.protocol,
                  n.translation,
                  n.do_not_nat ? "да" : "нет",
                ])}
            />
            <p className="sub">
              First match wins. Путь выбирает таблица маршрутизации.
            </p>
          </Card>
        )}
      </div>
      {(zone || tab === "Псевдонимы") && (
        <Card title="Псевдонимы (алиасы)">
          <DataTable
            heads={["Имя", "Тип", "Содержимое", "Вложение"]}
            rows={c.aliases.map((a) => [
              a.name,
              a.type === "address" ? "Адреса" : "Порты",
              a.elements.join(", "),
              a.includes.join(", "),
            ])}
          />
        </Card>
      )}
    </>
  );
}
