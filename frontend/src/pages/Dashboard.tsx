import { Button } from "@mui/material";
import { Link } from "react-router-dom";
import { useConfiguration, statusLabels } from "../state";
import { Badge } from "../components/Badge";
import { StatusHero } from "../components/StatusHero";
import { StatTile } from "../components/StatTile";
import { Card } from "../components/Card";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { InfoNote } from "../components/InfoNote";
import { PageHeader } from "../components/PageHeader";
import { RuntimeServiceInline, useServiceTelemetry } from "./Services";

export function Events({ standalone = true }: { standalone?: boolean }) {
  return (
    <>
      {standalone && <PageHeader>Журнал событий</PageHeader>}
      <Card title="Последние события">
        <EmptyState>Просмотр событий пока не подключён к API.</EmptyState>
      </Card>
    </>
  );
}
export default function Dashboard() {
  const { configuration: c, versions, applyState } = useConfiguration();
  const telemetry = useServiceTelemetry();
  const draft = versions.find((v) => v.status === "draft");
  const confirmed = versions.find((v) => v.status === "confirmed");
  return (
    <>
      <PageHeader>Обзор сети</PageHeader>
      <Card title="Службы · текущее состояние">
        <DataTable
          heads={["Служба", "Состояние"]}
          rows={([ ["DHCP", "kea"], ["DNS", "unbound"], ["Caddy", "caddy"], ["DDNS", "ddns"] ] as const).map(([label, name]) => [
            label,
            <RuntimeServiceInline name={name} telemetry={telemetry} />,
          ])}
          empty={<EmptyState>Службы не настроены.</EmptyState>}
        />
      </Card>
      <StatusHero title="Интернет · состояние соединения" tone="unknown" primary={null}
        facts={[{ label: "Источник", value: "Телеметрия не подключена" }, { label: "WAN и адрес сейчас", value: "Нет данных" }]}
        action={<Button component={Link} to="/network" variant="outlined">Подключения и адреса</Button>} />
      <div className="dash-grid">
        <StatTile label="Скорость WAN" value={null} hint="Нет данных от агента" />
        <StatTile label="Время работы" value={null} hint="Нет телеметрии" />
      </div>
      <InfoNote>
        Конфигурация: {draft ? `черновик v${draft.id} (не применён)` : "черновика нет"};{" "}
        {confirmed ? `подтверждена v${confirmed.id}` : "подтверждённой версии нет"}.
        Настроенные параметры ниже не означают, что они действуют сейчас.
        {applyState ? ` Последний ответ команды в этой вкладке: ${statusLabels[applyState.result.status]}.` : " Состояние агента здесь не показано."}
      </InfoNote>
      <div className="dash-grid">
        <div>
          <Card title="Конфигурация WAN / Интернет" to="/network">
            <DataTable
              heads={["Интерфейс", "IP-адрес", "DNS", "Трафик"]}
              rows={c.interfaces
                .filter((i) => i.zone === "wan")
                .map((i) => [
                  <b>{i.name}</b>,
                  i.addresses.join(", "),
                  c.dns.upstreams.map((u) => u.address).join(", "),
                  "—",
                ])}
              empty={<EmptyState>Интерфейсы WAN не настроены.</EmptyState>}
            />
          </Card>
          <Card title="DHCP" to="/dhcp">
            <div className="stats">
              <div>
                <strong>{c.dhcp_subnets.length}</strong>Подсети
              </div>
              <div>
                <strong>—</strong>Активных аренд
              </div>
              <div>
                <strong>
                  {c.dhcp_subnets.reduce(
                    (n, s) => n + s.reservations.length,
                    0,
                  )}
                </strong>
                Резерваций
              </div>
            </div>
            <DataTable
              heads={["Подсеть", "Диапазон", "Аренд", "Использование"]}
              rows={c.dhcp_subnets.map((s) => [
                s.interface,
                s.subnet,
                "—",
                "—",
              ])}
              empty={<EmptyState>Подсети DHCP не настроены.</EmptyState>}
            />
          </Card>
          <Card title="Интерфейсы и VLAN" to="/network">
            <DataTable
              heads={["Интерфейс", "Тип", "Зона", "IP-адрес", "Состояние"]}
              rows={c.interfaces.map((i) => [
                i.name,
                i.type,
                <Badge>{i.zone ?? "fail-closed"}</Badge>,
                i.addresses.join(", "),
                "—",
              ])}
              empty={<EmptyState>Интерфейсы не настроены.</EmptyState>}
            />
          </Card>
        </div>
        <div>
          <Card title="Туннели" to="/tunnels">
            <DataTable
              heads={["Название", "Тип", "Статус", "Пиры", "Трафик"]}
              rows={c.tunnels.map((t) => [
                t.name,
                t.protocol === "wg" ? "WireGuard" : "AmneziaWG",
                <RuntimeServiceInline name={`tunnel:${t.interface}`} telemetry={telemetry} showAsOf={false} />,
                t.role === "server" ? t.peers.length : "клиент",
                "—",
              ])}
              empty={<EmptyState>Туннели не настроены.</EmptyState>}
            />
          </Card>
          <Card title="Прокси (Caddy)" to="/proxy">
            <DataTable
              heads={["Домен", "Upstream", "TLS", "Статус"]}
              rows={c.sites.map((s) => [
                s.hostname,
                s.upstream,
                s.certificate_mode,
                "—",
              ])}
              empty={<EmptyState>Сайты не настроены.</EmptyState>}
            />
          </Card>
          <Events standalone={false} />
        </div>
      </div>
    </>
  );
}