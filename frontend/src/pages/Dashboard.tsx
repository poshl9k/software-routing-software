import { Button, Typography } from "@mui/material";
import { Link } from "react-router-dom";
import { useConfiguration, statusLabels } from "../state";
import { Badge, Card, DataTable, Todo } from "../ui";
export function Events() {
  return (
    <Card title="Последние события">
      <Todo />
      <DataTable
        heads={["Время", "Событие", "Сообщение"]}
        rows={[]}
      />
    </Card>
  );
}
export default function Dashboard() {
  const { configuration: c, versions, applyState } = useConfiguration();
  const draft = versions.find((v) => v.status === "draft");
  return (
    <>
      <Typography component="h1" variant="h1" className="page-title">
        Обзор сети
      </Typography>
      <div className="status-strip">
        <div className="status-pill">
          🌐{" "}
          <div>
            <b>Интернет</b>
            <div className="sub">TODO-API · статус неизвестен</div>
          </div>
        </div>
        <div className="status-pill">
          ⇅{" "}
          <div>
            <b>WAN</b>
            <div className="sub">TODO-API · скорость неизвестна</div>
          </div>
        </div>
        <div className="status-pill">
          ✔{" "}
          <div>
            <b>Система</b>
            <div className="sub">TODO-API · телеметрия отсутствует</div>
          </div>
        </div>
        <div className="status-pill">
          <div>
            <Badge tone="amber">
              {applyState
                ? statusLabels[applyState.result.status]
                : draft
                  ? `Черновик v${draft.id}`
                  : "Маркер недоступен"}
            </Badge>
            <div className="sub">
              {applyState
                ? "Последний ответ команды в этой вкладке"
                : "TODO-API · неподтверждённые изменения: неизвестно"}
            </div>
          </div>
        </div>
        <Button component={Link} to="/apply" variant="contained">
          Настроить
        </Button>
      </div>
      <div className="dash-grid">
        <div>
          <Card title="WAN / Интернет" to="/network">
            <DataTable
              heads={["Интерфейс", "IP-адрес", "DNS", "Трафик"]}
              rows={c.interfaces
                .filter((i) => i.zone === "wan")
                .map((i) => [
                  <b>{i.name}</b>,
                  i.addresses.join(", "),
                  c.dns.upstreams.join(", "),
                  "TODO-API",
                ])}
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
                "TODO-API",
                "—",
              ])}
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
                "TODO-API",
              ])}
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
                "TODO-API",
                t.role === "server" ? t.peers.length : "клиент",
                "—",
              ])}
            />
          </Card>
          <Card title="Прокси (Caddy)" to="/proxy">
            <DataTable
              heads={["Домен", "Upstream", "TLS", "Статус"]}
              rows={c.sites.map((s) => [
                s.hostname,
                s.upstream,
                s.certificate_mode,
                "TODO-API",
              ])}
            />
          </Card>
          <Events />
        </div>
      </div>
    </>
  );
}
