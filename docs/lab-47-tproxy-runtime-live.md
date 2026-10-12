# Lab 47 — TProxy включён на VM, движок реально запущен (runtime-приёмка)

Verdict: **PASS** для «TProxy включается и движок sing-box реально работает» на одноразовой VM
`vsr-fresh-695476d`. Это приёмка **runtime-слоя** (движок/nft/DNS/Clash API); полноценный
транзит трафика через внешний прокси-выход не проверялся — политика построена на `action=direct`
(без прокси-выхода), что достаточно для доказательства слоя.

## Что сделано

Раздел TProxy активирован через **штатный путь приложения** (HTTP API, роль admin): черновик →
`tproxy.enabled=true`, `ingress_interfaces=["enp2s0"]` (LAN), одно правило (`action=direct`),
`final=direct`, `sniff=true` → `POST /api/apply`. Применено как версия **3** (`confirmed`).
Использован постоянный guest-agent helper; raw-SQLite правок не делалось, секретов не создавалось.

Требования валидаторов, важные при включении (проверено по `validators.py:99-116`):
- `tproxy.ingress_interface` — каждый ingress-интерфейс обязан существовать в конфигурации и иметь
  зону не `wan`/`None` (то есть capture — только LAN-сторона).
- `tproxy.enabled_incomplete` — при `enabled=true` нужны и ingress, и хотя бы одно правило.
- `route`-правило допустимо только на объявленный выход при `proxies.enabled`; правило `direct`
  прокси-выхода не требует — поэтому включение возможно без прокси-выхода.

## Независимо проверенные свидетельства (выполнено отдельно от субагента)

```
# юниты
vs-router-singbox.service        active running  vs-router sing-box TProxy engine
vs-router-unbound-selected.service active running
vs-router-unbound-ordinary.service active running
vs-router-web/-agent, bootrestore, ddns/source timers — active

# процесс движка
pgrep -a sing-box
4746 /usr/local/lib/vs-router/sing-box run -c /etc/vs-router/applied/singbox.json

# Clash API (loopback)
curl -s http://127.0.0.1:9099/version
{"meta":true,"premium":true,"version":"sing-box 1.14.2"}

# nftables tproxy-таблицы
nft list tables
table inet vs_router_tproxy_guard / _ipv6_guard / _preauth / _dns_ingress / _dns_listener /
_dns_output / _ct_reset / _interception   (+ vs_router, vs_router_ssh_lock)

cat /proc/sys/net/ipv4/ip_forward
1

# панель и runtime-API (HTTPS, admin)
GET https://192.168.10.1/                         → 200
GET /api/runtime/engine → {"installed":true,"version":"1.14.2","running":true,"pid":4746,
                           "clash_api":true,"ip_forward":true,"nft_tproxy_tables":true}
GET /api/runtime/connections                      → 200
GET /api/versions → [(3,'confirmed',tproxy.enabled=True),(2,'confirmed',False),(1,'confirmed',False)]
```

## Итог

| Проверка | Результат |
| --- | --- |
| `vs-router-singbox.service` active | PASS |
| Процесс `sing-box run` (PID 4746) | PASS |
| Clash API `127.0.0.1:9099/version` | PASS (sing-box 1.14.2) |
| nftables TProxy-таблицы установлены | PASS |
| `ip_forward=1` | PASS |
| `/api/runtime/engine` running/clash_api/nft | PASS |
| `/api/runtime/connections` | PASS (200, пусто — соединений нет) |
| Панель HTTPS | PASS (200) |

## Ограничения

- Прокси-выход не добавлялся; политика `direct`-only. Для реальной маршрутизации оператор добавляет
  выход (Прокси-выходы / импорт ссылки) и правило «через выход».
- Транзит пакетов через прокси и fail-closed не проверялись (это отдельная packet-path приёмка,
  ср. lab-37…lab-44 для TProxy и lab-45 для AND-матчера).
- О влиянии TProxy ingress на management-трафик: `final=direct`, поэтому management-доступ сохранён
  (панель отвечает 200).

VM оставлена включённой: TProxy включён и применён, владелец может открыть панель и увидеть раздел.
