# DoT/DoH upstream в общей DNS-конфигурации — дизайн (предложение)

Статус: **предложение**, не принято; ADR не заведён. Обязательный пункт владельца
продукта: общая DNS-конфигурация (не только DNS-политика sing-box) должна
поддерживать **DoT и DoH** как upstream.

## Что есть сейчас
- Модель `DNS` (`schema.py`): `interfaces, access_control, records, forwards,
  upstreams, recursive, log_queries`. `upstreams` и `forwards[].upstreams` —
  просто **список IP-строк** (plain UDP/TCP 53).
- Генератор `generators/unbound.py`: `forward-zone` + `forward-addr: <ip>`;
  ndots/DoT/DoH не выражаются. Проверка — `unbound-checkconf`.

## Возможности Unbound (проверено на VM, Unbound 1.26.1)
- **DoT (upstream) — нативно:** `forward-tls-upstream: yes` (global или per-zone)
  плюс `forward-addr: <ip>@853#<tls-name>`.
- **DoH у Unbound — только серверная сторона**, upstream-клиента DoH нет:
  в бинарнике есть `https-port` / `dohpath` / `listen doh sslctx` (это DoH-*сервер*),
  строки DoH-*клиента* отсутствуют.
  → **DoH как upstream нельзя сделать «штатным Unbound»**; нужен внешний
  DoH-клиент, к которому Unbound форвардит локально.

## Решение (компонент DoH-клиента)
Принято: **`dnscrypt-proxy`** — отдельный локальный DoH/DoT-клиент; Unbound форвардит
на него. Обоснование: один статический бинарник, поддерживает и DoH, и DoT, есть в
Debian-репозитории (пиннится тем же snapshot, что и остальные пакеты), простой
TOML-конфиг, нет привязки к Cloudflare (в отличие от `cloudflared`) и нет связки
общей DNS с TProxy-движком sing-box. DoT при этом реализуется нативно в Unbound,
`dnscrypt-proxy` нужен для DoH. Перед реализацией — завести ADR (пиннинг по ADR-0005,
install-time доставка как у sing-box, отдельный systemd-юнит).

## Варианты (историческая запись)
- **A. DoT — в Unbound (нативно), DoH — через отдельный DoH-клиент.**
  DoT: `forward-tls-upstream` + `@853#sni`. DoH: пиннутый DoH-клиент
  (`dnscrypt-proxy`) на `127.0.0.1:<port>`, Unbound форвардит на него. ← **выбрано**
- **B. И DoT, и DoH — через один внешний резолвер** (dnscrypt-proxy умеет оба;
  cloudflared — DoH). Единый путь, но теряется нативный DoT.
- **C. DoH отложить до DNS-политики sing-box** (слайс S6). Минус: общая DNS станет
  зависеть от TProxy-движка.

## Набросок модели (черновой, требует ADR)
```
class DNSUpstream(Model):
    address: str
    port: int = 53
    mode: Literal["udp", "tls", "https"] = "udp"
    tls_name: str | None = None   # SNI / DoH-хост (обязателен для tls/https)
```
`dns.upstreams: tuple[DNSUpstream, ...]`, `dns.forwards[].upstreams` — тот же тип.
Генератор: `tls` → `forward-addr: ip@853#name` + `forward-tls-upstream: yes`;
`https` → forward на локальный DoH-клиент (адрес клиента), сам клиент — отдельный
пиннутый юнит. Совместимость старых конфигов: строка-IP → `mode=udp`.

## Открытые решения (нужны до кода)
1. Компонент DoH-клиента: `dnscrypt-proxy` vs `cloudflared` (пиннинг по ADR-0005,
   доставка install-time как sing-box).
2. Гранулярность: DoT/DoH глобально или per-forward-zone.
3. DoH-клиент как отдельный systemd-юнит vs unicast к маршрутизатору.
4. Нужен ли серверный DoH (`https-port`) — сейчас не цель.
5. Взаимодействие с TProxy-DNS-контуром (ADR-0014): общий vs раздельные upstream.

## Вне объёма
Зашифрованный DNS клиентов (DoH/DoT *от* клиентов к роутеру) — это серверный DoH,
не приоритет.

## Статус
- **D1 — сделано:** схема `DNSUpstream {address, port, mode: udp|tls, tls_name}` +
  обратная совместимость (голый IP-строкой), DoT в генераторе Unbound
  (`forward-addr: ip@853#sni` + `forward-tls-upstream` per-zone), валидатор
  (`dns.upstream_invalid`, `dns.upstream_tls_name_required`), UI-редактор принимает
  текст `ip[@port][#tls-name]`. Проверено: backend 851, frontend 96, tsc/build ok.
- **D2 — контракт+генераторы сделано:** режим `https` (`doh_server`), Unbound форвардит
  `https`-upstream'ы на локальный `127.0.0.1:5300` (+ `do-not-query-localhost: no`, без
  `forward-tls-upstream`), новый `generators/dnscrypt.py` (пакет `dnscrypt-proxy`,
  `server_names` из встроенных имён, отсортирован и без дублей). Проверено: backend 856,
  frontend 96, tsc/build ok.
- **D2b — сделано:** `dnscrypt-proxy` в bootstrap (пакет пиннится снапшотом) + mask
  дистрибутивных юнитов (`dnscrypt-proxy.socket` занял бы loopback:53); `agent/dnscrypt_service.py`
  (verify → config-check → enable → ready, без capabilities); аддитивная DoH-ветка в
  `apply.py` (`dnscrypt.toml`, readiness-step до фазы `unbound`, teardown при откате).
  Конфигурации без https-upstream'ов байт-в-байт как раньше. Проверено: backend 869.
  **Осталось:** живой прогон на VM (`dnscrypt-proxy -check`, `systemctl`, DoH-резолв).
- **D3 — сделано:** структурный редактор upstream (режим UDP/DoT/DoH + адрес/порт/
  tls_name/doh_server, поля по режиму, валидация как на бэкенде), общий компонент
  `UpstreamRows` для корневого и per-domain списков вместо текстового поля. Проверено:
  frontend 97, tsc/build ok.
