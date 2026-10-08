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

## Варианты
- **A. DoT — в Unbound (нативно), DoH — через отдельный DoH-клиент.**
  DoT: `forward-tls-upstream` + `@853#sni`. DoH: поднять пиннутый DoH-клиент
  (`dnscrypt-proxy` или `cloudflared proxy-dns`) на `127.0.0.1:<port>`, а Unbound
  форвардит на него. Плюс: DoT прост и надёжен; минус: ещё один компонент/юнит.
- **B. И DoT, и DoH — через один внешний резолвер** (dnscrypt-proxy умеет оба;
  cloudflared — DoH). Единый путь, но теряется нативный DoT и добавляется
  зависимость для обоих режимов.
- **C. DoH отложить до DNS-политики sing-box** (слайс S6/sing-box DNS — он умеет
  DoH/DoT outbound). Минус: общая DNS станет зависеть от TProxy-движка.

## Рекомендация
Вариант **A**: DoT реализовать нативно в Unbound; DoH — через пиннутый
`dnscrypt-proxy` (простой, статический конфиг, DoH/DoT, без GUI). Серверный DoH у
Unbound (`https-port`) — отдельный необязательный плюс, не цель.

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
