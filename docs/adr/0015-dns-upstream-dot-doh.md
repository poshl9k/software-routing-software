# ADR-0015: DoT/DoH upstream в общей DNS-конфигурации

**Статус:** принят
**Дата:** 2026-10-08
**Участники:** владелец продукта и Hermes Agent

## Контекст

Общей DNS-конфигурации (не только DNS-политике sing-box) нужны зашифрованные
upstream'ы: **DoT** и **DoH**. Сейчас `DNS.upstreams` и `DNSForward.upstreams` —
просто список IP-строк; `generators/unbound.py` эмитит plain `forward-addr: <ip>`.
Проверено на VM (Unbound 1.26.1): **DoT upstream — нативный**
(`forward-tls-upstream: yes` + `forward-addr: <ip>@853#<tls-name>`); **DoH у Unbound
только серверный** (`https-port` / `dohpath`), upstream-клиента DoH нет. Значит
DoH требует внешнего DoH-клиента. Владелец продукта выбрал: **`dnscrypt-proxy`**
(есть в Debian-репозитории → пиннится тем же snapshot, что kea/unbound/nftables,
без отдельного install-time downloader, как у sing-box; умеет DoH и DoT).

## Решение

1. **Модель.** Новый тип `DNSUpstream`:
   `{ address: str = "", port: int = 53, mode: Literal["udp","tls","https"] = "udp",
   tls_name: str | None = None, doh_server: str | None = None }`.
   `doh_server` — **встроенное имя** резолвера из списка dnscrypt-proxy
   (`cloudflare`, `quad9`, …); свой DoH-сервер (`sdns://`-stamp) — отдельная задача.
   `DNS.upstreams` и `DNSForward.upstreams` становятся `tuple[DNSUpstream, ...]`.
   **Обратная совместимость:** строка вида `"1.1.1.1"` коэрцится в
   `DNSUpstream(address=...)` (mode `udp`) до валидации; старые конфиги читаются
   без миграции.
2. **DoT (`mode=tls`).** Рендерится самим Unbound: `forward-addr: <ip>@<port>#<tls_name>`
   + `forward-tls-upstream: yes` в соответствующем `forward-zone`. Требуется `tls_name`.
3. **DoH (`mode=https`).** Unbound не умеет: отдельный `dnscrypt-proxy` слушает
   `127.0.0.1:5300`, в его конфиге `server_names` = встроенные имена DoH-серверов;
   Unbound форвардит `https`-upstream'ы на этот локальный адрес (и получает
   `do-not-query-localhost: no`). `dnscrypt-proxy` — системный пакет (пиннинг
   снапшотом как у kea/unbound), отдельный systemd-юнит. Требуется `doh_server`.
4. **Смешение разрешено:** `udp`/`tls` реализуются Unbound напрямую, `https` — через
   `dnscrypt-proxy`; записи могут сосуществовать в одном списке.
5. **Валидация:** `udp`/`tls` требуют непустой `address` (IPv4/IPv6), `mode=tls`
   требует `tls_name`; `mode=https` требует `doh_server` и не должен нести
   `address`/`tls_name`; коды `dns.upstream_invalid`, `dns.upstream_address_required`,
   `dns.upstream_tls_name_required`, `dns.upstream_doh_server_required`,
   `dns.upstream_doh_server_unexpected`.
6. **UI:** редактор upstream (режим + `tls_name`/`doh_server`) в DNS-странице.

## Вне объёма

Серверный DoH (клиенты→роутер), перехват DoT/DoH от клиентов, DNSCrypt/DNSSEC-режимы,
DoH3/QUIC.

## Последствия и шаги

- **D1 (этот шаг):** схема `DNSUpstream` (режимы `udp|tls` пока без `https`) +
  обратная совместимость + генератор Unbound для DoT + валидатор + типы + тесты.
  `https` **отсутствует в Literal** до D2 (явное расширение, а не молчаливый отказ).
- **D2:** режим `https` + `dnscrypt-proxy` (packaging/пиннинг, генератор конфига,
  systemd-юнит, агент) + `doh_url`.
- **D3:** UI-редактор upstream; docs.

Связанные: `docs/dns-dot-doh.md`, ADR-0005 (пиннинг релизов), ADR-0014 (DNS-контур
TProxy — общие upstream'ы Unbound не должны конфликтовать со split-контуром).
