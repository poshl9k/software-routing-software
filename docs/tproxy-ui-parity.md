# UI-паритет sing-box TProxy (слайс A)

Решение владельца продукта: сначала **контракт + UI-паритет** (черновик; gate
`tproxy.not_available` остаётся закрыт), packet-path parity — отдельно.
Референс: `hoaxisr/awg-manager`, доки `https://awgm.hoaxisr.ru/guide/singbox/router/`.
Семантика — `CONTEXT.md` «Выборочная маршрутизация (TProxy)»; план —
`docs/sing-box-tproxy-plan.md` этапы 2–3. UI — React/MUI, `docs/ui-rules.md`.

Slow-инертность: всё ниже — только черновик/предпросмотр, без перехвата трафика.

## Слайсы

- [x] **S1. Выход правила («куда»).** `TProxyRule.action: direct|block|route`
      + `outbound` (тег прокси-выхода/группы). Валидатор: `route` требует
      существующий выход (`tproxy.outbound_unavailable`, только при `proxies.enabled`);
      `route` без выхода → `tproxy.outbound_required`; `outbound` при direct/block →
      `tproxy.outbound_unexpected`. Генератор: `block→reject`, `direct→route direct`,
      `route→route <outbound>`. UI: селектор действия + условный селектор выхода с
      очисткой `outbound` при смене действия. Тесты: backend +4, frontend +2.
      Проверено: backend 834 passed, frontend 95 passed, tsc/build ok.
- [x] **S2. Матчеры правила.** Добавлены `source_ip_cidr`, `rule_sets` (ссылки на
      объявленные `rule_sets`), `protocol` (any|tcp|udp), `ports` (порт или диапазон).
      Валидатор: `tproxy.ruleset_unavailable`, `tproxy.source_ipv4_required`; минимум
      один матчер (`tproxy.rule_matcher_required`). Генератор: OR-матчеры
      (`source_ip_cidr`/`rule_set`/`port`/`port_range`/`network`). UI: поля источника,
      портов, протокола и чекбоксы наборов. Backend +6, frontend 95 passed.
- [x] **S3. Конечное действие политики.** `TProxy.final: direct|block|route` +
      `final_outbound`. Валидатор: `tproxy.final_outbound_required`/`_unavailable`/`_unexpected`;
      тег `block` зарезервирован. Генератор: `block`→block-outbound, `route`→тег,
      `direct` — legacy (прямой выход/авто-группа). UI: «Конечное действие» + «Выход по
      умолчанию». Backend +6, frontend +1. Проверено: backend 846, frontend 96, tsc/build ok.
- [x] **S3b. Bypass/исключения.** ~~Список исключений (порты/подсети/устройства) в `TProxy`.~~
      **СДЕЛАНО:** `TProxyBypass {name, source_ip_cidr, ip_cidr, ports, protocol}` + `TProxy.bypass`.
      Валидатор: `tproxy.bypass_matcher_required`/`_ipv4_required`/`_source_ipv4_required`/`_name_duplicate`.
      Генератор nftables: `return` в capture-цепочке (priority −80, после exemptions, до `gate`
      и `tproxy`-redirect) — исключённый трафик не перехватывается. sing-box: правило
      `route → direct` первым. UI: секция «Исключения из перехвата (bypass)». Проверено:
      backend 874, frontend 98, tsc/build ok. Семантика в `CONTEXT.md` (термин «Исключение TProxy»).
- [x] **S4. Simple/Expert режимы.** Переключатель «Простой/Эксперт» (`ValueTabs`). Простой —
      счётчики (источники/правила/исключения/конечное действие) + сводка
      «источник → sing-box → назначения · финал», плюс компактный список; редактирование
      открывается сразу в «Эксперте» (полные поля), из «Простого» можно сохранить черновик
      без экспертных полей. Проверено: frontend 99, tsc/build ok.
- [x] **S5. Визард первичной настройки.** Третья вкладка «Мастер» (Простой/Мастер/Эксперт):
      шаги «Источники → Признаки → Выход → Предпросмотр», собирает одно TProxy-правило +
      источники и сохраняет черновик (`enabled: false`); локальный текстовый предпросмотр
      (API предпросмотра отражает сохранённый черновик и мастером не вызывается). Проверено:
      frontend 100, tsc/build ok. Делегировано Codex на `gpt-6-sol`.
- [~] **S6. DNS-политика** (апстримы UDP/TLS/HTTPS, DNS-правила) — поверх `dns`/ADR-0014, без
      перехвата DNS роутера. **S6a (бэкенд) сделано:** `TProxyDNSServer {tag, type udp|tls|https,
      server, server_port, tls_name, path, domain_resolver, detour}` + `TProxyDNSRule` +
      `TProxyDNS`; генератор рендерит `dns`-блок sing-box **нового формата** (1.14: `type`/`server`,
      не legacy `address`) + `route.default_domain_resolver`. Коды: `tproxy.dns_server_required`,
      `_tls_name_required`, `_servers_required`, `_server_duplicate`, `_rule_duplicate`,
      `_rule_matcher_required`, `_rule_server_unavailable`, `_bootstrap_required`. Проверено:
      backend 889, и **реальный `sing-box check` на закреплённом 1.14.2** (тест + независимая
      проверка). **S6b (UI) сделано:** `types.ts` + секция «DNS-политика (sing-box контур)» в
      «Эксперте» (серверы: тег/тип/сервер/порт/tls_name/path/резолвер/detour; правила: имя/
      домены/наборы/сервер) + фикстура + тест. Проверено: frontend 101, tsc/build ok.
- [ ] **S7. Connections / журнал / инспектор** — только когда есть runtime-API
      (gate открыт); сейчас вне объёма.
- [ ] **S8. Outbounds/подписки: импорт ссылок, массовые операции.**

## Сознательно вне объёма
FakeIP/policy-TUN, перехват OUTPUT роутера, полный IPv6 TProxy, произвольное
исполнение конфигурации/команд.

## Общая конфигурация — DoH/DoT (обязательный пункт) — СДЕЛАНО
Реализовано по **ADR-0015** (`docs/adr/0015-dns-upstream-dot-doh.md`),
журнал в `docs/dns-dot-doh.md`:
- **D1** — `DNSUpstream {address, port, mode udp|tls, tls_name}`, DoT нативный в Unbound.
- **D2** — `mode: https` + `doh_server`; Unbound форвардит на локальный `127.0.0.1:5300`,
  генератор `generators/dnscrypt.py`.
- **D2b** — пакет `dnscrypt-proxy` (snapshot) + mask дистрибутивных юнитов,
  `agent/dnscrypt_service.py`, аддитивная DoH-ветка в `apply.py`.
- **D3** — структурный UI-редактор upstream. Коммиты `150ff5d`, `6c3737d`, `3975444`, `beb4960`.
- Осталось: живой VM-прогон (требует авторизации).
**S6** переиспользует `DNSUpstream` (общий тип) для DNS-политики sing-box.

## Журнал
- S1 — сделано (см. выше).
- S2 — сделано (см. выше).
- S3 — сделано (конечное действие; bypass вынесен в S3b).
- DoH/DoT — **сделано** через ADR-0015 (D1–D3), см. раздел выше.
- S3b/S4/S5/S6/S8 — в очереди; S7 вне объёма до открытия gate.
