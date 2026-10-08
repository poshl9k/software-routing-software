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
- [ ] **S3. Конечное действие политики + bypass.** `final` = direct|block|outbound;
      исключения (порты/подсети/устройства) как отдельный список.
- [ ] **S4. Simple/Expert режимы.** Счётчики-статусы сверху, сводка
      «источник → движок → назначения», экспертные секции.
- [ ] **S5. Визард первичной настройки** (сервисы → выход → устройства → превью).
- [ ] **S6. DNS-политика** (апстримы UDP/TLS/HTTPS, DNS-правила) — поверх
      `dns`/ADR-0014, без перехвата DNS роутера.
- [ ] **S7. Connections / журнал / инспектор** — только когда есть runtime-API
      (gate открыт); сейчас вне объёма.
- [ ] **S8. Outbounds/подписки: импорт ссылок, массовые операции.**

## Сознательно вне объёма
FakeIP/policy-TUN, перехват OUTPUT роутера, полный IPv6 TProxy, произвольное
исполнение конфигурации/команд.

## Общая конфигурация — DoH/DoT (обязательный пункт, вне TProxy-слайса)
Нужна поддержка DoH и DoT как upstream DNS в общей конфигурации (не только в
DNS-политике sing-box). Нюанс, требующий решения: **Unbound нативно умеет DoT**
(`forward-tls-upstream: yes` + `forward-addr: <ip>@853#<sni>`), но **DoH как
клиент Unbound не умеет** — нужен отдельный компонент (dnscrypt-proxy /
cloudflared / sing-box DNS). Варианты: (а) DoT — в Unbound, DoH — через отдельный
резолвер/компонент; (б) и DoT, и DoH — через один DoH-capable резолвер; (в) DoH
отложить до DNS-политики sing-box (S6). Требует фиксации в ADR перед реализацией.

## Журнал
- S1 — сделано (см. выше).
- S2 — сделано (см. выше).
- DoH/DoT — записано как обязательный пункт общей DNS-конфигурации (дизайн-док
  `docs/dns-dot-doh.md`; решение по компоненту не принято).
