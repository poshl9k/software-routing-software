# Функциональный паритет с awg-manager (sing-box): гэп-анализ и план

Референс: живая панель `awg-manager` 2.19.9 (`http://10.10.10.1:2222`), репозиторий
`hoaxisr/awg-manager`, доки `awgm.hoaxisr.ru/guide/singbox/*`.
Инвентаризации: `docs/reference-awgm-live-inventory.md`, `docs/reference-awgm-source-inventory.md`,
`docs/reference-awgm-docs-notes.md`. Наш текущий слайс — `docs/tproxy-ui-parity.md` (S1–S6b сделаны,
S7 runtime — нет).

Цель: **функциональная** близость (визуал у нас свой, Keenetic-стиль — это ок).
Принцип как раньше: сначала **контракт + UI-паритет**, runtime/packet-path — отдельными волнами.

## Что делает референс (карта возможностей)

| Область | Референс (awg-manager) |
| --- | --- |
| Выходы | импорт share-links (vless/trojan/ss/hysteria2/naive/mieru/tt) и файлов; карточка выхода (протокол/транспорт/TLS/Reality), delay-sparkline, RX/TX, «Изменить/Удалить»; отдельный Proxy-интерфейс |
| Группы | composite `selector`/`urltest` под одним тегом; ручной выбор активного vs автовыбор по скорости; url/interval/tolerance |
| Подписки | URL/inline источник; headers с пресетами; автообновление (час…неделя); member'ы со стабильными тегами; diff при refresh (added/updated/сироты); include/exclude regex; «Исключённые» с бейджем; активный member; «Проверить всё» (delay по каждому); «Обновить сейчас»; сводные группы поверх нескольких подписок |
| Rulesets | remote `.srs`/URL/interval/download-detour, local-файл, inline-условия, быстрый Geosite/GeoIP; каталог; bulk-смена detour |
| Правила | first-match; matchers: domain, domain_suffix, domain_keyword, regex, ip_cidr, source_ip_cidr, **source_mac**, port, **rule_set**, protocol, **inbound**, **ip_is_private**, **network**; **logical and/or**; действия route/reject + системные **sniff**/**hijack-dns**/udp_timeout; `final` |
| DNS-контур | upstream udp/tls/https + detour; один `final`/`strategy`; DNS-правила (domain/regex/keyword/rule_set/query_type/match_response) с действиями Route/Block/Evaluate/Respond; DNS Rewrite; пресеты цепочки; трассировка цепочки |
| Движок | статус (версия/работа/PID), установка/обновление/запуск/стоп/рестарт; sniff, udp timeout, обход портов/CIDR/GeoIP, DSCP→outbound; проверка netfilter/TPROXY как зависимость |
| Наблюдаемость | монитор соединений (Clash API: источник/назначение/правило/outbound/трафик, закрытие), журнал sing-box (уровни/источники/поиск), inspect/trace правил, staging apply/discard |
| Онбординг | empty-state «туннель → сервисы → правила+DNS → final=direct → включить TProxy»; мастер правила «что направить → куда → предпросмотр»; пресеты сервисов |

## Что уже есть у нас (по коду)

- `TProxyRule` (domain/ip_cidr/source_ip_cidr/ports/protocol/rule_sets → action direct|block|route+outbound),
  `TProxyBypass`, `TProxy.final`, `TProxyDNS{servers,rules}`, `ProxyOutbound`, `ProxyGroup`,
  `ProxySubscription`, `RuleSetSource` (`backend/src/vs_router/schema.py:274–519`).
- UI: `Routing.tsx` — TProxy «Простой/Мастер/Эксперт», правила/исключения/DNS-контур; `RoutingProxy.tsx` —
  прокси-выходы (импорт share-links), подписки (только объявление), группы.
- Агент: downloader/`rulesets`/`presets`/`source_update_job` (загрузка наборов), rpc, apply/rollback.
- Сделано: S1–S6b (выход правила, матчеры, final, bypass, simple/expert, мастер, DNS-политика),
  реальный `sing-box check` на 1.14.2, живая приёмка TProxy (lab-37…45), AND-матчеры (lab-45).
- Пока нет: runtime (Clash API), fetch/refresh подписок, монитор/журнал, выразительность правил
  (logical/MAC/inbound/regex), статус/управление движком, авто-DNS в мастере.

## Гэпы (функциональный паритет), по приоритету

### Волна 1 — контракт + UI (без runtime, безопасно)

- **G3. Выразительность правил.** Добавить в `TProxyRule`: `domain_exact`/`domain_keyword`/`domain_regex`,
  `source_mac`, `inbound`, `ip_is_private: bool`, `network` (tcp/udp/any) и **logical-группу**
  (`mode: and|or` поверх под-матчеров) — либо явную модель «матчер-группа». Валидатор + генератор
  sing-box + UI-редактор. **Что даёт:** паритет по матчерам и комбинированию (AND/OR).
- **G4a. Параметры движка как поля.** `TProxy.sniff: bool`, `TProxy.udp_timeout`,
  `TProxy.bypass`-расширения (уже есть CIDR/ports; добавить GeoIP/GEOip-набор опционально).
  Генератор: sniff-правило первым, udp_timeout на правилах/UDP. UI: блок «Параметры движка».
- **G2a. Группа выходов — tolerance.** `ProxyGroup.tolerance_ms` (urltest) + `url` уже есть.
  Контракт + генератор + UI (мелкое).
- **G6. Мастер = quickstart.** Мастер первичной настройки дополнительно создаёт `dns-direct` +
  `dns-tunnel` (detour на выбранный выход), синхронизирует доменные DNS-правила, ставит `final=direct`.
  UI-шаги «Туннель → Что в туннель → DNS → Применить».
- **G1a. Подписки — контракт-надстройка.** Расширить `ProxySubscription`: `headers`, `mode`
  (selector/urltest), `url_test` (url/interval/tolerance), `filter_include`/`filter_exclude`,
  `active_member`, `excluded_members`, `pinned`/`inline`. Валидатор + типы + UI-форма (без fetch).

### Волна 2 — runtime (агент + Clash API)

- **G1b. Подписки: fetch/refresh.** Агент: SSRF-safe загрузчик (лимиты 5 MiB/20 с), парсер
  (clash YAML / sing-box/Xray/v2ray JSON / base64 / raw share-links), стабильные теги member'ов,
  diff (added/updated/orphan), include/exclude regex, активный member. API: list/refresh/preview/
  update/members/exclude. UI: вкладки «Серверы/Исключённые/Настройки», «Обновить сейчас»,
  delay по member'ам, активный member. Долгий.
- **G5. Наблюдаемость.** Клиент Clash API (loopback): `/connections`, `/logs`; API-эндпоинты;
  UI «Монитор соединений» + журнал sing-box (уровни/источники/поиск). Зависит от включённого
  `experimental.clash_api` в генерируемом конфиге.
- **G4b. Статус/управление движком.** `status` sing-box (версия/работа/PID), start/stop/restart
  через агент; проверка netfilter/TPROXY как блокирующая зависимость в UI.
- **G2b. Runtime-выбор/тест выходов.** Выбор активного выхода в группе + latency-тест через Clash API.

### Волна 3 — продуктовые решения (пока вне объёма)

- **G7. FakeIP / TUN-режим** (fakeip DNS-сервер, TUN inbound, device-mode). Отдельный режим входа,
  не TProxy; требует продуктового согласования и packet-path приёмки.
- **G8. Policy-tun / отдельный LAN SOCKS5/HTTP-прокси, DSCP-классы, per-rule udp_timeout в UI.**
- **G9. DNS-контур «продвинутый»:** evaluate/respond/rewrite + трассировка цепочки.

## Терминология (awg-manager → vs-router)

См. карту в `docs/reference-awgm-docs-notes.md`. Ключевое: outbound→«Прокси-выход/тег выхода»,
composite→«Группа выходов», rule-set→«Набор правил/источник набора», routing rule→«Правило TProxy»,
final→«Конечное действие», DNS detour≠download detour, hijack-dns→«перехват DNS», NDMS Proxy→
«привязка выхода к интерфейсу» (не переносить буквально).

## Границы

- Keenetic/NDMS/OpkgTun/DSCP/Entware — платформенные детали референса, не обязательная архитектура
  Debian-панели (не переносить буквально).
- Инвентаризация живой панели — наблюдения экранов; сохранение/запуск не проверялись (read-only обход).
