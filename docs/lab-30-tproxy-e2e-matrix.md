# Lab-30: e2e-матрица TProxy на одной одноразовой VM (полный стек)

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab`
(kernel 6.12.107+deb13-amd64, nftables 1.1.3, Python 3.13.5, Unbound 1.26.x,
setpriv/ss/ip присутствуют). Рабочий домен `vsr-live-403ab3a` не затрагивался.
Все сетевые изменения — внутри **четырёх** временных network namespace
(`vsr-e2e-router` / `vsr-e2e-selected` / `vsr-e2e-ordinary` / `vsr-e2e-origin`);
корневое пространство гостя, его маршруты и firewall не менялись. Публичный gate
`tproxy.not_available` **не открывался**: включённый снапшот получен только офлайн
через штатный lab-механизм `model_copy` (тот же, что и в `generate_tproxy_dns_split_cases.py`).
sing-box: тестовый `/var/cache/vsr-singbox-probe` (`SagerNet/sing-box` v1.14.2
linux/amd64), запущен под тестовым UID `29091` с `CAP_NET_ADMIN`/`CAP_NET_RAW`.

## Зачем

Блокер #5 плана (`docs/sing-box-tproxy-plan.md`): по частям всё доказано
(lab-24 пре-авторизация, lab-26 `ct mark` INPUT, lab-27 перехват, lab-28 DNS-контур,
lab-29 INPUT по `ct mark` в продуктовом генераторе), но **совместной** проверки
всего тракта и матрицы отказов не было. Здесь весь стек собирается как одно целое
и прогоняется через нормы, шесть отказов, восстановление, эмуляцию пере-применения
и явный off.

## Артефакты

- `backend/tests/lab/tproxy_e2e_probe.py` — VM-only, root, **stdlib**, 4 netns.
- `backend/tests/lab/generate_tproxy_e2e_cases.py` — host-only офлайн-фикстура из
  настоящих генераторов через интегрированный контур
  (`plan_tproxy_dns` + `agent.tproxy_apply.build_artifacts`).
- `backend/tests/test_tproxy_e2e_lab.py` — 5 host-free проверок фикстуры и
  stdlib-чистоты пробы.

SHA256:

| Файл | SHA256 |
| --- | --- |
| `tproxy_e2e_probe.py` | `63b1d9202e5a5e1228d56d8af68f302759921d7030cb3f3b5e810187c79840ae` |
| `generate_tproxy_e2e_cases.py` | `37bbcc4c0ec6f399589c651685724aa7b8e4e8eb43c06487cfb460d6abd37f49` |
| `test_tproxy_e2e_lab.py` | `f246aef27e244b3085d62a51e367e8aac4f529933b1e6ae00c4db141ca0bde33` |
| Fixture `e2e-case.json` | `c514c2392331817917ee95e0686d3e0f94685be262c57574c18eaa2c74b3dc6d` |

## Собираемый тракт

В router-namespace `nft -f` одним целым (артефакты — настоящий вывод генераторов):

```
ordinary firewall (generate_nftables)          INPUT/FORWARD default-deny + allow_tcp/udp 19090
                                               + dns 53 + mgmt 443
guards:
  inet vs_router_tproxy_guard        FORWARD   priority -10   containment (drop selected transit)
  inet vs_router_tproxy_preauth      PREROUTING priority -90  post-DNAT first-match, default deny, stamps 0x400 on authorized transit
  inet vs_router_tproxy_dns_ingress  PREROUTING priority -110 drop selected direct :53
  inet vs_router_tproxy_dns_listener INPUT      priority -10   cross-listener boundary
  inet vs_router_tproxy_dns_output   OUTPUT     priority -20   skuid 29092 boundary
interception (generate_tproxy_interception):
  inet vs_router_tproxy_ct_reset     PREROUTING priority -85   clear ct proof bit
  inet vs_router_tproxy_interception PREROUTING priority -80   preauth stamp gate (mark & 0x400) + meta mark 0x100 + ct mark|0x200 + tproxy
  inet vs_router_tproxy_input        INPUT      priority -20   drop if ct mark lacks proof
policy route (marks.POLICY_ROUTES[0]): ip rule prio 100 fwmark 0x100 lookup 100
                                       ip route add local 0.0.0.0/0 dev lo table 100
```

sing-box (JSON из `generate_singbox`) слушает tproxy tcp `127.0.0.1:51272` и udp
`127.0.0.1:51271`; два настоящих Unbound (selected UID `29092` на `10.212.1.1`,
ordinary UID `29093` на `10.212.3.1`) с конфигами из `build_artifacts`; loopback
DNS-стаб `127.0.0.1:15353`; два fake WAN-origin `198.18.0.2`/`198.18.0.3`.

Порядок исполнения хуков: DNS ingress `-110` → preauth `-90` → reset `-85` →
capture `-80` → затем INPUT guard `-20` и обычный firewall (priority `filter`).
Меньший приоритет — раньше.

### LAB SCAFFOLD (явно, не вывод генератора)

Продуктовый firewall default-deny'ит INPUT, а генератор перехвата даёт только INPUT
**drop**-guard, но не INPUT **accept** для перехваченного тракта. Чтобы
перехваченный поток дошёл до listener'а sing-box, проба вставляет в цепочку
`inet vs_router input` одно правило accept, ключёванное по **продуктовому же
токену владения** — `ct mark & 0x200` (тот же бит, что ставит capture). Это
сопутствующая/смоделированная авторизация, а не поставляемый текст генератора; в
документе и в отчёте она помечена явно. Она открывает INPUT только для пакета,
уже помеченного capture, а capture (lab-31) срабатывает лишь при живом preauth —
поэтому потеря preauth теперь ведёт к fail-closed, а не к сквозной дыре (см. F4).

## Матрица (18 сценариев, exit=0 при успехе harness)

Прогон дважды подряд: `PASS=18`, `RESIDUAL=0`, `FAIL=0`, `EXIT=0`, cleanup пуст.

| # | Сценарий | Статус | Ключевая строка |
| --- | --- | --- | --- |
| N1 | allowed TCP через прокси | PASS | `origin_peer=10.212.2.1 (proxied)`, containment 0 |
| N2 | allowed UDP через прокси | PASS | `origin_peer=10.212.2.1 (proxied)` |
| N3 | unselected (lan1) — не перехватывается | PASS | `direct, origin_peer=10.212.3.2`, capture не вырос |
| N4 | запрещённый selected не доходит | PASS | `blocked at preauth, origin empty` (transit drop ↑) |
| N5 | запрещённый unselected | PASS | `blocked by FORWARD default-deny, origin empty` |
| N6 | selected DNS → стаб | PASS | `unmatched -> 203.0.113.8, no WAN` |
| N7 | ordinary DNS → origin | PASS | `-> 203.0.113.7, stub untouched` |
| N8 | local-запись приоритетна | PASS | `router.test. = 192.0.2.77 on both, no upstream` |
| N9 | explicit forward приоритетен | PASS | `*.forward.vsrprobe.org -> 198.18.0.2 on both` |
| N10 | panel/mgmt локальный доступ | PASS | `TCP/443 reachable from both lan clients` |
| F1 | **SIGKILL sing-box** | PASS | `fail-closed (no leak), deny held, mgmt kept, recovery ok` |
| F2 | **удаление interception** | PASS | `transit fail-closed at containment (-10) (independent of preauth)` |
| F3 | **потеря policy route** | PASS | `fail-closed (no leak), deny held, mgmt kept, recovery ok` |
| F4 | **потеря preauth** | PASS | `capture gate holds: allowed+denied selected transit fail-closed at containment (-10); mgmt kept; recovery ok` |
| F5 | **остановленный DNS-стаб** | PASS | `selected denied (no WAN leak), ordinary/local alive, recovery ok` |
| F6 | **kill selected Unbound** | PASS | `denied (no WAN leak), ordinary alive, mgmt kept, recovery ok` |
| R | **reboot (эмуляция пере-применения)** | PASS | `guards deny before any tract, then readiness, then capture` |
| OFF | снятие всех своих таблиц/route | PASS | `ordinary routing; default deny kept` |

### Ключевые механики, которые матрица закрывает совместно

- **Capture отрывает selected от FORWARD**, поэтому containment `-10` не срабатывает
  на норме (N1: containment = 0). **Как только capture исчезает (F2), selected-транзит
  ловится containment `-10`** — это независимый от preauth fail-closed барьер:
  потеря таблицы перехвата не даёт обхода, а даёт отказ (`guard` counter ↑, origin пуст).
- **Потеря preauth (F4) fail-closed (lab-31):** capture теперь требует
  зарезервированный packet-mark `0x400`, который preauth выставляет только на
  авторизованном (first-match `pass`) selected-транзите. Удаление таблицы preauth
  убирает mark → capture возвращает пакет без перехвата → поток идёт обычным
  FORWARD-путём → его режет containment `-10`. **И разрешённый, и запрещённый
  selected-потоки не достигают origin**; mgmt (dest `zone:router`) идёт INPUT-путём
  и сохраняется. Это чистое правило, без демона-watchdog и без второго writer'а
  mark/table/hook (ADR-0013); mark — общий контракт preauth↔capture из
  `marks.MARK_TPROXY_AUTH_VALUE`.
- **Потеря policy route (F3) fail-closed**: помеченный пакет не доставляется к
  loopback-listener'у, ответа/эха нет, origin пуст.
- **SIGKILL движка (F1)**: tproxy-перенаправление в мёртвый `127.0.0.1:51272`
  даёт отказ; прямой утечки в origin нет; при этом обычный firewall, preauth,
  containment и mgmt сохраняются.
- **Потеря DNS-стаба (F5)**: selected получает отказ без утечки в WAN (кэш
  selected off), ordinary/локальная запись/forward живы; восстановление стаба
  возвращает тракт без перезапуска Unbound.
- **Kill selected Unbound (F6)**: selected DNS отказывает без утечки, ordinary
  DNS жив, mgmt сохранён; перезапуск resolver'а восстанавливает.
- **Эмуляция reboot (R)**: снимаются все свои таблицы + policy route + процессы,
  затем тракт поднимается **в фазовом порядке** `guards → readiness → interception`;
  проверено, что до установки capture **защита уже deny'ит** запрещённый поток и
  mgmt доступен, и только после этого ставится перехват.
- **OFF**: снятие всех собственных таблиц + policy route возвращает обычную
  маршрутизацию (selected снова `origin_peer=10.212.1.2`, не через прокси) с
  сохранением default deny (свежий flow снова блокируется).

## Что это доказывает

На реальном пакетном тракте, в четырёх изолированных namespace, с настоящим
sing-box, двумя настоящими Unbound и **байт-в-байт** артефактами генераторов:

- весь тракт работает как одно целое: разрешённые TCP и UDP выбраны (proxied,
  origin видит src роутера), запрещённые/невыбранные не обходят firewall и не
  доходят до origin; DNS разделён по источнику (selected→стаб, ordinary→WAN),
  local-запись и explicit forward сохраняют приоритет, локальный mgmt-доступ жив;
- матрица отказов содержит независимые fail-closed барьеры: containment `-10`
  ловит потерю capture, потеря policy route даёт отказ, смерть движка даёт отказ,
  потеря DNS-стаба/resolver'а даёт отказ без утечки в WAN; **потеря preauth (F4)
  тоже fail-closed** — capture выключен отсутствием stamp-mark, и **и разрешённый,
  и запрещённый** selected-поток режется containment `-10` (lab-31);
- восстановление артефактов возвращает тракт; эмуляция пере-применения доказывает,
  что защита (guards) поднимается **до** тракта; явный off возвращает обычную
  маршрутизацию с сохранением default deny;
- cleanup действительно пуст (`ip netns list`, `nft list tables`, table 100).

## Чего это НЕ доказывает (честные пределы)

- **F4 больше не остаток, но барьер — containment, а не интерцепт.** Потеря preauth
  теперь fail-closed: capture не срабатывает (нет `0x400`), и selected-транзит
  режет независимый containment `-10`. Это доказывает отсутствие обхода, но
  **цена** — потеря всей selected-связности на время отсутствия preauth
  (сознательный fail-closed, не graceful degrade). Дифференциальный прогон
  (та же фикстура со снятой gate-строкой) воспроизводит прежнюю утечку
  (`allowed flow delivered`, origin peer `10.212.2.1`) — то есть именно gate, а не
  что-то иное, закрывает обход. Реальный барьер по-прежнему — единственный writer
  пространства mark/table/hook (ADR-0013), а не атомарность файла preauth: если
  writer потерян/подделён, ни mark, ни gate не защищают.
- **INPUT accept — lab scaffold, а не продуктовый генератор.** Как и в lab-24/27/29,
  доставка перехваченного потока к listener'у требует accept-правила в INPUT;
  текущие генераторы его не эмитят. Правило вставлено пробой и ключёвано по
  `ct mark`, но его наличие само по себе — недоказанное продуктовое требование.
- **«Reboot» — только эмуляция пере-применения.** Настоящее перезагрузочное
  восстановление (persisted marker, boot-restore, порядок systemd) не
  воспроизводилось: staged только повторное применение артефактов; поднимать
  реальный reboot и проверять его последствия в этом стенде нельзя.
- **Не доказывает**: публичный gate `tproxy.not_available` остаётся закрытым — это
  не enablement; атомарный apply/rollback/commit; systemd-жизненный цикл sing-box
  и Unbound (в пробе процессы запускаются напрямую под setpriv), права на bind
  `:53`, изоляция и деградация; IPv6; произвольный policy routing/ECMP с
  iif/L4-зависимыми правилами; bridge/offload; уже буферизованные байты при
  teardown; failover; неподделываемость против привилегированного writer'а
  `ct mark`; выбор и pin продуктового бинарника sing-box (ADR-0012).
- **Норма НЕ доказывает** мультипоточность/масштаб: проверен один TCP- и один
  UDP-поток точного lab-tuple на сценарий, один selected- и один ordinary-клиент.

## Проверки вне VM

`backend/`: `uv run --no-sync pytest -q` → **758 passed, 0 failed** (lab-30 изначально
фиксировала 750 passed + 1 environmental; после этой задачи полный набор зелёный).
Новые/обновлённые host-free тесты: `tests/test_tproxy_e2e_lab.py` (5),
`tests/test_tproxy_preauth_gate.py` (новый, 6), обновлённые
`test_tproxy_interception.py` / `test_tproxy_preauth.py` /
`test_tproxy_preauth_combined_lab.py`. Golden-файлы и `generate_nftables`/
`generate_singbox` не менялись: правки — аддитивные gate/stamp в офлайн-генераторах
TProxy и аддитивные файлы пробы.

## Как воспроизвести

```
# host: офлайн-фикстура из интегрированного контура (gate закрыт)
cd backend && env -u PYTHONPATH .venv/bin/python \
  tests/lab/generate_tproxy_e2e_cases.py e2e-case.json
# гость: VM-only, root
bash .../vm-lab/vm-push.sh <tproxy_e2e_probe.py> /root/vsr-e2e
bash .../vm-lab/vm-push.sh <e2e-case.json> /root/vsr-e2e \
  "python3 -u tproxy_e2e_probe.py e2e-case.json"
# ожидаемо: EXIT=0, summary {pass:18, residual:0, failed:[]}, CLEANUP пуст
```

Дифференциал (доказательство, что обход закрывает именно gate lab-31): из
`interception`-текста удаляется строка `meta mark & 0x400 == 0 return`; проба
воспроизводит прежнюю утечку F4 (`fault_preauth_lost FAIL`, allowed flow
доставлен через прокси к origin). Подробности — `docs/lab-31-tproxy-preauth-independence.md`.
