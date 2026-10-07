# Lab-36: IPv6-WAN-эскейп выбранных источников при IPv4-only TProxy

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab` (kernel
6.12.107+deb13-amd64, nftables 1.1.3, Python 3.13.5), сеть `default`. Все
сетевые изменения — внутри четырёх временных network namespace
(`vsr6-router`/`vsr6-client`/`vsr6-other`/`vsr6-origin`); корневое пространство
гостя, его маршруты и firewall не менялись (проверено: `ip netns list` и
`nft list tables` в root пусты после пробы). Рабочий домен `vsr-live-403ab3a` не
затронут. Публичное включение TProxy по-прежнему запрещено: `tproxy.not_available`
не открывался.

## Закрываемая дыра

Семантика плана §5: первая поставка TProxy маршрутизирует **IPv4**; для выбранных
источников IPv6-выход в WAN должен быть заблокирован, пока нет эквивалентного
IPv6-перехвата. Перехват/preauth/containment — IPv4-центричны: capture
(`generate_tproxy_interception`) на non-IPv4 делает `return` и пакет уходит
обычным FORWARD-путём в WAN **мимо прокси**. Containment
(`generate_tproxy_containment`) блокирует весь selected-транзит, но это
экспериментальная offline-таблица без ограничений по семейству и без сохранения
локального трафика; отдельного, узкого, gated IPv6-WAN-гейта не было.

Здесь добавлен детерминированный gated-генератор, который закрывает именно
routed-IPv6-эскейп выбранных источников, сохраняя локальный/management/
линк-локальный IPv6 и невыбранные источники.

## Артефакты

- `backend/src/vs_router/generators/nftables.py:generate_tproxy_ipv6_guard` —
  новый offline-генератор отдельной `inet vs_router_tproxy_ipv6_guard`; при
  `enabled=False` возвращает только `destroy table` своей таблицы. Неверный или
  пустой ingress отвергается (`tproxy.ipv6_guard_invalid_ingress`); enabled-снапшот
  достижим только через offline `model_copy`, остальной контракт ре-валидируется.
- `backend/src/vs_router/generators/marks.py` — таблица и hook-приоритет
  зарегистрированы в едином реестре владения (`TABLES`, `HOOKS` → forward `-11`).
- `backend/src/vs_router/agent/tproxy_apply.py:guard_content` — таблица добавлена
  в фазу `guards` (gated, инертна при `enabled=False`), ровно в один артефакт
  `tproxy_guards`; `PHASE_ORDER`/`TPROXY_FILES` не менялись.
- `backend/tests/test_tproxy_ipv6_guard.py` — host-free: узость, IPv6-only,
  сохранение local/management/link-local, невыбранный ingress, единственный
  drop, детерминизм, невалидный ingress, off ровно своей таблицы, владение
  table/hook, инертность агента и включение в guard-фазу, host-free проверки
  VM-fixture/probe.
- `backend/tests/lab/generate_tproxy_ipv6_cases.py` — test-only генератор
  фикстуры (`--` офлайн, без сети).
- `backend/tests/lab/tproxy_ipv6_guard_probe.py` — VM-проба (stdlib + `ip`/`nft`/
  `ping`), строит IPv6-топологию в четырёх netns.

SHA256:

| Файл | SHA256 |
| --- | --- |
| `tproxy_ipv6_guard_probe.py` | `e4e26cdbd2b64ddc12ba6d1be40d8fac130ed9757ba696c970098781f9c8ee5b` |
| `generate_tproxy_ipv6_cases.py` | `057d229c9eda92bd0ed9be1fa467fc3541034989d38f11e35fbf5da853938121` |
| `test_tproxy_ipv6_guard.py` | `c1e62315a7f2ffb409321de5ea375cc2414548127979ca9423fbfe3fedc901e5` |
| VM-fixture `ipv6-guard.json` | `c7f3e8e2fbd3fec6d6bf96edabb0fa163318f3e6c81d5d93c1152f1628178068` |

## Схема IPv6-guard

```
table inet vs_router_tproxy_ipv6_guard          # owner: generators/marks.py
  chain forward   hook forward priority -11; policy accept;
    iifname != { <selected ingress> } return    # невыбранные источники не тронуты
    meta nfproto != ipv6 return                 # IPv4 и non-IP не задеваются
    fib daddr type local return                 # local/management/panel/loopback
    ip6 daddr { fe80::/10, ff00::/8 } return    # линк-локальный/мультикаст scope
    counter drop comment "tproxy_ipv6_guard"    # fail-closed routed-IPv6 drop
```

- **Порядок / приоритет:** FORWARD `-11` — раньше containment `-10` и продуктового
  filter-hook `0` (меньший приоритет исполняется раньше). Таблица независима от
  перехвата и preauth: IPv6 не перехватывается вообще, поэтому гейт работает на
  обычном FORWARD-пути и срабатывает **до** тракта перехвата.
- **Узость:** матч по **входному интерфейсу**, а не адресу источника — смена
  IPv6-адреса выбранным хостом гейт не обходит. Только IPv6
  (`meta nfproto != ipv6 return`), IPv4-тракт не задевается.
- **Сохранение:** `fib daddr type local` сохраняет все адреса самого роутера
  (management/панель, loopback, интерфейсные адреса) — они термируются локально
  (INPUT) и никогда не форвардятся; `fe80::/10` и `ff00::/8` — линк/scope-локальны
  и не являются WAN-эскейпом.
- **Fail-closed:** единственное правило — `counter drop`, без per-flow
  `established`-шортката; уже открытый selected-IPv6-поток режется в момент
  загрузки гейта. `accept` в таблице отсутствует (кроме `policy accept` основного
  правила).
- **Off:** `enabled=False` → `destroy table inet vs_router_tproxy_ipv6_guard` и
  ничего чужого. Полный teardown каркаса
  (`tproxy_apply.cleanup_content`) сносит таблицу как non-wired owned-таблицу из
  `marks.TABLES`.

## Результат на пакетах (VM, EXIT=0)

Топология: `vsr6-client` (selected, `lan0` `2001:db8:1::/64`) и `vsr6-other`
(unselected, `lan1` `2001:db8:2::/64`) ходят через `vsr6-router` в `vsr6-origin`
(`wan0` `2001:db8:3::/64`); far-WAN-адреса `2001:db8:99::1` (v6) и `198.18.0.1` (v4)
живут на loopback origin и достижимы только routed-транзитом через `wan0`.

| Шаг | Наблюдение |
| --- | --- |
| baseline (гейта нет) | selected→WAN v6, selected→local, selected→management, selected→link-local, unselected→WAN v6, selected→WAN v4 — все `true` |
| **guard: selected→WAN v6** | **заблокировано** (`false`), `guard_drop_delta=2` — правило достигнуто |
| guard: selected→local (`2001:db8:1::1`) | `true` (сохранено) |
| guard: selected→management (`2001:db8:6::1`) | `true` (сохранено) |
| guard: selected→link-local (`fe80::…%eth0`) | `true` (сохранено) |
| guard: unselected→WAN v6 | `true` (не затронут) |
| guard: selected→WAN v4 (`198.18.0.1`) | `true` (IPv4-тракт не сломан) |
| off | таблица отсутствует (`true`), selected→WAN v6 снова `true` |

Ключевая строка: при активном гейте routed-IPv6 выбранного источника к нелокальному
(WAN) назначению **дропается** (`guard_drop_delta=2`), при этом локальный,
management- и линк-локальный IPv6, невыбранный источник и весь IPv4-тракт
работают; явный off восстанавливает маршрутизацию. Нативные проверки: сгенерированный
текст прошёл `nft -c -f` на VM (`SYNTAX_OK`). После пробы netns и тестовые таблицы
удалены, root-пространство гостя не менялось.

## Host-free проверки

`uv run --no-sync pytest -q` → **824 passed**, 0 падений. Собственный вклад:
`test_tproxy_ipv6_guard.py` фиксирует FORWARD `-11` (раньше containment `-10`),
IPv6-only (`meta nfproto != ipv6 return`, нет `ip daddr`), сохранение
local/management (`fib daddr type local`) и link-local/multicast
(`ip6 daddr { fe80::/10, ff00::/8 }`), матч по интерфейсу выбранных источников,
единственный `counter drop`, отсутствие `established`-шортката, детерминизм и
независимость от порядка ingress, отказ невалидного ingress, off ровно своей
таблицы, регистрацию table/hook в `marks.py`, включение таблицы в артефакт
`tproxy_guards`/фазу `guards` и инертность при `enabled=False`, а также opt-in
VM-fixture и import-safety пробы. Golden-файлы и продуктовые
`generate_nftables`/`generate_singbox` не изменены (генератор — аддитивная
функция).

## Что доказывает и чего НЕ доказывает

**Доказывает (на реальном пакетном тракте, в этих namespace, настоящие `ip`/`nft`):**

- gated-генератор детерминирован, узок и офлайн; при off снимает ровно свою таблицу;
- при активном гейте routed-IPv6 выбранных источников к нелокальному (WAN)
  назначению **не доходит** до WAN — эскейп закрыт fail-closed на FORWARD-пути;
- локальный/management IPv6, линк-локальный IPv6, невыбранные источники и
  IPv4-тракт **не затронуты**; явный off восстанавливает маршрутизацию.

**НЕ доказывает / известная граница (не выдавать за проверенное):**

- публичный gate `tproxy.not_available` **не открыт** — это не enablement;
- **bridge/flow-offload НЕ покрыты:** гейт стоит на обычном FORWARD-хуке `-11`;
  fast-path'ы (hardware/software flow offload, bridge forwarding) могут обходить
  обычное FORWARD-решение, и эта проба их не проверяла и не закрывает;
- **iif/L4-зависимые policy-routing и ECMP НЕ покрыты:** гейт не воспроизводит
  маршрутные политики, зависящие от входного интерфейса/протокола/порта, и все
  случаи ECMP; хосты с такой конфигурацией остаются вне эксперимента (та же
  граница, что зафиксирована для preauth `fib daddr . mark oifname`);
- **уже буферизованные kernel-байты и in-flight соединения:** гейт режет новые
  пакеты в момент загрузки, но не отзывает уже отданные/буферизованные байты;
- IPv6 ND spoofing / не-routed сценарии, IPv6-фрагментация, атомарный
  apply/rollback/reboot с реальным трактом, proxy OUTPUT, DNS/Unbound — вне
  пробы; гейт проверен для одного selected-потока точного lab-tuple;
- это не доказательство безопасности всей TProxy-функции и не замена независимого
  crash-guard; владение mark/table/hook-пространством — единый root-writer
  (ADR-0013).
