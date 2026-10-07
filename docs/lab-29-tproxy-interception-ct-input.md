# Lab-29: INPUT-авторизация по `ct mark` в продуктовом генераторе перехвата + UDP packet-proof

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab` (kernel
6.12.107+deb13-amd64, nftables 1.1.3, Python 3.13.5), сеть `default`. Все
сетевые изменения — внутри трёх временных network namespace
(`vsr-tcp-router`/`vsr-tcp-client`/`vsr-tcp-origin` для TCP,
`vsr-pa-router`/`vsr-pa-client`/`vsr-pa-origin` для UDP); корневое пространство
гостя, его маршруты и firewall не менялись. Рабочий домен `vsr-live-403ab3a` не
затронут. Публичное включение TProxy по-прежнему запрещено: `tproxy.not_available`
не открывался. sing-box: тестовый `/var/cache/vsr-singbox-probe`
(`SagerNet/sing-box` v1.14.2 linux/amd64), то же окружение, что lab-24/26/27.

## Закрываемая дыра

lab-09 показал, что INPUT-авторизация по packet `meta mark` подделываема: любое
привилегированное правило, сработавшее раньше в пакетном пути, может выставить
proof-бит и пропустить established-поток. lab-26 доказал, что перенос владения в
`ct mark` (отдельное 32-bit пространство conntrack) нейтрализует **точную**
инъекцию packet-mark, но оставил дизайн лабораторным. lab-27 перенёс
детерминированный захват в продукт, но INPUT-авторизации в генераторе не было —
существовал только packet-mark `0x100` для routing/policy-route. ADR-0013
фиксирует реальную границу: единственный root-writer пространства mark/table/hook.

Здесь lab-26 перенесён в **продуктовый** генератор (gated, офлайн) и добавлен
packet-proof для UDP (lab-27 был TCP-only).

## Артефакты

- `backend/src/vs_router/generators/nftables.py:generate_tproxy_interception` —
  теперь эмитит три таблицы: `inet vs_router_tproxy_ct_reset` (PREROUTING `-85`),
  `inet vs_router_tproxy_interception` (`-80`) и `inet vs_router_tproxy_input`
  (INPUT `-20`). Офлайн, без I/O.
- `backend/src/vs_router/generators/marks.py` — обе новые таблицы и их
  hook-приоритеты внесены в единый реестр владения; routing-mark `0x100` и
  conntrack-proof-бит `0x200` берутся из зарезервированных констант
  (`MARK_TPROXY_ROUTE_VALUE`, `MARK_TPROXY_CT_PROOF_*`).
- `backend/tests/test_tproxy_interception.py` — host-free: узость, порядок
  hook'ов, reset, guard по `ct mark`, детерминизм, off, владение
  mark/table/hook, инертность агента, opt-in VM-fixture (TCP + UDP).
- `backend/tests/lab/generate_tproxy_preauth_cases.py` — новый режим
  `--tproxy-interception-udp` (маркер `__tproxy_interception_udp__`); режим
  `--tproxy-interception` (маркер `__tproxy_interception__`) обновлён под
  ct-дизайн.
- `backend/tests/lab/tproxy_interception_probe.py` — TCP-проба: добавлено
  доказательство (c) «INPUT по ct mark» (lab-09 packet-mark forge после reset).
- `backend/tests/lab/tproxy_preauth_probe.py` — UDP-ветка
  `interception_ct_probe(...)` (маркер `__tproxy_interception_udp__`).

SHA256:

| Файл | SHA256 |
| --- | --- |
| `tproxy_interception_probe.py` | `d9b655b13e0a62cbfab0776816814158772e5d60f431e983cfd4e58e4981b0d2` |
| `tproxy_tcp_probe.py` (базовые хелперы TCP) | `cd2ca27a5ad563875bd69f1e8b0867677db516cf214d1deb557e9e5af2512dc9` |
| `tproxy_preauth_probe.py` (базовые хелперы UDP) | `31db3464fbc73a60e843b75d4f08ec61f77ea6137edb15c5597c55824e260742` |
| `generate_tproxy_preauth_cases.py` | `74cc84d87e50a52d6a41bc8b4f94a10b8c0ea30ad65d40f13475d3ab2b768315` |
| TCP fixture (`--tproxy-interception`) | `ffe04ccac769e97a9a55fc414de82ce0b28059cff4297198cb5611e91f18b246` |
| UDP fixture (`--tproxy-interception-udp`) | `f46f8021f35f4607d06374d18240f8365cf3b9508c3828494f8a3a3a13817f41` |

## Схема (hook / priority / mark / ct mark)

```
table inet vs_router_tproxy_ct_reset        # owner: generators/marks.py
  chain prerouting  hook prerouting priority -85; policy accept;
    iifname != { <selected ingress> } return
    fib daddr type local return              # local-FIB (mark-agnostic) → return
    ct status dnat return                    # DNAT / port-forward
    meta nfproto != ipv4 return
    meta l4proto != { tcp, udp } return
    ct mark set ct mark & 0xfffffdff         # clear reserved ct proof bit

table inet vs_router_tproxy_interception    # owner: generators/marks.py
  chain prerouting  hook prerouting priority -80; policy accept;
    <same exemptions>
    meta nfproto ipv4 meta l4proto tcp \
        meta mark set 0x100 ct mark set ct mark | 0x200 \
        tproxy ip to 127.0.0.1:51272 counter accept comment "tproxy_tcp"
    meta nfproto ipv4 meta l4proto udp \
        meta mark set 0x100 ct mark set ct mark | 0x200 \
        tproxy ip to 127.0.0.1:51271 counter accept comment "tproxy_udp"

table inet vs_router_tproxy_input           # owner: generators/marks.py
  chain input       hook input priority -20; policy accept;
    <same exemptions>
    ct mark & 0x200 == 0 counter drop comment "tproxy_input_denied"
```

- **Hook / priority:** preauth `-90` → reset `-85` → capture `-80` (меньший
  приоритет исполняется раньше) → INPUT guard `-20`. Established-shortcut нет:
  preauth перепроверяет каждый пакет (lab-24/26).
- **Routing mark:** `0x100` = `marks.MARK_TPROXY_ROUTE_VALUE`, бит 8, namespace
  `TPROXY_RESERVED_BITS`; генератор вызывает `marks.assert_no_collisions(...)`.
  Тот же mark drive'ит policy-route helper (`marks.POLICY_ROUTES[0]`:
  `ip rule priority 100 fwmark 0x100 lookup 100` + `ip route add local 0.0.0.0/0
  dev lo table 100`).
- **ct mark:** `0x200` = `marks.MARK_TPROXY_CT_PROOF_VALUE` — **отдельное**
  32-bit conntrack-пространство (не packet-mark REGISTRY). Capture выставляет его
  в том же узком rule после routing mark; reset `& 0xfffffdff` очищает; INPUT
  guard допускает только при наличии бита. Packet proof-бит `meta mark | 0x200`
  в генераторе отсутствует по построению.
- **Off:** `enabled=False` → `destroy table` для всех трёх своих таблиц
  (`ct_reset`, `interception`, `input`) и ни для каких чужих. Полный teardown
  каркаса (`tproxy_apply.cleanup_content`) сносит все non-wired owned-таблицы,
  выведенные из `marks.TABLES`.
- **Фазы каркаса не изменены:** `guards → readiness → interception`; reset+guard
  грузятся как часть артефакта `tproxy_interception` вместе с захватом.

## Подключение к apply (gated)

В `agent/tproxy_apply.py` ничего не менялось: `build_artifacts` берёт
`generate_tproxy_interception(version)`, `TPROXY_FILES`/`PHASE_ORDER` те же.
Ветка достижима только из офлайн-`model_copy` (публичный gate закрыт),
`enabled=False` инертен. Валидатор — `nft -c -f`; сгенерированный текст прошёл
синтаксическую проверку в VM (`nft -c -f` → `SYNTAX_OK`).

## Результат на пакетах (VM, EXIT=0)

### TCP (`tproxy_interception_probe.py tcp-ct.json`)

| Шаг | Наблюдение |
| --- | --- |
| `allow` / `pass-before-block` | токен через прокси: peer origin `10.212.2.1`, вход/OUTPUT +4/+4, containment guard 0 |
| `deny_first-fresh` / `default_deny-fresh` | fresh SYN → `TimeoutError` |
| `ct-guard-healthy` | здоровый поток по proxy, guard drop delta 0 |
| **`ct-guard`** (lab-09: удалён захват, инъекция `meta mark | 0x200`, `-84`) | `delivered=false`, `forge_delta=6`, **`input_guard_drop_delta=6`**, `echoed=false`, sender timeout, `established=6` |
| `ct-guard-recovered` | после восстановления захвата положительный контроль проходит |
| `deny_first` / `default_deny` (established) | blocked: ingress +1, origin/echo пусты, `violation=false` |
| `off-allow` | peer `10.212.1.2`, source port сохранён, вход/OUTPUT = 0 |
| `off-default-deny-fresh` | снова `TimeoutError` |

Ключевая строка: packet-mark-инъекция lab-09 (**только** `meta mark`) после
reset больше **не** пропускает established TCP — INPUT-guard по `ct mark` режет
пакет (`input_guard_drop_delta=6`), здоровый поток и recovery проходят.

### UDP (`tproxy_preauth_probe.py udp-ct.json`)

| Шаг | Наблюдение |
| --- | --- |
| `ct_allow` / `ct_allow_control` | токен через прокси: origin wire 2/receive 1, proxy OUTPUT +1 |
| `ct_deny_first` / `ct_default_deny` | origin wire 0 / receive 0, proxy OUTPUT 0 |
| **`ct_guard_forge`** (TProxy-правило выставляет packet mark `0x100`, но **не** ct proof; reset оставляет бит чистым) | `reply=null`, **`input_guard_drop_delta=1`**, `established_delta=1`, `proxy_output_delta=0` |
| recovery | восстановление захвата → токен снова через прокси |
| `ct_off` | обычная маршрутизация: origin wire 2/receive 1, source port сохранён, proxy OUTPUT 0 |
| `ct_off_default_deny` | fresh → 0/0 |

UDP-случай показывает то же владение: intercepted UDP-пакет с routing-mark, но
без ct-proof, **не** доходит до proxy — его режет INPUT-guard по `ct mark`.
(Packet-mark forge в UDP-пробе не гонялся в позиции «после reset без захвата»:
при снятом capture UDP-поток уходит в FORWARD и его режет containment `-10`, а не
INPUT-guard — механизм тот же, что зафиксирован в lab-07.)

После обеих проб `ip netns list` и тестовые `nft list tables` пусты, `ip rule` —
только стандартные, table 100 удалена.

## Host-free проверки

`uv run --no-sync pytest -q` → **728 passed**, 0 падений (в рабочем дереве
параллельно присутствуют изменения других задач; собственный вклад — новые и
обновлённые тесты `test_tproxy_interception.py` и проверки реестра). Golden-файлы
и `generate_nftables`/`generate_singbox` не изменены: генератор перехвата —
аддитивно расширенная функция, покрытая host-free. Обновлённые host-free тесты
фиксируют: три таблицы и их приоритеты, reset `-85` и его маску, capture `-80`
(`meta mark 0x100` + `ct mark | 0x200` + `tproxy`), INPUT-guard `-20`
(`ct mark & 0x200 == 0 drop`, без `meta mark`, без `accept`), отсутствие
packet-proof `meta mark | 0x200`, детерминизм и порядок таблиц, off-удаление
ровно своих таблиц, регистрацию таблиц/hook'ов в `marks.py`, покрытие
`cleanup_content`/`owned_tables`, opt-in TCP- и UDP-fixtures.

## Что доказывает и чего НЕ доказывает

**Доказывает (в этих namespace, на реальном пакетном тракте, настоящий sing-box,
настоящие firewall/preauth/containment + сгенерированный захват/guard):**

- расширенный продуктовый генератор детерминирован, узок и офлайн; при off снимает
  ровно свои три таблицы;
- разрешённый TCP- и UDP-поток идёт через прокси; запрещённый (fresh и
  established) не доходит до origin/echo — preauth `-90` отрабатывает до захвата
  `-80`;
- INPUT-авторизация по **`ct mark`**: packet-mark-инъекция lab-09 (TCP) и
  TProxy-правило без ct-proof (UDP) **не** проходят — guard по `ct mark` режет
  intercepted-пакет;
- явный off восстанавливает обычную маршрутизацию с сохранением default deny.

**НЕ доказывает:**

- публичный gate `tproxy.not_available` **не открыт** — это не enablement;
- неподделываемость против **root/привилегированного** writer'а: правило
  `ct mark set ct mark | 0x200` (lab-26) всё равно доставляет token; корректное
  требование — не «неподделываемый бит», а **единственный writer** (ADR-0013);
- уже буферизованные kernel/proxy байты, proxy OUTPUT-авторизация, DNS/Unbound,
  IPv6, произвольный policy routing/ECMP, bridge/offload, failover;
- атомарный apply/rollback/reboot с реальным перехватом: `tproxy_policy_route_commands`
  — данные для пробы/тестов; на реальном хосте policy route через агент не
  применялся (произвольный shell запрещён);
- валидатор sing-box (`sing-box check -c`) предполагаемый; бинарник не выбран и
  не закреплён как продуктовый релиз (ADR-0012);
- `ct mark` как владение проверен для одного TCP- и одного UDP-потока точного
  lab-tuple; это не доказательство для всех протоколов/потоков.
