# Lab-27: детерминированный генератор перехвата TProxy + VM-проба

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab` (kernel
6.12.107+deb13-amd64, nftables 1.1.3, Python 3.13.5), сеть `default`. Все
сетевые изменения — внутри трёх временных network namespace
`vsr-tcp-router`/`vsr-tcp-client`/`vsr-tcp-origin`; корневое пространство гостя,
маршруты и firewall не менялись. Рабочий домен `vsr-live-403ab3a` не затронут.
Публичное включение TProxy по-прежнему запрещено: `tproxy.not_available` не
открывался.

## Закрытая дыра

Фаза `interception` в `backend/src/vs_router/agent/tproxy_apply.py` была пуста:
каркас умел ставить guards и готовить sing-box, но генератора самого захвата
(mark/redirect) и управляемого policy route не существовало. lab-05 показала,
что реальный перехват **обходит default-deny FORWARD**; lab-24 доказала, что
предварительная авторизация (`-90`, post-DNAT, default deny) закрывает обход
для TCP; lab-26 перенесла INPUT-авторизацию на `ct mark` и зафиксировала
границу «единственный владелец mark/table/hook». Не хватало детерминированного,
gated генератора захвата, строго идущего после preauth и делящего marks с
продуктом.

## Артефакты

- `generators/nftables.py:generate_tproxy_interception(version)` — таблица
  `inet vs_router_tproxy_interception`, офлайн, без I/O.
- `generators/nftables.py:tproxy_policy_route_commands(action)` — детерминированные
  argv `ip rule`/`ip route` для того же mark (данные, не shell, не I/O).
- `generators/marks.py` — таблица и hook-priority захвата внесены в единый
  реестр владения (единственный владелец).
- `agent/tproxy_apply.py` — фаза `interception` подключена: `TPROXY_FILES`
  `tproxy_guards → singbox → tproxy_interception`, `PHASE_ORDER`
  `guards → readiness → interception`, валидатор `nft -c -f`, `build_artifacts`
  добавляет захват. Инертно при `enabled=False`, gated при закрытом gate.
- `backend/tests/test_tproxy_interception.py` — 18 host-free тестов.
- `backend/tests/lab/generate_tproxy_preauth_cases.py` — режим
  `--tproxy-interception` (opt-in маркер `__tproxy_interception__`), настоящие
  firewall/preauth/containment/sing-box + сгенерированный захват.
- `backend/tests/lab/tproxy_interception_probe.py` — standalone VM-проба.

## Схема перехвата (hook / priority / mark / table)

```
table inet vs_router_tproxy_interception          # овладелец: generators/marks.py
  chain prerouting  type filter hook prerouting priority -80; policy accept;
    iifname != { <selected ingress> } return      # невыбранный ingress
    fib daddr type local return                   # локальный FIB
    ct status dnat return                         # DNAT / port-forward
    meta nfproto != ipv4 return                   # только IPv4
    meta l4proto != { tcp, udp } return
    meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 \
        tproxy ip to 127.0.0.1:51272 counter accept comment "tproxy_tcp"
    meta nfproto ipv4 meta l4proto udp meta mark set 0x100 \
        tproxy ip to 127.0.0.1:51271 counter accept comment "tproxy_udp"
```

- **Hook / priority:** PREROUTING `-80`. Preauth — `-90`, DNS ingress guard —
  `-110`; nft исполняет меньший приоритет раньше, значит preauth **строго до**
  захвата. Established-shortcut отсутствует: preauth перепроверяет каждый пакет
  (совпадает с lab-24/26).
- **Mark:** `0x100` = `marks.MARK_TPROXY_ROUTE_VALUE` (бит 8, namespace
  `TPROXY_RESERVED_BITS`); генератор вызывает `marks.assert_no_collisions(...)`
  — использование proof-бита `0x200` отсутствует по построению.
- **Table id / policy route:** `marks.POLICY_ROUTES[0]` — `ip rule priority 100
  fwmark 0x100 lookup 100` + `ip route add local 0.0.0.0/0 dev lo table 100`.
  Хелпер отдаёт ровно эти две записи (и их inverse `del`).
- **Off:** при `enabled=False` генератор возвращает только
  `destroy table inet vs_router_tproxy_interception\n` — снимает лишь свою
  таблицу. Полный teardown каркаса дополнительно сносит все owned-таблицы
  (`cleanup_content`, выведен из `marks.TABLES`).

## Подключение к apply (gated)

Порядок в `agent/apply.py`: product files → `tproxy_guards` → `singbox` →
`tproxy_interception` (dict-порядок `TPROXY_FILES`). Валидаторы исполняются в
том же порядке, т.е. nft-захват не активируется, пока guards и readiness не
готовы. При `enabled=False` `required()` → False, `build_artifacts()` → `{}`,
файл `tproxy-intercept.nft` не пишется, в маркере нет ключа `tproxy` —
поведение прежнее (тесты инертности). Ветка достижима только из офлайн-снапшота
`model_copy`.

## Результат VM-пробы (EXIT=0)

Fixture `--tproxy-interception` SHA256
`83523d603f7bd468c86b00b9d1100d9bd2d4fca9a8f6e8e161b41a55ed37b0a1`; проба
`tproxy_interception_probe.py` SHA256
`eac9e5cfc1607cf286eb9e796ce7135f012070f4d27ae186cbec4453527a281a`; базовые
хелперы `tproxy_tcp_probe.py` SHA256
`cd2ca27a5ad563875bd69f1e8b0867677db516cf214d1deb557e9e5af2512dc9`. sing-box:
официальный `SagerNet/sing-box` v1.14.2 linux/amd64 (тот же тестовый бинарник
`/var/cache/vsr-singbox-probe`, версия подтверждена внутри VM; хеш архива
`a684484d…`, окружение совпадает с lab-24/26).

Проба `PASS`, exit 0. Ключевые записи:

| Шаг | Наблюдение |
| --- | --- |
| `allow` / `pass-before-block` | токен через прокси: peer origin `10.212.2.1`, вход/OUTPUT счётчики +4/+4, containment guard = 0 |
| `deny_first-fresh` / `default_deny-fresh` | fresh SYN → `TimeoutError`; origin SYN не видит |
| `deny_first` / `default_deny` (established) | blocked: ingress +1, established +6, origin/echo пусты, `violation=false` |
| `*-recovered` | после восстановления захвата положительный контроль проходит |
| `off-allow` | peer `10.212.1.2`, source port сохранён, вход/OUTPUT = 0 → обычная маршрутизация |
| `off-default-deny-fresh` | снова `TimeoutError` |
| cleanup | `ip netns list` пуст, `nft list tables` пуст, `ip rule` — только стандартные, table 100 удалена |

Заблокированный пакет drop'ается на preauth `-90` до захвата `-80`: обхода
default-deny FORWARD для TCP при включённом preauth не воспроизводится.

## Host-free проверки

`uv run --no-sync pytest -q` → **635 passed**, 0 падений. Golden-файлы и
`generate_nftables`/`generate_singbox` не изменены (генератор захвата —
аддитивная новая функция). Тесты фиксируют узость (hook/priority/исключения),
наличие mark при on и отсутствие при off, детерминизм, владение mark, инертность
агента при `enabled=False`, порядок активации guards→readiness→interception и
opt-in VM-fixture.

## Что доказывает и чего НЕ доказывает

**Доказывает:**
- генератор детерминирован, узок и офлайн; при off снимает только свою таблицу;
- сгенерированный захват на реальном пакетном тракте (три namespace, настоящий
  sing-box, настоящие firewall/preauth/containment) отправляет разрешённый поток
  через прокси, а запрещённый (fresh и established) не доставляет ни origin, ни
  echo — preauth `-90` отрабатывает до захвата `-80`;
- явный off восстанавливает обычную маршрутизацию с сохранением default deny;
- каркас apply активирует захват только офлайн (gated), инертен при
  `enabled=False`.

**НЕ доказывает:**
- публичный gate `tproxy.not_available` **не открыт**; это не enablement;
- UDP-перехват на пакетах не гонялся (правило UDP сгенерировано и покрыто
  host-free, но VM-проба ограничена TCP);
- этап INPUT-авторизации по `ct mark` (lab-26) в продукт не перенесён; здесь
  захват ставит packet-mark `0x100`, proof/ct-mark в генератор не входит;
- уже буферизованные байты, proxy OUTPUT, DNS/Unbound, IPv6, policy routing с
  iif/L4-зависимыми правилами, ECMP, bridge/offload, атомарный
  apply/rollback/reboot с реальным перехватом — не проверялись;
- нет типизированного загрузчика TProxy-артефактов/policy route в агенте:
  `tproxy_policy_route_commands` — данные, потребляемые пробой и тестами; на
  реальном хосте политический route не применялся через агент (произвольный
  shell запрещён);
- валидатор sing-box (`sing-box check -c`) предполагаемый; бинарник не выбран
  и не закреплён (ADR-0005);
- «единственный владелец» остаётся контрактом реестра, а не security-гарантией
  против конкурирующего root-nft-writer'а (граница lab-26).
