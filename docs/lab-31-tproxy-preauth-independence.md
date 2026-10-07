# Lab-31: независимость перехвата от preauth — закрытие остатка F4

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab` (kernel
6.12.107+deb13-amd64, nftables 1.1.3, Python 3.13.5, sing-box
`/var/cache/vsr-singbox-probe` v1.14.2). Рабочий домен `vsr-live-403ab3a` не
затрагивался: все сетевые изменения — внутри четырёх временных network namespace
(`vsr-e2e-router`/`selected`/`ordinary`/`origin`), корневое пространство гостя,
его маршруты и firewall не менялись. Публичный gate `tproxy.not_available`
**не открывался** (включённый снапшот — только офлайн `model_copy`, как в
lab-24/27/29/30).

## Остаток F4 (lab-30)

При потере таблицы preauth запрещённый selected-поток **доходил до origin**
(`docs/lab-30-tproxy-e2e-matrix.md`, строка F4 = RESIDUAL). Причина — структурная:

- containment (`FORWARD -10`) и обычный default-deny ловят только **транзитный**
  (FORWARD) поток;
- перехват уводит выбранный пакет в `LOCAL_IN → sing-box → LOCAL_OUT`, **минуя
  FORWARD**;
- enforcement политики делает именно preauth; interception/preauth были
  **независимы**, поэтому потеря preauth оставляла живой capture, который
  по-прежнему тащил запрещённый поток к origin в обход FORWARD-policy.

Реальный барьер по ADR-0013 — единственный writer пространства mark/table/hook,
но это не отменяет требования: у потери preauth должен быть независимый
fail-closed исход, а не сквозная дыра.

## Выбранная механика: capture, зависимый от preauth (чистое правило)

`generate_tproxy_preauthorization` на **авторизованном** (first-match `pass`)
selected-транзите выставляет зарезервированный packet-mark
`marks.MARK_TPROXY_AUTH_VALUE` (`0x400`), а `generate_tproxy_interception` в
capture-цепочке **требует** его:

```
# preauth, chain transit (authorized pass):
... meta mark set meta mark | 0x400 counter return comment "allow_tcp"

# interception, chain prerouting (-80), после исключений и перед tproxy:
meta mark & 0x400 == 0 return              # capture только для прошедшего preauth
meta nfproto ipv4 meta l4proto tcp meta mark set 0x100 ct mark set ct mark | 0x200 \
    tproxy ip to 127.0.0.1:51272 counter accept comment "tproxy_tcp"
```

Логика отказа: таблица preauth удалена → mark `0x400` не выставляется → capture
делает `return` (пакет остаётся на обычном FORWARD-пути) → его режет
**независимый** containment `-10` (или default-deny). И разрешённый, и
запрещённый selected-потоки **не достигают origin**; mgmt (`dest zone:router`)
идёт INPUT-путём и сохраняется.

### Почему packet mark `0x400`, а не ct mark / route mark

- **Не route mark `0x100`.** Если preauth выставит `0x100`, пакет **до** routing
  decision попадёт под `ip rule fwmark 0x100 → table 100` и уйдёт в local-доставку
  ещё до tproxy — interception перестал бы быть нужен для доставки, а F2
  («потеря capture») деградировал бы из containment-дропа в полу-открытый локальный
  сокет. Поэтому gate — **отдельный бит**.
- **Не ct mark.** `ct mark` в этом контракте — пространство **INPUT-авторизации**
  (lab-26/29); держать его отдельно от гейта перехвата сохраняет ровно те
  семантики. Плюс reset `-85` чистит ct-proof на каждом пакете, и смешение стало бы
  хрупким. Гейт — про **routing/capture control**, а не про INPUT-auth.
- **Позиция стампа.** Стамп ставится внутри matched-правила, **после** его
  собственного `fib daddr . mark oifname` и перед `counter`, поэтому match-time
  FIB-lookup никогда не видит бит, который правило само пишет (иначе изменился бы
  результат маршрутного матча; см. ошибку FIB в lab-06).
- **Чистое правило, без демона.** Рассматривался альтернативный вариант —
  независимый host-owned watchdog/детектор отсутствия preauth + blanket-drop. Он
  отвергнут: добавляет второй writer/демон, ломает single-writer (ADR-0013) и
  вносит гонку. Gate-правило — декларативно, детерминировано и уже fail-closed по
  построению.
- **Single-writer сохранён.** `0x400` — единственный владелец TPROXY,
  зарегистрирован в `marks.REGISTRY` (`tproxy_preauth_capture_gate`),
  `assert_no_collisions` вызывается обоими генераторами; отдельных writer'ов
  mark/table/hook не появилось.

## Файлы

- `backend/src/vs_router/generators/marks.py` — `MARK_TPROXY_AUTH_MASK/VALUE = 0x400`
  + запись в `REGISTRY` (Owner.TPROXY). Единственный владелец mark.
- `backend/src/vs_router/generators/nftables.py`:
  - `_FirewallCompiler.rules(..., stamps=...)` — стамп-стейтмент после match, до
    `counter`/вердикта;
  - `generate_tproxy_preauthorization` — стамп `meta mark set meta mark | 0x400`
    на каждом `pass`-правиле (block/reject не стампятся);
  - `generate_tproxy_interception` — `meta mark & 0x400 == 0 return` в capture
    (reset и INPUT-guard гейт не несут).
- `backend/tests/test_tproxy_preauth_gate.py` — новый host-free файл: инвариант
  coupling, single-owner, «mark не протекает на deny/off», однонаправленность
  (capture→preauth, не наоборот).
- `backend/tests/test_tproxy_interception.py`, `test_tproxy_preauth.py`,
  `test_tproxy_preauth_combined_lab.py`, `test_tproxy_e2e_lab.py` — обновлены под
  gate/stamp.
- `backend/tests/lab/tproxy_interception_probe.py` — `validate_fixture` требует
  gate и stamp.
- `backend/tests/lab/tproxy_e2e_probe.py` — F4-сценарий переписан на fail-closed
  (нет `RESIDUAL`-ветки); проба печатает PASS/FAIL, без отдельного остатка.

Артефакты генераторов **байт-в-байт** (gated, офлайн). Публичный gate и агент
apply не менялись.

## Результат на VM (`EXIT=0`, F4=PASS)

Офлайн-фикстура из настоящего контура (`plan_tproxy_dns` + `tproxy_apply`),
проба `tproxy_e2e_probe.py` — четыре namespace, настоящие sing-box и два Unbound.

- Норма — та же: N1/N2 proxied (`origin_peer=10.212.2.1`), N3 unselected direct,
  N4/N5 запрещённые origin пуст, DNS-контур (N6–N9), mgmt (N10) — **PASS**.
- **F4: PASS** — `preauth loss → capture gate holds: allowed+denied selected
  transit fail-closed at the independent containment (-10); mgmt kept; recovery ok`.
- F1 (SIGKILL), F2 (удаление interception), F3 (потеря policy route), F5/F6 (DNS),
  R (эмуляция re-apply), OFF — **PASS** без регрессов.
- `summary {pass:18, residual:0, failed:[]}`, `EXIT=0`, cleanup пуст; повторный
  прогон — те же 18/0.

### Дифференциал (доказательство причинности)

Та же фикстура со **снятой** одной gate-строкой (`meta mark & 0x400 == 0 return`)
воспроизводит прежнюю утечку: `fault_preauth_lost FAIL`,
`allowed flow delivered ... reply 'vsr-e2e-f4-...'`, sing-box log показывает
`inbound/tproxy[tproxy-tcp]: inbound connection from 10.212.1.2 → to 198.18.0.2:19090`,
origin получает token (`peer 10.212.2.1`). Значит обход закрывает **именно**
lab-31-gate, а не иное изменение.

SHA256 фикстуры: `c514c2392331817917ee95e0686d3e0f94685be262c57574c18eaa2c74b3dc6d`.

## Host-free проверки

`backend/`: `uv run --no-sync pytest -q` → **758 passed, 0 failed**. Golden-файлы,
`generate_nftables` и `generate_singbox` не менялись (правки — аддитивные
gate/stamp в офлайн-генераторах TProxy и аддитивные/обновлённые тесты).

## Что доказывает и чего НЕ доказывает

**Доказывает (реальный пакетный тракт, 4 namespace, настоящий sing-box, байт-в-байт
артефакты):**

- захват перехвата теперь **зависит от живого preauth**: preauth стампит `0x400`,
  capture без него не срабатывает;
- потеря preauth **fail-closed** для **и разрешённого, и запрещённого**
  selected-транзита (пакет уходит в FORWARD и режется containment `-10`), mgmt
  сохранён, recovery работает;
- это **чистое правило**: без демона, без второго writer'а, единственный владелец
  mark (`marks.REGISTRY`) и single-writer ADR-0013 не нарушены;
- дифференциал показывает, что обход закрывает именно gate.

**НЕ доказывает:**

- публичный gate `tproxy.not_available` **не открыт** — это не enablement;
- **цена** fail-closed — потеря всей selected-связности на время отсутствия
  preauth (сознательный отказ, не graceful degrade); отдельной деградации
  «разрешить, но с политикой» нет;
- неподделываемость: gate-mark — packet mark, подделываемый конкурирующим
  root-writer'ом; реальная гарантия — единственный writer (ADR-0013). Потеря/
  компрометация **самого writer'а** обходит и gate;
- не проверялись: уже буферизованные kernel/proxy байты, proxy OUTPUT, IPv6,
  произвольный policy routing/ECMP, bridge/offload, атомарный apply/rollback/boot
  с реальным перехватом, failover; не-`pass`/иные вердикты и first-match краевые
  случаи за пределами lab-фикстуры; UDP-вариант гейта — в этой пробе F4 гонялся на
  TCP (правило UDP гейтится тем же стампом в том же генераторе, но packet-path
  UDP-потери preauth не воспроизводился отдельно);
- «reboot» — только эмуляция повторного применения артефактов, не реальная
  перезагрузка.
