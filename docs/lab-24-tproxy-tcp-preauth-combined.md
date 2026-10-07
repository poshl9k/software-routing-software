# TCP-проба: перехват TProxy вместе с предварительной авторизацией

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab` (2 vCPU/2 GiB, libvirt, сеть `default`), снимок чистого состояния `pre-singbox-2026`. Все сетевые изменения — внутри трёх временных network namespace; корневое пространство гостя, маршруты и firewall хоста не менялись. Рабочий домен `vsr-live-403ab3a` не затронут.

## Что проверялось

Закрывался открытый вопрос блокера #1 из `docs/sing-box-tproxy-plan.md`: при активном TProxy-перехвате пакет обрабатывается LOCAL_IN → sing-box → LOCAL_OUT и **обходит default-deny FORWARD** (`docs/lab-05-singbox-tproxy.md`). Гипотеза: экспериментальная предварительная авторизация (`generate_tproxy_preauthorization`, post-DNAT first-match, default deny, hook `-90`) закрывает обход и для TCP. Ранее UDP-комбинация preauth+sing-box+containment прошла (`docs/lab-07`), TCP-комбинация с реальным перехватом не проверялась.

## Материал

- Генератор: `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp-preauth-combined` (новый режим). Берёт **настоящие** продуктовые тексты: ordinary firewall, preauthorization, containment и JSON sing-box.
- Проба: `backend/tests/lab/tproxy_tcp_preauth_combined_probe.py` — standalone, stdlib, root-only, только внутри трёх новых namespace. Перехват TProxy, INPUT proof и UID OUTPUT observer — **лабораторные** правила, не продуктовые.
- sing-box: официальный `SagerNet/sing-box` v1.14.2 linux/amd64, SHA256 архива `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`. Это тестовый бинарник, не закреплённый продуктовый релиз; в VM размещён по фиксированному пути `/var/cache/vsr-singbox-probe`.
- Host-free проверки: `backend/tests/test_tproxy_preauth_combined_lab.py` (opt-in маркер, узость правил, порядок hook'ов, off-удаление только своих таблиц).

## Результат

Проба завершилась **EXIT=0**, вывод `PASS`:

> real interception plus preauthorization never bypassed default-deny FORWARD; proxy OUTPUT was authorized separately while active; explicit off restored ordinary routing.

- (a) allow / pass-before-block: токен проходит через прокси, origin видит source роутера; containment-guard = 0.
- (b) deny_first / default_deny: fresh SYN **и** established-поток (preauth перепроверяет каждый пакет — нет established-shortcut) не достигают origin при активном перехвате. Заблокированный пакет drop'ается на preauth (`prerouting -90`) до перехвата: обхода FORWARD нет.
- (c) proxy OUTPUT авторизуется **отдельно** от FORWARD, keyed на UID сокета: при UID-скопированном отзыве новый токен в активном окне не доходит и не эхоится (drop>0), а другой UID к **тому же** tuple `198.18.0.2:19090` проходит (`other` +5, drop 0). Это доказывает разделение по UID, а не по destination.
- (d) explicit off возвращает обычную маршрутизацию; обычный default-deny fresh SYN снова блокируется.
- (e) cleanup удалил namespace и таблицы.

## Найденное ограничение (важно)

Отзыв OUTPUT верен **в активном окне** и для новых outbound-connect'ов. Но байты, уже принятые в send-buffer сокета, при teardown (client abort → sing-box закрывает outbound) уходят к origin одним сегментом, которому `meta skuid` в LOCAL_OUT **не сопоставляет** владельца (диагностические skuid-бакеты пусты; достаточно destination-scope). Проба это печатает как `teardown_buffer_flush` и не выдаёт за успех. Это то же ограничение «buffered bytes», что в `docs/lab-08` и `docs/lab-12`.

## Что это доказывает и чего не доказывает

Доказывает: при **активном** preauth реальный TCP-перехват не превращает отклонённый firewall-пакет в разрешённое соединение; proxy egress контролируется независимой точкой, а не FORWARD.

Не доказывает: удержание уже буферизованных байт при teardown; IPv6; DNS/Unbound; policy routing/ECMP и `fib daddr . mark oifname` на iif/L4-зависимых правилах; offload/bridge; отсутствие race с произвольным сторонним nft-writer; атомарный apply/rollback/reboot; failover. UID 29090/29091 — лабораторные идентичности, не продуктовая модель владения; marks/UID продуктом не зарезервированы. Публичный gate `tproxy.not_available` не тронут.

## Проверки вне VM

Host-free backend: `uv run --no-sync pytest -q` → **516 passed**. Golden-файлы генераторов не изменены.