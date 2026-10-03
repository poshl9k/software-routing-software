# Совместная UDP-проба preauth, sing-box и containment

Одноразовая Debian VM `vsr-verify-20261002`, исходный snapshot `pre-singbox-20261002`. Все live nftables, маршруты и процессы пробы находятся в трёх новых network namespace. Keenetic и сетевые настройки основного пространства VM не менялись.

## Артефакты и граница доказательства

- `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --combined` выдаёт test-only набор: настоящий ordinary firewall, offline preauth и containment, настоящий JSON sing-box. Вызвать из `backend/` через `env -u PYTHONPATH .venv/bin/python ...`. Публичный `enabled=true` остаётся запрещён; тестовые `model_copy` не являются API enablement.
- `backend/tests/lab/tproxy_preauth_probe.py OUTPUT.json` запускается root **только в разрешённой одноразовой VM**, не на хосте или рабочем роутере. Без `--combined` у генератора сохраняется предыдущая UDP INPUT/DNAT-проба.
- В VM заранее нужен официальный sing-box 1.14.2 amd64 по пути `/var/cache/vsr-singbox-probe`. В этой сессии архив скачан с GitHub release, SHA256 проверен до извлечения: `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`. `version` подтвердил 1.14.2, linux/amd64; JSON настоящего генератора прошёл `sing-box check`.
- Тест добавляет **лабораторные**, не продуктовые interception и INPUT-правила: hook -80 после preauth -90; исключения local/DNAT до mark; IPv4 UDP TProxy `127.0.0.1:51271`, packet mark `0x100`, policy rule priority 100 → table 100, local route через lo. INPUT-вставка ограничена lan0, source `10.212.1.2`, destination `198.18.0.2`, UDP 19090 и mark. Это не модель безопасного продуктового происхождения mark.
- Генерируемый containment работает в FORWARD -10. Никаких conntrack/socket shortcuts до preauth не добавлено. Перехват UDP, не TCP. sing-box direct создаёт отдельный OUTPUT-поток, который preauth/containment не авторизуют.

## Наблюдение

Одновременно работают AF_PACKET-наблюдатели и UDP receiver. Каждый запрос имеет уникальный токен и явно отдельный source port. Sender фиксирует отправленные байты, payload/tuple ответа; origin — кадры и payload приложения. Положительные proxy-запросы приходят с source `10.212.2.1`, а explicit-off — с исходного client IP. OUTPUT-счётчик для назначения подтверждает отдельный локальный поток; interception-счётчик увеличивается, FORWARD guard на положительных proxy-пробах остаётся нулевым. Это различает proxy OUTPUT и обычный forwarded fallback.

Окно отрицательного наблюдения: timeout UDP 0.7 секунды плюс 0.2 секунды наблюдения. Готовность listener/capture проверяется отдельно, а работоспособность пути — реальным положительным запросом. Сбой службы вызывается SIGKILL с ожиданием завершения, без автоматического restart. Между восстановлением и следующей неисправностью выполняется положительный контроль.

| Случай | wire sender / origin | приложение origin | proxy OUTPUT delta | результат |
| --- | --- | ---: | ---: | --- |
| явный firewall allow | 2 / 2 | 1 | 1 | ответ |
| deny перед allow | 1 / 0 | 0 | 0 | блокировка |
| default deny | 1 / 0 | 0 | 0 | блокировка |
| allow после отказов | 2 / 2 | 1 | 1 | ответ |
| SIGKILL sing-box | 1 / 0 | 0 | 0 | блокировка |
| служба восстановлена | 2 / 2 | 1 | 1 | ответ |
| удалён только interception | 1 / 0 | 0 | 0 | guard drop +1 |
| interception восстановлен | 2 / 2 | 1 | 1 | ответ |
| удалён только local route table 100 | 1 / 0 | 0 | 0 | блокировка |
| local route восстановлен | 2 / 2 | 1 | 1 | ответ |
| удалён только fwmark policy rule | 1 / 0 | 0 | 0 | блокировка |
| policy rule восстановлен | 2 / 2 | 1 | 1 | ответ |
| explicit off, ordinary firewall allow | 2 / 2 | 1 | 0 | обычная маршрутизация |
| explicit off, ordinary default deny | 1 / 0 | 0 | 0 | блокировка |

Wire включает запрос/ответ, не число независимых запросов. После удаления interception пакет действительно достиг FORWARD guard: счётчик увеличился на 1. Для исчезновения local route первоначальная проверка того же счётчика **не прошла**, хотя payload не достиг origin. Финальная проба не приписывает эту блокировку guard: пакет может погибнуть раньше FORWARD при сохранённом TProxy socket assignment; точное место падения не трассировалось. Не отсутствие ответа, а совместное наличие токена на ingress, отсутствие на origin и отсутствие OUTPUT сопоставлено с контрольными запросами.

## Повторная проба: один established UDP tuple через отказы

Combined-режим расширен второй веткой: отдельный клиентский процесс держит **один и тот же UDP socket**, привязанный к `10.212.1.2:25000`, до конца всей матрицы. После каждого изменения отправляет новый уникальный токен тому же `198.18.0.2:19090`; сокет не переоткрывается, conntrack не очищается. Старые ответы не принимаются за результат нового запроса: receiver sender-процесса сравнивает payload с текущим токеном до deadline.

Лабораторный observer PREROUTING -150 (после conntrack, до preauth) считает **только этот исходный tuple в `ct state established`**. Первый успешный запрос дал delta 0; каждый следующий persistent-запрос, включая блокируемые, дал delta 1. Таким образом, установленное состояние подтверждено ядром, а не предполагается из повторного source port. В конце проверены живой исходный процесс и отсутствие всех запрещённых токенов у origin за весь последующий период контрольных запросов.

| Persistent-сценарий | wire sender / origin | приложение origin | результат |
| --- | --- | ---: | --- |
| initial allow и все recovery controls | 2 / 2 | 1 | proxy-ответ |
| deny перед allow, default deny при включённом намерении | 1 / 0 | 0 | preauth не пропускает established shortcut |
| SIGKILL sing-box | 1 / 0 | 0 | нет доставки |
| потеря interception | 1 / 0 | 0 | нет доставки, guard сработал |
| потеря local route | 1 / 0 | 0 | нет доставки |
| потеря policy rule | 1 / 0 | 0 | нет доставки |
| explicit off с обычным allow | 2 / 2 | 1 | ответ обычным forwarding, client source IP |

Для положительных пар fresh+persistent proxy OUTPUT delta составила 2; для отрицательных и explicit-off — 0. При удалении interception guard drop delta 2 соответствует свежему и established запросам. При восстановлении правил counters сбрасываются генератором; observer established/OUTPUT не пересоздаётся.

Последний ordinary default-deny контроль после explicit off остаётся **только fresh-flow**: действующий обычный firewall допускает `established,related` до пользовательских правил. Поэтому немедленное отозвание старого потока при последующей смене ordinary allow → default deny здесь не требуется и не доказано; это не утечка включённого TProxy. Отрицательные окна остаются ограниченными, стресс/долгие UDP timeout и TCP не проверены. Расширенная проба завершилась exit 0; cleanup и backend suite повторно прошли.

## Проверки и ограничения

Финальная combined-проба завершилась exit 0. Предыдущая INPUT/DNAT-проба также повторно прошла после расширения генератора. Backend: 297 passed. Cleanup подтвердил удаление test namespace и отсутствие test nft tables в основном пространстве VM; затем VM возвращена к исходному snapshot и выключена.

Ревью субагента подтвердило ограничения: INPUT нельзя разрешать по `iif lo` или listener port — TProxy сохраняет исходные packet headers; mark не является разрешающим токеном; OUTPUT требует отдельной политики; blanket containment ломает выбранный DNAT/обратное направление. Продуктовые генераторы/apply/bundle не подключены и не изменены этой пробой.

**Не доказаны:** established TCP после отказа, TCP-перехват с preauth, длительные/нагрузочные UDP-сценарии, local/DNAT вместе с перехватом и containment, hairpin, OUTPUT authorization/смена outbound, DNS/Unbound, IPv6 WAN guard, mark conflicts, policy routing/ECMP, offload/bridge, исчезновение guard, failover, атомарный apply/rollback/boot. Ручная сборка лабораторного тракта не доказывает продуктовый fail-closed. До этих gates `tproxy.not_available` сохраняется.
