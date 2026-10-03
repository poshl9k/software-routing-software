# TCP TProxy: лабораторная идентификация исходящих сокетов sing-box

## Среда и область проверки

Одноразовая разрешённая Debian VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`. `backend/tests/lab/tproxy_tcp_uid_probe.py` работает только внутри трёх временных network namespace. Использованы настоящий generated ordinary firewall/preauth/containment и sing-box JSON, а interception/INPUT proof/OUTPUT guard остались лабораторными. Сгенерировать вход через `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp-proof`, затем в VM запустить `python3 tproxy_tcp_uid_probe.py OUTPUT.json` вместе с двумя соседними TCP probe-модулями. Публичный `enabled=true` не разрешён.

Официальный sing-box 1.14.2 amd64 распакован из архива с проверенным SHA256 `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` — **только тестовый бинарник, не закреплённый продуктовый релиз**. `sing-box check` проверил generated JSON. Проба разрешает доступ числовому UID `29090` только к проверенному secret-free тестовому конфигу и запускает sing-box внутри router namespace через `setpriv` с `CAP_NET_RAW`; проверяет действительный UID процесса, `CapEff`/`CapAmb` и принадлежность TCP-слушателя PID. Не выполняет `useradd` или `setcap`.

Независимая таблица `inet vsr_tcp_uid_guard` проверяет `meta skuid 29090` и отдельно `29091` для **одного и того же** назначения `198.18.0.2:19090` через `wan0` в OUTPUT hook `-20`. После здорового обмена на установленном TCP socket вставляется правило `meta skuid 29090 ... counter drop` перед обычным OUTPUT. Вторая отправка на том же клиентском socket содержит новый уникальный токен. Одновременно другой локальный процесс с UID `29091` отправляет свой токен тому же origin адресу и порту. Guard остаётся активным до остановки старого клиента/приёмника и sing-box; затем новый TCP поток доказывает восстановление. Off-контроли используют обычный forwarding и fresh default-deny.

## Наблюдения

| Случай | Результат |
| --- | --- |
| Здоровый sing-box UID `29090` | echo от proxy-пути, origin peer `10.212.2.1`; наблюдались сквозной трафик и `ct state established` клиентского tuple (контрольный счётчик +2) |
| Отозван OUTPUT UID `29090` при работающем proxy | клиентский токен увиден на ingress; INPUT observer +1; UID drop +5; **origin wire и echo receiver токен не увидели**, клиентский ответ отсутствовал в ограниченном окне |
| Другой UID `29091` на **том же** origin tuple при действующем drop | echo получен, origin peer `10.212.2.1`; observer другого UID +5, proxy UID drop delta 0 на время контроля |
| Recovery и explicit off | новый proxy-поток прошёл; после off обычный forwarding прошёл, fresh default-deny не дал установить TCP |

Лабораторный процесс завершился exit 0. Наблюдение длилось sender timeout 1.5 секунды + 1.5 секунды дополнительного окна, затем контрольные запросы; это не гарантия для длительных потоков. После пробы `ip netns list` и `nft list tables` в корневом namespace VM пусты, `ip rule` содержит только стандартные правила. VM возвращена к `pre-singbox-20261002`, выключена. Host-free backend suite: **315 passed**.

## Вывод и открытые блокеры

В этой IPv4/TCP-пробе `meta skuid` отличил исходящий proxy socket от другого локального процесса при одинаковом назначении. Это уже точнее, чем destination-only guard из `docs/lab-10-tproxy-output-revocation.md`, но **не** связывает proxy outbound с исходным клиентом или конкретным правилом `direct`/`block`. Оба UID принадлежат тестовой схеме; root и другое привилегированное ПО могут менять метки, менять правила, запускать процессы под тем же UID или передавать сокеты. Не проверены UDP, DNS, IPv6, все proxy-протоколы, WG/AWG, буферизованные байты, маршруты/egress после смены WAN и управление правами/process lifecycle через agent. Отдельный INPUT proof уязвим к инъекции метки после reset (`docs/lab-09-tproxy-mark-collision.md`). `tproxy.not_available` остаётся закрытым.
