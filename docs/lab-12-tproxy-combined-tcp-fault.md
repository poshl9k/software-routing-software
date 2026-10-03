# TCP TProxy: инъекция proof-бита вместе с отзывом proxy OUTPUT

## Среда и границы

Авторизованная одноразовая Debian VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`. `backend/tests/lab/tproxy_tcp_combined_fault_probe.py` работает только в трёх временных network namespace. Базовые ordinary firewall, offline preauth/containment и sing-box JSON — из проектных генераторов. Proof-reset, interception, INPUT observer, UID-scoped OUTPUT и инъекция метки — только лабораторные правила; публичный gate `tproxy.not_available` не менялся.

Fixture создан через `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp-proof`, запуск в VM: `python3 tproxy_tcp_combined_fault_probe.py OUTPUT.json` рядом с TCP base/output/UID probe-модулями. Официальный sing-box 1.14.2 amd64 проверен SHA256 release-архива `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`; `sing-box check` проверил generated JSON. Исполнялся с тестовым UID `29090` и effective/ambient `CAP_NET_RAW`, проверялись UID процесса и PID TCP-слушателя. Это не выбор бинарника или service design для продукта.

Два независимых установленных TCP-потока: каждому предшествуют healthy echo и `ct state established` для точного client tuple. После потери interception лабораторное правило PREROUTING `-84` выставляет только proof `0x200` **после** reset `-85`; ни route-bit `0x100`, ни новое INPUT-разрешение не добавляются. Для второго потока заранее отзывается proxy UID OUTPUT к `198.18.0.2:19090` через `wan0` на hook `-20`. Новый token проверяется на client ingress, INPUT observer, UID OUTPUT, origin wire и echo receiver. Старый сокет abort-close и sing-box остановлены до восстановления правил; recovery использует новый поток.

## Пакетные наблюдения

| Сценарий | Проход входа | Proxy OUTPUT | Origin |
| --- | --- | --- | --- |
| Коллизия **без** OUTPUT revocation | injector +2, INPUT proof drop 0, INPUT observer +2, exact established +2, FORWARD guard 0 | UID observer +2, drop 0 | новый token получен и возвращён клиенту; source `10.212.2.1` |
| Коллизия **с** OUTPUT revocation | sender ingress token есть, injector +1, INPUT proof drop 0, INPUT observer +1, exact established +1, FORWARD guard 0 | UID drop +5 | новый token не виден в origin wire/receiver, клиент получил timeout |
| Контроль чужого UID при действующем отзыве | иной локальный отправитель `29091` к **тому же** destination IP/port | его observer +5, proxy UID drop delta 0 | echo получен |
| Recovery / explicit off | новый proxy-поток после восстановления проходит; off возвращает ordinary forwarding; fresh default-deny блокирует TCP handshake | — | — |

Отрицательное окно: sender timeout 1.5 секунды + дополнительные 1.5 секунды, затем контроль чужого UID; запрещённый token повторно проверен у origin после этого контроля. Проба завершилась exit 0. Это подтверждает лишь ограниченную защиту **этого** established IPv4/TCP flow, когда UID OUTPUT drop **уже активен**. Коллизия INPUT остаётся реальной: без drop токен утёк. Автоматического обнаружения потери interception и атомарного включения OUTPUT-блокировки нет; отдельный привилегированный writer всё ещё может изменить nft/UID.

После проверки в VM `ip netns list` и `nft list tables` пусты, `ip rule` содержал лишь стандартные правила; VM откатана к snapshot и выключена. Host-free backend suite: **317 passed**. UDP/DNS, IPv6, уже буферизованные proxy bytes, маршруты/egress после смены WAN, policy attribution и agent apply/rollback/boot не проверены. Не открывать TProxy для применения.
