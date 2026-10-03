# Лабораторная проба sing-box TProxy — ограниченный сетевой тракт

Дата: 3 октября 2026 · одноразовая Debian 13.7 VM `vsr-verify-20261002` · предварительный snapshot `pre-singbox-20261002`. Keenetic не использовался.

## Изоляция и состав

- Только VM: два локальных network namespace `vsr-tp-client` (`10.200.1.2`) и `vsr-tp-origin` (`10.200.2.2`), veth через корневое пространство VM. Ни nftables, ни маршруты хоста не менялись. WAN VM на libvirt NAT не участвовал в тестовом трафике.
- Официальный sing-box v1.14.2, `linux/amd64`; архив сверен с опубликованным digest SHA256 `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` и повторно проверен внутри VM. Это **не** аудит доверия к релизу и не выбор бинарника для установки.
- Тестовый nft `table ip vsr_tproxy_lab`, transient unit `vsr-tproxy-lab.service`, временные policy rule `fwmark 0x123 → table 100` и `local default dev lo` существовали только в VM. Применялись вручную **для эксперимента**, не через агент проекта. Это не готовый механизм apply/rollback.

## Наблюдения

| Сценарий | Наблюдение |
| --- | --- |
| Без перехвата | HTTP на origin: `200`; UDP echo: `origin:probe`. |
| TCP `redirect to :51272`, sing-box слушает `127.0.0.1` (старый генератор) | TCP connect отказан; nft redirect counter = 1. `sing-box check` ранее принимал конфиг, но пакетный тракт не работает. |
| TCP REDIRECT, отдельный **лабораторный** bind `0.0.0.0` + nft INPUT guard для порта | HTTP `200`, счётчик redirect = 2, счётчик `ct status dnat` в INPUT = 6. Такой bind **нельзя** переносить без защиты слушателя. |
| UDP TProxy `to 127.0.0.1:51271`, mark + local route, guard FORWARD | Echo `origin:probe`; счётчик TProxy = 1, guard FORWARD не срабатывал. |
| Остановка sing-box с сохранённым TCP redirect / UDP TProxy | TCP connect отказан; UDP ответ не получен; счётчик UDP TProxy вырос с 1 до 2. Это доказательство только для новых запросов в данной схеме, не всех существующих соединений. |
| Удаление правила перехвата при сохранённом guard | TCP заблокирован (`forward_guard` = 3 packets); UDP timeout (`forward_guard` = 2 packets). |
| Явное выключение: удалить тестовую nft-таблицу и policy route/rule, служба остановлена | HTTP вновь `200`; UDP echo `origin:off`. |
| Модель default-deny FORWARD (`table ip vsr_fw_lab`, `policy drop`) | Без перехвата клиентский HTTP заблокирован. После TCP REDIRECT+sing-box — HTTP **`200`**, хотя FORWARD остаётся `policy drop`. **Критический обход firewall:** пакет обрабатывает LOCAL_IN → sing-box → LOCAL_OUT вместо FORWARD. |
| TCP TProxy вместо REDIRECT, оба inbound на `127.0.0.1`, с `fwmark`/local route | HTTP `200`; счётчик `tcp_tproxy` = 7, `forward_guard` = 0, слушатель только `127.0.0.1:51272`. Проверен синтаксис обновлённого генератора через `sing-box check`; этот вариант не требует wildcard bind. **Обход default-deny FORWARD остаётся.** |
| Лабораторная предварительная авторизация `prerouting priority -200` до TProxy | HTTP заблокирован, счётчик preauth = 2; счётчик TProxy не вырос. Это проверяет точку применения, но **не** реализует перенос всей политики firewall. |

## Вывод и открытый gate

**Включение TProxy по-прежнему запрещено (`tproxy.not_available`).** Требуется согласованная с существующим firewall предварительная авторизация **до** перехвата, сохраняющая default deny, first-match, интерфейсы и исключения DNAT/port-forward; отдельный независимый fail-closed guard; защищённая атомарная последовательность включения/выключения и boot restore. Простое копирование тестовой nft-таблицы в генератор небезопасно.

Таймауты при отказе **не доказывают отсутствие утечки сами по себе**: использовались счётчики перехвата/guard и положительный контроль echo-сервера, но не синхронный захват пакетов и журналы получения уникальных payload на origin во время каждого отказа. Следующий gate: сверить вход, FORWARD/OUTPUT и приёмник по идентификаторам запросов, включая уже установленные соединения и исчезновение policy rule/local route. Текущие результаты — ограниченная проба, не завершённое доказательство fail-closed.

Не проверены: реальный агент/apply/reboot/rollback, реальные WAN/LAN и management path, DNAT/port-forward, DNS и Unbound, IPv6, WG/AWG/proxy выходы, доменные правила при разных протоколах и долгоживущие TCP/UDP-сессии. Все положительные результаты ограничены этой VM и двумя тестовыми namespace.

По завершении VM выключена и возвращена к `pre-singbox-20261002`. Контрольная загрузка после отката подтвердила отсутствие `/root/singbox-lab`, тестовых namespace/nft-таблиц и правила `fwmark 0x123`; затем VM вновь выключена и откатана к тому же snapshot. Временный HTTP-сервер на libvirt NAT хоста остановлен.
