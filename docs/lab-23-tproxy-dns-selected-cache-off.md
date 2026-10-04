# Selected Unbound: запрет выдачи старого ответа после потери stub

## Причина и изменение

В `docs/lab-22-tproxy-dns-stub-failure.md` selected Unbound после остановки fake DNS-stub ответил из собственного кэша на ранее разрешённое unmatched имя. Для отдельного **offline-only** selected-конфига генератор теперь выставляет `cache-max-ttl: 0`, `cache-max-negative-ttl: 0`, `serve-expired: no`. Ordinary Unbound и действующий live `generate_unbound()` не менялись. Выключение кэша selected намеренно затрагивает и **явные forwards**, что требует оценки производительности до выпуска; локальные `local-data` остаются в конфиге. Это не host-owned detector и не продуктовая активация.

## Изолированная VM-проверка

Одноразовая Debian 13 VM `vsr-verify-20261002`, те же четыре namespace и два отдельных Unbound под UID `29092`/`29093`, тестовый loopback DNS-stub и два тестовых WAN origin. Каждый конфиг прошёл `unbound-checkconf`, nft-файлы — `nft -c` до применения в router namespace. После здоровых проверок fake stub завершён без остановки Unbound/guard, затем запущен заново без перезапуска resolver.

| Проба | Фактическое наблюдение |
| --- | --- |
| Повтор того же положительного selected QNAME при живом stub (UDP и TCP) | Оба раза получен ответ `203.0.113.8`, **каждый** повтор зарегистрирован fake stub. Ordinary повтор того же QNAME не породил нового WAN-запроса. |
| То же ранее разрешённое selected имя после остановки stub | По TCP не получен прежний A-ответ; probe вывел `previously resolved selected name blocked after stub loss: PASS`. |
| Новые selected QNAME по UDP/TCP при остановленном stub | Оба дали timeout; QNAME не пришли ни на ordinary, ни на explicit WAN origin во время отказа и после восстановления. Обычный клиент продолжил получать ответ с ordinary origin на **другое** свежее имя. |
| Выбранный клиент при отказе | Локальная запись и новый explicit forward сохранились по UDP/TCP; forward подтверждён у разрешённого origin. |
| После рестарта stub | Новые selected UDP и TCP имена получили ответ stub без перезапуска Unbound; у WAN origin их нет. |

Финальный пакетный прогон завершился `guest exit: 0`; прежние UID INPUT/OUTPUT и direct-DNS проверки также прошли. Временные namespaces/процессы/конфиги удалены, VM возвращена к `pre-singbox-20261002` и выключена. Host-free тест явно проверяет, что опции только в selected-конфиге и не трогают ordinary.

## Не доказано

Опции ограничивают обычные ответы из кэша в наблюдаемой последовательной UDP/TCP-пробе; **не** обещают отдельный upstream-запрос на каждый параллельный клиентский запрос. Unbound может объединять одновременные запросы; дополнительно остаются отрицательные ответы, DNSSEC/aggressive NSEC, опциональные кэши, кэш клиента/stub и ответы, уже находящиеся в очередях или сокетных буферах. Проверка не содержит настоящего sing-box DNS и не решает отказ самой службы Unbound, автоматическое обнаружение сбоя, атомарную активацию/reboot/rollback, IPv6 или privileged bypass. OUTPUT allow для явного forward привязан к IP/порту, не к QNAME. Поэтому `tproxy.not_available` остаётся закрытым.

Исторический lab-22 фиксирует **предыдущий** конфиг с кэшем; текущий fixture/probe дополнен этим новым режимом и уже не воспроизводит старый ответ из кэша без явного отката параметров.
