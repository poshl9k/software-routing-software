# DNS baseline при явно выключенном TProxy

## Среда и область доказательства

На разрешённой одноразовой Debian VM `vsr-verify-20261002` проверен **обычный DNS-тракт при `tproxy.enabled=false`**. `backend/tests/lab/generate_tproxy_dns_cases.py` создаёт из действующих генераторов Unbound и ordinary nftables JSON-фикстуру; `backend/tests/lab/tproxy_dns_baseline_probe.py` запускает отдельные client/router/origin network namespace и настоящий Unbound. Процесс/правила сети корневого namespace VM и хоста не менялись. Временный конфиг Unbound с уникальным именем создаётся в `/etc/unbound` **только внутри одноразовой VM**, потому что Debian AppArmor не разрешил чтение из временного каталога; удаляется при завершении пробы. До испытания сохранён snapshot `pre-singbox-20261002`.

Проба использует два виртуальных линка, клиента `10.212.1.2`, resolver `10.212.1.1:53` и синтетический upstream `198.18.0.2:53`. Generated firewall разрешает доступ клиента к DNS роутера по UDP и TCP; FORWARD остаётся default deny. Generated Unbound обслуживает локальную A-запись `router.test. → 192.0.2.77`, явный forward `forward.test.` к синтетическому upstream; остальные имена не уходят в сеть. У origin работают отдельные UDP/TCP DNS echo-ответчики. AF_PACKET наблюдатели на LAN ingress и origin сравниваются с фактическим приёмом запроса upstream; прямой обход firewall контролируется отдельно.

## Реальная VM-проверка

| Клиентский запрос | Результат |
| --- | --- |
| UDP и TCP к роутеру, `router.test.` | правильный локальный A-ответ; запрос не достиг origin |
| UDP к роутеру, `www.forward.test.` | правильный forward-ответ; origin wire и receiver увидели запрос от `10.212.2.1` |
| TCP к роутеру, `tcp.forward.test.` | правильный forward-ответ; origin wire и receiver увидели запрос от `10.212.2.1` |
| UDP и TCP к роутеру, `unknown.test.` | `NXDOMAIN` (`rcode=3`); нет запроса к origin |
| UDP и TCP напрямую к `198.18.0.2:53` | клиентский пакет/SYN виден на ingress, ответ не получен; origin запрос не получил, FORWARD drop counter вырос |

Оба forward-имени нарочно разные: Unbound кэшировал первый UDP-ответ и затем обслуживал тот же QNAME по клиентскому TCP без второго upstream-запроса. Кроме того, Unbound менял upstream DNS transaction ID — сравнивать его с клиентским ID неверно; probe сверяет upstream wire с upstream receiver по имени, транспорту и upstream ID. Клиентский TCP не означает upstream TCP; probe не требует совпадения транспорта между сторонами. Эти наблюдения относятся к реальным пакетам, не к одному `unbound-checkconf`.

Первые итерации не проходили из-за AppArmor-пути конфига, ошибочного ожидания одинаковых DNS ID, ожидаемого `REFUSED` вместо наблюдённого `NXDOMAIN` и теста повторно закэшированного QNAME. Это были проблемы лабораторной пробы; итоговый полный запуск завершился exit 0: все UDP/TCP local/forward/unknown/direct случаи прошли. После пробы в VM не осталось test namespace, nft таблиц или временных `/etc/unbound/vsr-dns-*.conf`; VM возвращена к snapshot и выключена. Позднее улучшена только очистка probe при частичном старте/ошибке удаления: host-free тесты с симуляцией этих ошибок и отсутствующего Unbound прошли, весь backend suite — **328 passed**. Изменённую cleanup-ветку в VM не запускали.

Повтор после отката к `pre-singbox-20261002` остановился **до любых сетевых изменений**: в этом snapshot не установлен `unbound`. Это ограничение воспроизводимости VM, а не успешный второй прогон. Зависимость для повторного испытания нужно разрешить в отдельно санкционированной подготовке VM; итоговый успешный запуск выше произведён до отката. После неудачного повтора snapshot возвращён повторно, VM выключена.

## Не проверено

Это **не** доказательство DNS-политики при включённом TProxy. Нет перехвата DNS выбранных источников, приоритета локальных записей/forwards относительно sing-box, блокировки внешнего DNS при падении sing-box, защиты от DoH/DoT, IPv6 DNS, автоматического rollback или failover. `tproxy.not_available` остаётся обязательным.
