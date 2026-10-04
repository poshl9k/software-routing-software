# DNS listener: граница по фактическому входящему интерфейсу

## Реализация

Новый `generate_tproxy_dns_listener_guard()` в `generators/nftables.py` — **offline-only** nft-таблица с INPUT hook priority `-10`, раньше ordinary INPUT с `ct state established,related accept`. После проверки IPv4 TCP/UDP `:53` выбранный ingress допускает DNS только к IP своего будущего selected Unbound listener; запрос с любого другого ingress к selected listener блокируется. Выход `tproxy_unbound_listener_addresses()` строит эти IPv4-адреса из той же проверенной схемы, что и оба offline Unbound-конфига (`docs/lab-18-tproxy-unbound-split-config.md`). Таблица не подключена к bundle/apply/agent/boot; при явном off генератор выдаёт только её удаление. Обычный DNS и работающая система не меняются; публичное `enabled=True` всё ещё запрещено.

Это важно: bind selected Unbound к `10.212.1.1` сам по себе **не** запрещает клиенту другого интерфейса обратиться к этому IP через роутер, минуя DNS-разделение по источнику. Граница проверяет именно `iifname` до established acceptance; для выбранного интерфейса DNS на другой локальный IP также блокируется. После DNAT уже проверяется фактический адрес назначения; DNAT-исключения и interception требуют отдельного дизайна.

## Пакетная проверка

Одноразовая VM `vsr-verify-20261002`, router/selected/other/origin в изолированных namespaces. Сгенерированные ordinary firewall, preauth, ранее добавленные direct-DNS и FORWARD guard и новая listener-таблица применялись только в router namespace, после `nft -c` каждого шага. На `:53` работали привязанные к **разным адресам** UDP echo receiver, не Unbound; AF_PACKET ingress, receiver и nft-счётчики проверены. Между двумя LAN локально добавлены host routes для cross-listener контроля. Один UDP socket на клиента сохранялся через все стадии.

| Стадия | Наблюдение |
| --- | --- |
| Без listener guard: `lan0` → DNS IP `lan1`, `lan1` → DNS IP `lan0` | Оба получили свои токены; это положительный контроль обходного пути. |
| Guard включён: каждый → собственный DNS IP | Оба получили токены. |
| Те же сокеты → чужой DNS IP | Ingress увидел токены; локальные receiver не получили их, timeout; оба счётчика соответствующих INPUT drop выросли. Observer на INPUT priority `-20` подтвердил `ct state established` до guard для обоих tuple. |
| Listener guard удалён | Оба cross-listener пути снова получили точный echo; остальные проверки direct DNS и FORWARD containment остались успешны. |

Первый VM-прогон установленного UDP не доказал: старый wildcard receiver отвечал с адреса *другого* интерфейса, поэтому conntrack не подтверждал established. После привязки каждого receiver к целевому IP повторный прогон прошёл полностью (`guest exit: 0`, все именованные этапы `PASS`). После проверки namespaces/nft-таблиц нет, VM откатана к `pre-singbox-20261002` и выключена.

## Осталось

Это проверка границы локального **UDP echo**, не DNS split в работающем продукте. Не проверены TCP, IPv6/фрагменты, DNAT, реальный Unbound и кэш двух процессов, output-UID/forward, DNS-stub, отказ sing-box, apply/boot/rollback и комбинация с реальным перехватом. Правило INPUT не ограничивает Unbound OUTPUT. `tproxy.not_available` не открывать.

После обзора добавлен отдельный запрет входа **не с `lo`** к будущему stub `127.0.0.1:15353` до возврата для другого DNS-порта. Новое правило прошло `nft -c` на той же одноразовой VM; пакетный доступ к loopback с внешнего интерфейса **не проверялся**. Ограничение действует только при установке экспериментальной таблицы — продукт его пока не применяет.
