# DNS: граница локального INPUT и выбранного FORWARD

## Объём

Одноразовая Debian VM `vsr-verify-20261002`; четыре временных network namespace (router, выбранный `lan0`, невыбранный `lan1`, origin за `wan0`). Root namespace VM и сеть хоста не менялись. В VM после отката нет Unbound; **на порту 53 работали тестовые UDP echo-процессы с ASCII-токенами, не DNS-серверы и не корректные DNS-запросы**. Не заявлять проверку local-data, forward-zone, кэша, domain policy, DNS TCP или DNS при реальном sing-box.

Фикстура `backend/tests/lab/generate_tproxy_dns_boundary_cases.py` получена из действующих генераторов ordinary nftables, экспериментальных preauth и containment; `backend/tests/lab/tproxy_dns_boundary_probe.py` запускается только root на разрешённой VM, импорт безопасен на хосте. Публичный `enabled=True` запрещён; в тесте включённое намерение создаётся только через `model_copy` для генерации offline правил. Ordinary firewall разрешает UDP/53 к роутеру и к внешнему origin с обоих LAN и UDP/19090 к origin. Перехвата/route-mark/sing-box нет. Guard — отдельная сгенерированная таблица FORWARD, source-specific `lan0`; preauth возвращает локальные адреса через `fib daddr type local return`. Каждая применённая серия правил предварительно прошла `nft -c` **внутри namespace**.

| Этап | Фактическое наблюдение |
| --- | --- |
| Без guard: выбранный/невыбранный → локальный UDP/53 роутера | оба получили точный echo-токен; AF_PACKET ingress и локальный receiver подтвердили доставку |
| Без guard: выбранный → внешний UDP/53 | origin wire и receiver получили токен, клиент получил echo. Это **небезопасный контроль**: preauth сама по себе не останавливает разрешённый firewall прямой DNS-трафик |
| С заранее установленным guard: выбранный → локальный UDP/53 | локальный сервис остался доступным |
| С guard: новый токен в том же UDP-socket/tuple выбранный → внешний UDP/53 | ingress увидел токен; `ct state established` observer вырос до guard, `tproxy_containment` counter вырос; origin wire/receiver токен не увидели, клиент получил timeout |
| С guard: невыбранный → локальный UDP/53, внешний UDP/53 и внешний UDP/19090 | точные echo-токены дошли до receiver и обратно; выборка по `lan1` не попала в guard `lan0` |
| Explicit off: удалить preauth, guard, observer | выбранный UDP/53 и невыбранный UDP/19090 снова прошли обычный firewall |

Гостевой процесс завершился **exit 0**, десять именованных этапов вывели `PASS`; packet/receiver и счётчики проверялись внутри probe, не выводились как сводные значения. После опыта `ip netns list` и `nft list tables` пусты, `ip rule` — только стандартные local/main/default; VM откатана к `pre-singbox-20261002`, выключена. Host-free backend suite проверяется отдельно от сетевого опыта.

## Граница вывода

Установленный заранее FORWARD guard сохранил доступ к тестовому локальному UDP-сервису и блокировал установленный **forwarded** поток выбранного интерфейса, пока невыбранный прошёл. Это не доказывает защиту OUTPUT Unbound или sing-box, различение устройств на одном интерфейсе, автоматическое обнаружение отказа, порядок apply/boot, защиту установленного TCP через LOCAL_IN, обработку реальных DNS-имен и приоритет локальных записей/явных forwards. Общий Unbound всё ещё теряет признак исходного клиента (`docs/tproxy-dns-source-boundary.md`). Gate `tproxy.not_available` не открывать.
