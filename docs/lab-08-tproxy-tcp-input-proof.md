# TCP TProxy: утечка установленного потока и независимый INPUT proof guard

## Среда и артефакты

Авторизованная одноразовая VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`; три отдельные namespace `vsr-tcp-router`, `vsr-tcp-client`, `vsr-tcp-origin`. Физические NIC и сетевые правила основного пространства VM не менялись. Keenetic не использовался.

- `backend/tests/lab/tproxy_tcp_probe.py`: standalone stdlib TCP-проба, не часть pytest/apply. Запуск root только на разрешённой одноразовой VM. Нужен ранее проверенный sing-box 1.14.2 amd64 по `/var/cache/vsr-singbox-probe`.
- `backend/tests/lab/generate_tproxy_preauth_cases.py`: из `backend/` выполнить `env -u PYTHONPATH .venv/bin/python tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp` для baseline; `--tcp-proof` для отдельного INPUT proof experiment. На VM: `python3 tproxy_tcp_probe.py OUTPUT.json`.
- `backend/tests/test_tproxy_lab_cases.py`: host-free fixture checks; не запускают сетевые пробы. Дополнительные tests сначала упали из-за отсутствующего opt-in `input_proof`; после реализации прошли. TCP proof режим не меняет сгенерированный ordinary firewall/preauth/containment/sing-box JSON и не разрешён для UDP.

Текст ordinary firewall, offline preauth/containment и JSON sing-box берутся из настоящих генераторов. Interception, INPUT allowance, proof reset и proof guard — **лабораторные** правила в probe, не продуктовые генераторы. Публичный gate `tproxy.not_available` не менялся.

## Baseline: реальный отрицательный результат

TCP-проба проверяет fresh SYN default deny/deny-before-pass и positive pass-before-block. Перед каждым fault устанавливает отдельный здоровый TCP поток и отправляет контрольный token **по тому же открытомy socket**, подтверждая `ct state established` для точного tuple до preauth. После fault генерируется новый token. Одновременно работают TCP AF_PACKET capture/reassembly на client, ingress и origin и stream echo receiver. Успешный `send()` не принимается за доказательство отправки: требуется payload на ingress; исключение для SIGKILL допускает явно наблюдаемый socket reset.

Baseline с FORWARD-only containment **повторно завершился exit 1**:

| Fault установленного потока | Новое содержимое у origin | INPUT/OUTPUT/FORWARD evidence |
| --- | --- | --- |
| deny перед allow | нет | preauth блокирует established |
| default deny | нет | preauth блокирует established |
| SIGKILL sing-box | нет | клиент получил EOF в наблюдаемой пробе |
| удалён только interception | **есть, echo получен** | unmarked INPUT +2, OUTPUT +2, FORWARD guard 0 |
| удалён только local route | нет | нет proxy OUTPUT |
| удалён только fwmark policy rule | нет | нет proxy OUTPUT |

При удалении interception origin получил post-fault token от `10.212.2.1`, то есть продолжение proxy-сессии, не обычный client forwarding. Пакеты дошли до LOCAL_IN с mark 0 и прошли обычный `established,related` INPUT accept; mark-specific лабораторный INPUT allowance не сработал. FORWARD guard не увидел этот путь. Ошибка: `TCP containment violations: ['interception_deleted', 'interception_deleted:guard_not_reached']`.

Ревью субагента указало вероятный TCP early-demux/socket route cache механизм. Наблюдение **доказывает путь unmarked INPUT → продолжающийся proxy OUTPUT**, но без kernel tracing не доказывает конкретный `sk_rx_dst`/early-demux переход. Лабораторный post-failure candidate, требующий routing mark в INPUT, остановил последующий token (drop +6), но routing mark сам по себе не является доказательством нового успешного перехвата.

## Отдельный эксперимент: свежий proof после TProxy

Opt-in `--tcp-proof` добавляет два независимых от interception компонента:

1. PREROUTING -85 после preauth -90, до interception -80: очищает proof bit `0x200` у каждого IPv4 TCP packet выбранного lab tuple (lan0, client IP, nonlocal destination, dport 19090), включая established/retransmissions. Ни conntrack, ни socket mark не восстанавливают proof.
2. Interception ставит routing mark `0x100`, выполняет `tproxy ip to 127.0.0.1:51272`, затем **в той же nft rule после успешного выражения TProxy** добавляет proof `0x200`. Packet mark становится `0x300`. Policy rule использует mask `0x100/0x100`, лабораторный ordinary INPUT allowance изменён на mark `0x300`.
3. Независимый INPUT hook -20 блокирует выбранный nonlocal lab traffic без `0x200` до ordinary established accept. FORWARD guard остаётся для другого пути. Reset/INPUT guard не удаляются при исчезновении interception.

Все nft тексты прошли `nft -c` и live-применение внутри namespace; настоящий sing-box JSON прошёл `sing-box check`. Полная proof-mode TCP-проба завершилась **exit 0**. Positive allow/pass-before-block/recovery controls проходят; fresh deny/default deny SYN не доходят до origin. Established deny/default deny, SIGKILL, loss of interception/local route/policy rule не доставили новые токены origin. При потере interception INPUT proof guard drop увеличился на **6**, proxy OUTPUT delta 0, FORWARD guard delta 0 — блокировка произошла на нужном LOCAL_IN-пути. Explicit off снимает proof/interception/preauth/containment и policy route/rule; fresh ordinary allow проходит от исходного client tuple, fresh ordinary default deny блокирует handshake.

Это bounded TCP experiment: sender timeout 1.5 секунды, дополнительное отрицательное окно 1.5 секунды и settle 0.3 секунды. TCP-счётчики включают ACK/retransmissions, не число независимых payload. Проба прекращает старый client socket с abortive close и останавливает proxy **до восстановления** правил; recovery использует новый поток. Поэтому восстановление старого TCP socket и queued-byte release после повторного allow здесь не доказаны. Sequence-aware capture reassembly и приложение сопоставляются с уникальными tokens; это не доказательство отсутствия любых байтов/потоков при произвольном loss/reordering.

## Проверки и оставшиеся блокеры

- Backend suite: **303 passed**. Baseline red сохранён; proof режим отдельный, не замена ожидаемого baseline результата.
- Cleanup подтвердил отсутствие TCP namespace и test proof/containment tables в основном пространстве VM. VM возвращена к `pre-singbox-20261002`, выключена.
- Routing/proof bits не зарезервированы продуктом: whole-mark routing assignment и lab tuple scope не переносить в общий генератор без ownership/compatibility design. Preauth выполняется до reset и чувствителен к входящим marks. Другой writer после reset может подделать proof; проверка этого класса конфликтов ещё нужна.
- Proof означает успешное назначение transparent socket, **не** здоровье приложения, готовность outbound или авторизацию proxy OUTPUT. Уже принятые kernel/proxy-buffered bytes INPUT guard не отзывает.
- Не доказаны independent OUTPUT containment, DNS/Unbound, local/DNAT вместе с guard, IPv6, arbitrary policy routing/ECMP, offload/bridge, удаление самого proof reset/guard, atomic apply/rollback/boot, failover и окончательная explicit-off session lifecycle. Продуктовое включение остаётся запрещено.
