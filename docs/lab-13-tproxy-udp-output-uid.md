# UDP TProxy: UID-scoped OUTPUT для постоянного клиентского socket

## Среда и подход

Одноразовая разрешённая Debian VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`. Новый самостоятельный `backend/tests/lab/tproxy_udp_uid_probe.py` запускался только внутри трёх временных network namespace; в корневом namespace VM и на хосте правила/маршруты не менялись. Сгенерированные ordinary firewall, preauth, FORWARD containment и sing-box JSON взяты из проекта; interception, INPUT observer/accept и OUTPUT UID guard — лабораторные. Готового продуктового тракта нет, `tproxy.not_available` не менялся.

Вход: `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --combined`; гостевой запуск root: `python3 tproxy_udp_uid_probe.py OUTPUT.json` рядом с `tproxy_tcp_probe.py` (общие безопасные helpers). Использовался официальный sing-box 1.14.2 amd64 из архива SHA256 `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`; проверены checksum, `version` и `sing-box check` generated JSON. Это не выбор продуктового релиза. Sing-box работал под test UID `29090` с `CAP_NET_RAW`; probe проверил реальный UID, `CapEff`/`CapAmb` и владение UDP-listener PID. Конфигурация строго direct-only, без секретов и доменных lookup.

Один клиентский UDP socket `10.212.1.2:25000` удерживался через healthy, подтверждённый `ct state established` контроль и отказ. На router OUTPUT hook `-20` лабораторные счётчики различали socket UID `29090` и UID `29091` при **одинаковом адресе назначения и порту** `198.18.0.2:19090` через `wan0`. Правило `counter drop` для UID sing-box ставилось перед счётчиками и обычным OUTPUT. Каждый запрос имел уникальный payload; проверялись ingress/receiver AF_PACKET, UDP echo и отсутствие поздней доставки запрещённого токена после recovery/off. Лабораторный INPUT accept по метке `0x100` не доказательство защищённого происхождения метки.

## Результат

| Запрос | Наблюдение |
| --- | --- |
| Первый healthy на постоянном socket | ingress 1, origin wire 2, echo 1; proxy UID OUTPUT +1, INPUT observer +1; established 0 для первого пакета |
| Второй healthy на том же tuple | echo 1, proxy UID +1; exact `ct state established` +1 |
| Отозван OUTPUT UID `29090`, тот же socket | новый token на ingress 1; established +1 и INPUT observer +1; proxy UID drop +1; **origin wire 0, receiver 0**, клиент получил timeout |
| Другой UID `29091` к **тому же destination** при активном запрете | его OUTPUT observer +1, echo 1, proxy UID drop delta 0 |
| Восстановление / off | новый proxy-запрос прошёл, заблокированный token не появился позже; explicit off вернул обычный forwarding с IP клиента; fresh default-deny дал ingress 1, origin 0 |

Проба завершилась exit 0 после двух исправлений самой лабораторной пробы: таблицы nft требуют разделительных переносов при склейке текста, а INPUT observer для recovery не должен ограничиваться портом только первого socket (exact established observer ограничен). Исходные неудачные запуски не были доказательствами packet-path отказа: первый остановился на `nft -c`, второй — на слишком узком тестовом счётчике при успешном echo. Финальный сетевой прогон завершился полностью. Отрицательное окно: timeout 0.7 секунды + 0.3 секунды наблюдения с последующими контрольными запросами.

Host-free backend suite: **321 passed**. Финальный cleanup в VM: `ip netns list` и `nft list tables` пусты, `ip rule` — только стандартные правила. VM возвращена к snapshot и выключена.

## Что остаётся

Эксперимент показывает bounded socket-UID разделение **для одного IPv4 UDP direct-выхода** при уже установленном правиле отзыва. Он не проверяет DNS/Unbound (UDP echo — не DNS), автоматическое обнаружение отказа, отзыв до первой утечки, IPv6, WG/AWG, отдельные proxy-протоколы, маршруты после смены WAN, принадлежность outbound исходному клиенту/правилу, adversarial root, а также apply/rollback/boot. TCP-коллизия INPUT proof (`docs/lab-09-tproxy-mark-collision.md`) не исправлена. Не включать TProxy в продукте.
