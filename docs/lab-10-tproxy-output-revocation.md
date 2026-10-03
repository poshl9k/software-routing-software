# TCP TProxy: отдельный OUTPUT-барьер для установленного потока

## Среда и объём

Разрешённая одноразовая Debian VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`. Весь пакетный эксперимент — внутри трёх временных network namespace; nftables и маршруты корневого namespace VM и хоста не менялись. `backend/tests/lab/tproxy_tcp_output_probe.py` использует настоящий сгенерированный ordinary firewall, offline preauth/containment, sing-box JSON и лабораторные INPUT proof/interception из предыдущей TCP-пробы. Новый guard существует **только в лабораторной** `inet vsr_tcp_output_guard`, `OUTPUT` priority `-20`, до обычного firewall. Он ревокирует весь TCP `oifname "wan0"` к `198.18.0.2:19090`, включая established; остальной OUTPUT не меняет. Это ограничение **по адресу назначения**, а не по процессу sing-box или исходному клиенту.

Фикстура: `backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp-proof`; гостевой запуск root: `python3 tproxy_tcp_output_probe.py OUTPUT.json`. Требуются соседний `tproxy_tcp_probe.py` и ранее проверенный sing-box 1.14.2 amd64 по `/var/cache/vsr-singbox-probe`. Проверены SHA256 официального release-архива `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`, `version` и `sing-box check` сгенерированного JSON. Это не утверждение о пригодности бинарника для выпуска.

## Пакетный результат

Сначала здоровый TCP поток прошёл через TProxy: origin увидел payload от `10.212.2.1`; отдельный счётчик подтвердил `ct state established` для точного клиентского tuple. Затем добавлено правило OUTPUT `counter drop` без удаления interception, proxy или policy route. На **том же** клиентском socket послан новый уникальный токен; захват на ingress подтвердил его фактический приход (не только успешный `send()`). Лабораторный INPUT observer после proof guard посчитал пакет, OUTPUT-drop сработал, origin capture и echo receiver не увидели токен в ограниченном окне. Клиентский socket и принимающая сессия закрыты, proxy остановлен **до** восстановления OUTPUT-доступа. Новый поток после восстановления прошёл. Явное выключение вернуло обычный forwarding; fresh default-deny остался закрыт.

| Случай | Наблюдение |
| --- | --- |
| Healthy established | origin peer `10.212.2.1`, контрольный echo; `ct state established` положителен |
| Revoked OUTPUT на том же TCP socket | ingress payload есть; INPUT observer +1; OUTPUT drop +5; origin wire/receiver: 0 записей с токеном; sender timeout |
| Несвязанный OUTPUT роутера | TCP echo на том же origin, но порт 19091, прошёл при действующем guard |
| Recovery / explicit off | новый proxy-поток прошёл; после off origin peer — исходный клиент `10.212.1.2`; fresh default deny блокирует handshake |

Проба завершилась exit 0. Проверка cleanup: в VM `ip netns list` и `nft list tables` пусты, `ip rule` оставил только стандартные правила. VM откатана к `pre-singbox-20261002` и выключена. Host-free backend suite — **312 passed**; три новых теста проверяют opt-in, узость лабораторного правила и порядок revocation/cleanup. Нативная проверка правил и реальная передача пакетов выполнены в VM, а не в pytest.

## Ограничения

Этот guard блокирует **все** локальные процессы к тестовому tuple, не идентифицирует владельца proxy-сокета. Контроль на другом порту показывает лишь неповреждённый соседний путь, а не корректное разделение трафика по пользователю или политике. Проба не проверяет попытку другого локального процесса попасть **в тот же** tuple, уже буферизованные байты, пропуск трафика при подмене route/egress, DNS, UDP, IPv6 и жизненный цикл apply/rollback/reboot. OUTPUT-авторизация sing-box и связь исходного клиента с его outbound по-прежнему не реализованы. INPUT proof остаётся уязвимым к конфликту меток после reset (`docs/lab-09-tproxy-mark-collision.md`). `tproxy.not_available` остаётся обязательным.
