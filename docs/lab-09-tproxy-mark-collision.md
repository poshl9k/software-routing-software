# TCP TProxy: подделка proof-бита другим локальным правилом

## Граница эксперимента

Авторизованная одноразовая Debian VM `vsr-verify-20261002`, snapshot `pre-singbox-20261002`. Проба работает только в трёх временных network namespace; сетевые правила хоста и корневого namespace VM не менялись. Исходные ordinary firewall, preauth, FORWARD containment и sing-box JSON взяты из генераторов проекта; proof reset, INPUT guard, interception и инъекция метки — только лабораторные правила. Публичное включение TProxy остаётся запрещено.

`backend/tests/lab/generate_tproxy_preauth_cases.py OUTPUT.json --tcp --tcp-mark-collision` создаёт opt-in fixture; `backend/tests/lab/tproxy_tcp_probe.py OUTPUT.json` проводит прежнюю TCP proof-матрицу и две дополнительные пробы. Испытывался официальный sing-box 1.14.2 amd64; SHA256 архива повторно проверен перед использованием: `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`. `sing-box check` проверил конфигурацию, пакетную часть проверила сама проба. Архив не является выбранным продуктовым релизом.

Порядок: preauth `-90` → proof reset `-85` → TProxy/proof setter `-80` → INPUT proof guard `-20`. Для каждого случая открыто отдельное исправное TCP-соединение; контрольный токен прошёл через proxy, а `ct state established` посчитан для его точного tuple. Затем удалена только таблица interception, намерение включения и защитные таблицы сохранены. Узкое лабораторное правило для того же source port добавляет **только** `0x200` (proof), не `0x100` (routing), без TProxy и без нового INPUT accept. До восстановления правил клиентский socket закрывается abortive close, proxy останавливается; следующий опыт начинает новый поток. Отдельно проверено восстановление и явное выключение.

## Результат на пакетах

| Инъекция proof | Вход/INPUT proof drop | Proxy OUTPUT | Origin и echo |
| --- | --- | --- | --- |
| Нет, исходная матрица после удаления interception | sender ingress наблюдался; drop +6 | 0 | нет |
| Перед reset, PREROUTING `-86` | injector +6; drop +6; established +6 | 0 | новый токен не получен, sender timeout |
| После reset, PREROUTING `-84` | injector +2; drop 0; established +2 | +2 | **новый токен получен** origin и возвращён sender |

В последней пробе клиентский ingress capture увидел уникальный post-fault токен, origin AF_PACKET увидел его от proxy source `10.212.2.1`, echo receiver зарегистрировал тот же payload; ответ совпал. FORWARD containment остался с delta 0: пакет пошёл через LOCAL_IN и действующее proxy-соединение, хотя таблица перехвата была удалена. Инъекция до reset была нейтрализована; после reset обошла INPUT guard. Проба завершилась exit 0, потому что исследовательский режим фиксирует исход, а не предполагает отсутствие утечки. Этот exit 0 **не означает** прохождение fail-closed gate.

Host-free backend suite: **309 passed** (с venv в PATH и без `PYTHONPATH`); opt-in fixture tests включены. После пробы в VM `ip netns list` и `nft list tables` пусты, `ip rule` содержит только стандартные правила. VM возвращена к `pre-singbox-20261002` и выключена.

## Вывод

Proof bit в `meta mark` не является неподделываемым свидетельством успешного TProxy: привилегированное локальное правило, выполняющееся после reset, может выставить его и пропустить established TCP через INPUT. Это модель конфликта с другим владельцем nftables/mark, **не** возможность обычного LAN-клиента выставить mark. До продуктовой интеграции нужны резервирование и контроль единственного владельца отметок и порядка hooks либо иная независимая авторизация INPUT; отдельно защищать proxy OUTPUT. Также не доказаны защита уже буферизованных данных, произвольные маршруты/ECMP, DNS, IPv6 и atomic apply/rollback/boot. `tproxy.not_available` сохраняется.
