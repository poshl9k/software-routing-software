# Lab 48 — подписка → реальные proxy-выходы

Итог: **PASS** для цепочки «подписка → предложение → сохранённый конфиг → sing-box → реальное соединение через VLESS». VM `vsr-fresh-695476d` оставлена работающей, версия **6 confirmed**. Из трёх импортированных выходов соединение подтвердил один; два других не прошли delay-тест (см. ниже). Секреты, URL подписки и ответы API с шифрованными полями здесь не публикуются.

## Условия и точные команды прогона

Использовалась только одноразовая VM `qemu:///system`; host network не менялась, git push не выполнялся. Перед изменениями:

```sh
virsh -c qemu:///system list --all
virsh -c qemu:///system snapshot-list vsr-fresh-695476d
virsh -c qemu:///system snapshot-current vsr-fresh-695476d --name
virsh -c qemu:///system domiflist vsr-fresh-695476d
virsh -c qemu:///system qemu-agent-command vsr-fresh-695476d '{"execute":"guest-ping"}'
virsh -c qemu:///system snapshot-create-as vsr-fresh-695476d pre-lab48 --disk-only --atomic
```

Результат: VM работала, guest-ping вернул `{ "return": {} }`; новый `pre-lab48` появился как `disk-snapshot`. Адрес управления проверен в guest `/var/lib/vs-router-bootstrap/management.json`: `enp2s0`, `192.168.10.1/24`. Сервисы web/agent/Caddy/sing-box были `active`.

Штатные HTTP-вызовы делал одноразовый локальный драйвер с учётными данными из `~/VMs/vsr-fresh-admin.json`, TLS-проверкой через `~/VMs/vsr-fresh-ca.crt` и URL подписки, переданным только в запросе (скрипт лежит вне repo, в `~/.hermes/cache/scratch/lab48_run.py`, права 0600):

```sh
chmod 600 /home/poshl9k/.hermes/cache/scratch/lab48_run.py
python3 /home/poshl9k/.hermes/cache/scratch/lab48_run.py
```

Последовательность внутри драйвера — именно HTTP API под `admin`: `POST /api/auth/login`; `GET /api/versions` (существующий draft 6); `PUT /api/draft` с подпиской `his`, `format=auto`, `mode=urltest`, `interval_hours=6`, `enabled=true`; `POST /api/proxy/subscriptions/preview` (`authorized=true`); `PUT /api/draft` с `proxies.enabled=true` и предложенными `outbounds`/`groups`; `PUT /api/draft` с TProxy `ingress_interfaces=["enp2s0"]`, `sniff=true`, `final=direct` и одним правилом `lab48_his_example` (`domain_suffix=["example.com"]`, `action=route`, `outbound=his`); `POST /api/draft/validate` → `valid=true`; `POST /api/apply` с `{"version_id":6,"safe_mode":false}` → `confirmed`. Содержимое тел запросов/ответов с секретами не выводилось. Черновик изначально имел **пустые interfaces и DNS**; для guard были восстановлены интерфейсы из подтверждённой версии 5 (`enp2s0` LAN `192.168.10.1/24`, `enp1s0` WAN DHCP), а DNS listeners — из той же версии, через `PUT /api/draft`, без редактирования SQLite. `GET /api/versions` и `GET /api/apply/status` после прогона: версия 6 `confirmed`, marker 6 `confirmed`.

На VM `/etc/resolv.conf` не содержал `nameserver`, поэтому первоначальный preview отвечал HTTP 409 `download.resolve_failed`. Для восстановления работоспособности DNS **только внутри гостя** сохранили `/etc/resolv.conf.pre-lab48` и записали `nameserver 10.10.10.1`; `getent ahostsv4 rg1.poshl9k.ru` после этого вернул успех. Это лабораторная правка окружения, не изменение host network; при следующей перезаписи DHCP её нужно проверить повторно.

Первый apply при неполном DNS draft вернул `failed`, marker `agent.apply_failed` с пустыми phases; офлайн-генерация с ключом из `/etc/vs-router/secrets.env` определила `tproxy.dns_split_missing_listener`. После восстановления DNS следующий apply остановился на `singbox=failed`, marker `agent.validation_failed`: зафиксированный бинарник sing-box 1.14.2 требовал отсутствовавшую `libcronet.so` для Naive. Библиотека извлечена из **того же** официального архива, что и бинарник, после проверки SHA256 архива `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` по ADR-0012. Копия установлена только в guest `/usr/local/lib/vs-router/libcronet.so`; её SHA256 `23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294` совпал на host и guest. `sing-box check -c /run/lab48-singbox-check.json` → rc=0; третий apply через API → confirmed, все 16 фаз `applied`. Временный HTTP-сервер для передачи библиотеки остановлен. Библиотека — разовая исправляющая установка на VM, **не** изменение пакета/инсталлятора продукта.

## Предложение импорта

Preview вернул 3 members, 3 outbounds, 1 группу `his` типа `urltest` с тремя участниками. Таблица отражает только безопасные теги/типы, без адресов узлов, логинов и секретов.

| Строка | Результат | Тег / причина |
| --- | --- | --- |
| 1 | SKIP | `non_server` |
| 2 | SKIP | `non_server` |
| 3 | SKIP | `non_server` |
| 4 | SKIP | `non_server` |
| 5 | MEMBER, VLESS/http | `sub_38e84fab538c0905a0f94243` |
| 6 | SKIP | `subscription.unsupported_xhttp` |
| 7 | MEMBER, Hysteria2 | `sub_a8cdb647b68d129a9c85a0b2` |
| 8 | SKIP | `subscription.unsupported_xhttp` |
| 9 | MEMBER, Naive | `sub_ac2e9ba13365fe5b7856c12c` |
| 12 | SKIP | `subscription.invalid_port` |
| 13 | SKIP | `subscription.invalid_port` |

Строки 10–11 в preview не представлены ни как member, ни как skipped: это наблюдение API, их тип/судьба не утверждаются. `xhttp` и mieru могут быть пропущены; для mieru фактический код — `subscription.invalid_port`, не доказанная несовместимость протокола. VLESS/http, Hysteria2 и Naive материализовались. Preview не вернул отдельного VLESS/httpupgrade; нельзя утверждать, что он был импортирован.

## Проверки живого применения

Команды проверок, без вывода конфигурации или пользовательских URL:

```sh
python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py vsr-fresh-695476d 'systemctl is-active vs-router-singbox.service; python3 /run/lab48_verify.py'
# lab48_verify.py: stat + json.load применённого singbox.json (только булевы утверждения);
# GET http://127.0.0.1:9099/proxies;
# GET http://127.0.0.1:9099/proxies/<tag>/delay?url=http://www.gstatic.com/generate_204&timeout=5000
# HTTPS API: GET /api/runtime/engine, GET /api/runtime/connections, GET /
git status --short
git diff --check
```

| Проверка | Реальный ответ | Итог |
| --- | --- | --- |
| `/api/draft/validate` и apply | `valid=true`; версия 6 `confirmed`, все фазы `applied` | PASS |
| `vs-router-singbox.service` | `active` | PASS |
| `/etc/vs-router/applied/singbox.json` | `owner_root=true`, `mode_0600=true`, `outbound_count=5`; `credentials_real=true` (как минимум одно поле `uuid`/`password` отличается от заглушки) | PASS |
| Clash `/proxies` | HTTP 200; `his` содержит все 3 перечисленных участника | PASS |
| VLESS/http delay | HTTP 200, `delay=150 ms` на повторной пробе (`146 ms` на первой) | PASS — подтверждено реальное подключение с учётными данными подписки |
| Hysteria2 delay | HTTP 504, точный Clash JSON `{"message":"Timeout"}` | PARTIAL |
| Naive delay | HTTP 503, точный Clash JSON `{"message":"An error occurred in the delay test"}` | PARTIAL |
| `/api/runtime/engine` | `running=true`, `clash_api=true`, `nft_tproxy_tables=true` | PASS |
| `/api/runtime/connections` | HTTP 200 | PASS |
| Панель с установленным CA | HTTPS 200 после применения | PASS |
| Сохранённое состояние | `GET /api/versions`: версия 6 `confirmed`; `GET /api/apply/status`: 6 `confirmed`; VM работает | PASS |

Ограничение: delay-тест доказывает исходящее подключение выбранного VLESS-узла к HTTP target через sing-box, но не отдельный транзит пакета с LAN-клиента через правило `example.com`. Для двух других выходов успешное соединение не доказано.

`git status --short` до записи отчёта был пуст; после неё должен показывать только этот новый документ. URL-токен и учётные данные в repo не записывались. **Не пушить**; оставить VM с применённой подпиской. После перезапуска `vs-router-web` действующие сессии сбрасываются, потребуется повторный вход (в этом прогоне web не перезапускался).
