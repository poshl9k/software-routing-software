# vs-router backend

Python 3.11+, FastAPI, SQLAlchemy 2, Alembic, SQLite. Семантика следует
`../CONTEXT.md`, плану v0.3 и ADR-0001 (Debian 13, AmneziaWG userspace).

```sh
cd backend
uv sync
uv run pytest -q
uv run alembic upgrade head
uv run uvicorn vs_router.app:app --host 127.0.0.1
```

При отсутствии uv: `python3 -m venv .venv`, затем
`.venv/bin/pip install -e '.[test]'` и `.venv/bin/python -m pytest -q`.
Кэш uv расположен в `.uv-cache/` для работы в окружении с read-only home.
`uv.lock` фиксирует зависимости. Системные пакеты не нужны для unit-тестов.

## Хранение и контракт

`schema.py` — типизированный контракт всех объектов конфигурации. SQLAlchemy
хранит атомарный JSON-документ в `configuration_versions`, без параллельных
таблиц объектов и второго источника истины. Миграция создаёт CHECK статуса и
частичный UNIQUE-индекс: несколько confirmed-версий, не более одного draft.
`ConfigurationJSON` валидирует JSON при записи и чтении. Снимок заменяется
целиком; изменения вложенных объектов на месте не предназначены для сохранения.
`save_version` создаёт версию и проверяет неизменность роли существующего туннеля.
Транзакцией и commit управляет вызывающий код. `row.snapshot()` даёт вход генераторам.

Интерфейсы: `physical`, `bridge`, `vlan`; `zone: null` означает fail-closed.
`router` — встроенное назначение трафика, не назначаемая зона интерфейса.
Адреса интерфейса упорядочены (основной первым). Туннели ссылаются на отдельный
интерфейс; роль `server` имеет peers, роль `client` — endpoint удалённого сервера.
AWG требует Jc, S1, S2, H1–H4. Caddy хранит четыре режима сертификата.

Секреты принимаются только как объект `EncryptedSecret` с `encrypted: true` и
Fernet ciphertext. `encrypt_secret`/`decrypt_secret` используют переданный извне
ключ; ключ не хранится в БД. Поля plaintext для ключей/токенов отсутствуют,
неизвестные JSON-поля отвергаются. HTTP API скрывает даже ciphertext: вместо
секретного объекта возвращается `{"redacted": true}`. PUT сохраняет секрет по
этому маркеру только у прежнего именованного объекта; новые секреты передаются
как EncryptedSecret. `GET /health` доступен без входа.

## Генераторы

```python
from vs_router.schema import ConfigurationVersion
from vs_router.generators import generate_nftables, generate_unbound, generate_kea

version = ConfigurationVersion(configuration={})
text = generate_nftables(version)
```

Все три функции получают версию, возвращают текст и не выполняют I/O.

* Firewall: адрес или CIDR/диапазон, `any`, `@alias`, `zone:lan`/`zone:router`.
  Порты: `80`, `8000-8080`, `@ports`; элементы port-алиаса — `tcp/80`, `udp/53`.
  Псевдонимы вкладываются через `includes`. Адресные aliases создают IPv4/IPv6 sets.
  Правила сортируются по `(order, name)`; порядок задаётся внутри зоны входа.
  First match применяется к новым соединениям; established/related разрешаются
  после проверки назначенных интерфейсов. Anti-lockout LAN включён по умолчанию.
  Неявный default deny действует в input и forward. Счётчики nft начинаются с нуля;
  поле `counters` хранит наблюдения states/packets/bytes, не восстанавливает conntrack.
* Port forward: IPv4 DNAT в prerouting, до выбора локального сервиса; связанное
  filter-правило учитывает исходный WAN-адрес/порт и переведённую цель.
  При отсутствии WAN-адреса правило ограничено локальными адресами (`fib`).
  Авто-правила port forward предшествуют пользовательским filter-правилам.
* Outbound NAT: automatic/hybrid/manual/disabled; hybrid по умолчанию.
  Ручные правила идут первыми, `do_not_nat` завершает обработку NAT.
  `translation: primary` даёт masquerade (адрес выбирает ядро), конкретный IP — SNAT.
  Автоправила покрывают IPv4-подсети назначенных внутренних интерфейсов, выходящих
  через WAN. NAT не создаёт маршруты. IPv6 filter поддержан, NAT — только IPv4.
* Unbound слушает только адреса выбранных интерфейсов, доступ задают явные CIDR.
  Пустой конфиг слушает loopback и отказывает клиентам. Без upstream нет неявной
  рекурсии: неизвестные домены отвергаются, заданные per-domain forwards работают.
  Полная рекурсия включается только `recursive: true`.
* Kea: subnet4, pools, options и reservations; `reservations-in-subnet: true`,
  `reservations-out-of-pool: false` сохраняют проверки для обоих видов резерваций.

Валидаторы проверяют ссылки, типы и циклы aliases, диапазоны адресов/портов,
пересечения DHCP-пулов/подсетей, адрес интерфейса, network/broadcast и дубликаты
IP/MAC резерваций в подсети. Ошибки имеют машинные коды для будущего UI.

## Проверка и границы

В `tests/golden/` — по три эталона каждого генератора: empty, typical LAN/WAN,
edge (вложенные aliases, диапазон портов, дополнительный WAN-адрес,
резервация вне пула, per-domain DNS). Тесты также проверяют отсутствие мутации,
детерминизм, отрицательные сценарии, миграции и шифрование.

Нативная проверка на целевой машине: `nft -c -f FILE`,
`unbound-checkconf FILE`, `kea-dhcp4 -t FILE`. В текущей песочнице nft не может
открыть Netlink, Unbound/Kea отсутствуют; unit/golden-тесты не заменяют их проверку.
Генератор nft выдаёт содержимое принадлежащей роутеру таблицы; замена существующей
таблицы и управление состоянием — обязанность будущего механизма применения.
RPC-клиент и HTTP-заглушки существуют; демон агента, применение конфигов и
управление ОС пока не реализованы.

Синтаксис сверялся с первичными источниками:
[nftables](https://netfilter.org/projects/nftables/manpage.html),
[Unbound](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html),
[Kea](https://kea.readthedocs.io/en/kea-2.6.2/arm/dhcp4-srv.html).


## HTTP API

Перед запуском выполнить `uv run alembic upgrade head`. По умолчанию приложение
использует `sqlite:///vs-router.db`; URL можно задать через `VS_ROUTER_DATABASE_URL`
(для Alembic тот же URL задаётся в `alembic.ini`). `create_app(engine=...)` принимает
движок для тестов. Миграция 0002 добавляет users, роль и резервное поле TOTP.

* `POST /api/setup`: `{ "username": "admin", "password": "..." }`, пароль от
  8 символов; создаёт admin только при пустой users, повторный запрос — 409.
* `POST /api/auth/login`: те же поля; argon2id, Secure/HttpOnly/SameSite=Strict
  cookie на 8 часов. Нужен HTTPS. `POST /api/auth/logout` удаляет сессию,
  `GET /api/auth/me` возвращает id/username/role. После пяти неудач с одного IP
  вход заблокирован до конца 15-минутного окна. Заголовок X-Forwarded-For не
  используется. Сессии и счётчики локальны одному процессу и очищаются при рестарте.
* `GET /api/versions`, `GET /api/versions/{id}` возвращают снимки, включая
  конфигурацию с маркерами секретов. Operator имеет только доступ на чтение.
* `POST /api/draft`: тело Configuration или без тела — копия последней версии
  (при пустой БД — defaults). Существующий draft даёт 409. `PUT /api/draft`
  заменяет Configuration целиком; `DELETE /api/draft` удаляет черновик.
* `POST /api/draft/validate`: без тела проверяет сохранённый draft; с телом
  Configuration проверяет предложенную замену без записи. Ответ:
  `{ "valid": true, "errors": [], "warnings": [] }`. Вызываются доменные
  валидаторы и три чистых генератора; системные команды не запускаются.
* `GET /api/diff/{id1}/{id2}`: список add/remove/replace с JSON Pointer `path`
  и значениями `before`/`after`. Изменение секрета видно, его содержимое скрыто.
* `POST /api/apply`: `{ "version_id": 1, "safe_mode": false,
  "confirmation_timeout": 180 }` (таймер 60–600 секунд).
  `POST /api/confirm`: `{ "version_id": 1 }`; `POST /api/rollback`: `{}`.
  Валидные запросы возвращают 501, состояние БД не меняется.

Ошибки: `{ "code": "...", "message": "...", "details": [] }`; message пока
содержит машинный код для будущей локализации. В ошибках валидации нет исходных
значений. Изменения требуют admin; чужой Origin и Sec-Fetch-Site: cross-site
отвергаются. Запросы без Origin допускаются для небраузерных клиентов.

`agent/rpc.py` задаёт JSON-RPC 2.0 whitelist, типы параметров и ответов,
`build_request`, `parse_response`, `AgentClient.call`. Внедряемый синхронный
транспорт передаёт полное JSON-сообщение через send(bytes)/recv(); фрейминг,
таймауты, unix socket и peer-credentials будут реализованы на стороне транспорта.
