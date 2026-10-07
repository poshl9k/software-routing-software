# Расписания обновлений и обработка rule-set: планировщик, форматы, каталог пресетов

**Статус:** реализовано в агенте (оффлайн/тестово), **не** подключено к
конфигурационному gate и не активирует перехват. Публичный `tproxy.not_available`
остаётся закрытым. Модули не пишут в продуктовый bundle и не меняют пути
`apply`/`boot_restore`. Реального сетевого фетча в тестах нет — транспорт
мокирован.

Основание: `docs/sing-box-tproxy-plan.md` §«Источники списков и обновления»
(два взаимоисключающих режима расписания, ручное обновление, последняя
попытка/успех, отсутствие догоняющей серии, условные HTTP/backoff/джиттер,
DST; профиль источника строго определяет формат, лимит записей, статус stale;
каталог как данные/адаптер с провенансом и лицензией).

**Что уже было:** механизм фетча `agent/downloader.py` (SSRF, allowlist,
атомарная активация, история) и RPC `update_source`/`source_status` — см.
`docs/tproxy-sources-downloader.md`. Этот документ добавляет поверх него
**планировщик**, **обработку rule-set** и **каталог пресетов**, а также
типизированный метод интеграции планировщика с downloader'ом.

## Исполнение по таймеру (item 4)

`vs-router-source-update.timer` запускает `vs-router-source-update.service`
через 3 минуты после загрузки и далее примерно раз в час. Oneshoot-сервис
работает от `vs-router-web` и вызывает фиксированный Python-модуль
`vs_router.agent.source_update_job` без shell. Установка копирует оба unit-файла;
bootstrap включает таймер. Задание читает последний **подтверждённый** snapshot
из БД, его `rule_sets` и `tproxy.update_schedule`; при отсутствии источников
завершается без RPC. Историю попыток получает через `source_status`, вычисляет
`is_due` для каждого имени и отправляет только due-источники через типизированный
`update_source`. Для подтверждённых объявлений передаёт `authorized=True`;
URL вновь проверяется downloader'ом. Повторный запуск после записи попытки не
делает вторую загрузку до следующего слота. Окно использует `TZ` процесса
таймера (по умолчанию UTC); при настройке суточного окна задайте IANA `TZ` в
drop-in сервиса.

Перед чтением истории задание вызывает `status` и пропускает цикл при pending
apply. Каждый scheduled `update_source` дополнительно проверяет состояние apply
в агенте непосредственно перед загрузкой. RPC агент обрабатывает последовательно,
поэтому проверка и загрузка сериализованы с `apply_version`/rollback. При
появлении pending между вызовами задание прекращает текущий цикл.

Каталожный allowlist по умолчанию пуст. Для явного opt-in задайте в drop-in
`vs-router-agent.service` переменную
`Environment=VS_ROUTER_PRESET_SOURCE_KEYS=sing_geosite,rockblack_ip` и
перезапустите агент. Допустимы только ключи `CATALOG`; неизвестный ключ вызывает
ошибку запуска updater, без сетевого запроса. Opt-in лишь разрешает точные
каталожные URL/хосты; он не добавляет source в конфигурацию и не открывает
`tproxy.not_available`.

## Что реализовано

| Слой | Файл | Суть |
| --- | --- | --- |
| Планировщик | `backend/src/vs_router/agent/source_schedule.py` | чистые функции `next`/`base`/`is_due`/`describe` для режимов `interval`/`window`, TZ/DST, backoff/jitter, без догоняющей серии, инъектируемое «сейчас» |
| Rule-set | `backend/src/vs_router/agent/rulesets.py` | профиль источника (формат), строгая валидация набор↔формат, лимит размера/записей, версия/хеш, статус stale, распознавание `.srs` |
| Каталог | `backend/src/vs_router/agent/presets.py` | пресеты как данные (имя/формат/URL/лицензия/провенанс), адаптер в allowlist downloader'а, минимальный встроенный набор-пример |
| Интеграция | `agent/downloader.py:SourceUpdater.run_scheduled` | типизированный (data, не shell) метод: считает due по истории и, если пора, вызывает обычный `update` |
| Тесты | `backend/tests/test_source_schedule.py`, `test_rulesets.py`, `test_presets.py` | расчёт расписания/DST/backoff/no-catch-up, форматы и лимиты, каталог/allowlist |

## Схема расписания (`SourceSchedule`)

Два взаимоисключающих режима в одном объекте (задаётся `mode`):

* `interval` — «Периодически», по умолчанию **6 ч** (`interval_hours`, 1..168).
* `window` — «В суточном окне», один запуск за сутки внутри
  `[window_start, window_end)`, по умолчанию **00:00–05:00** по таймзоне сервера
  (`timezone`, IANA).

Общие поля политики: `jitter_seconds` (по умолчанию 300), `backoff_base_seconds`
(300), `backoff_max_seconds` (86400). Валидаторы: `window_start < window_end`
для режима окна (`schedule.invalid_window`), `backoff_base <= backoff_max`
(`schedule.invalid_backoff`), корректность IANA-таймзоны
(`schedule.invalid_timezone`). Модель можно собрать из контрактной
`schema.TProxyUpdateSchedule` через `SourceSchedule.from_contract(...,
timezone=...)`.

### Семантика следующего запуска

Чистые функции (`now` — epoch-секунды, передаётся явно; никакого скрытого
часа/IO):

* `base_next_run(schedule, now, state)` — детерминированное время следующей
  попытки (без джиттера). Значение `<= now` и означает «пора».
* `next_run(...)` — то же плюс джиттер `uniform(0, jitter_seconds)`
  (инъектируемый `rng`); это *проекция*/показ, джиттер **не влияет** на
  `is_due`.
* `is_due(schedule, now, state)` — по детерминированной базе.
* `describe(...)` — сериализуемый вид для UI/status: `due`, `next_run` (epoch),
  `next_run_local` (в TZ расписания, с корректным офсетом при DST), backoff и
  т. п.

Правила:

* **interval:** следующая попытка = `last_attempt + interval`. Если это уже
  прошло (хост спал/сервис был down) — источник **due сейчас** и срабатывает
  **ровно один раз**; догоняющей серии по пропущенным слотам нет. Точка
  отсчёта — **последняя попытка**, не последний успех (сбойный источник не
  «зависает»).
* **window:** если с открытия сегодняшнего окна попытки не было и текущий
  момент внутри окна — due сейчас; если окно уже закрыто (или запуск сегодня
  был) — следующая попытка завтра к началу окна. Полностью пропущенный день
  пропускается (снова без догоняющей серии).
* **backoff:** `base * 2**(n-1)`, ограниченный `backoff_max_seconds`, где `n` —
  `consecutive_failures`; добавляется к базовому времени.
* **DST:** арифметика окна — в IANA-таймзоне через `zoneinfo`, поэтому
  локальное «настенное» окно сохраняет смысл через переход, а возвращаемый
  epoch-инстант смещается.

**Честное ограничение:** граница окна, попадающая в DST-разрыв (несуществующее
локальное время), разрешается штатным fold-поведением `zoneinfo`, а не сдвигом
в конец разрыва; окно по умолчанию 00:00–05:00 в поддерживаемых регионах в
такой момент не попадает.

### Состояние (`RunState`)

`last_attempt`, `last_success`, `consecutive_failures` (epoch-секунды). Для
интеграции есть `state_from_history(history, name)`: берёт историю
downloader'а (записывается oldest-first), вытаскивает последнюю попытку,
последний `ok`-успех и хвостовой счётчик `failed`.

## Схема rule-set (`SourceProfile`, `validate_ruleset`)

Формат — **закрытое множество**, строго определяющее содержимое:

| Формат | Содержимое | Замечание |
| --- | --- | --- |
| `text-domain` | домены по строке (`domain:`/`full:`/`keyword:`/`regexp:`, комментарии `#`/`//`/`;`) | строка CIDR → `ruleset.format_mismatch` |
| `text-cidr` | IP/CIDR по строке | строка-домен → `ruleset.format_mismatch` |
| `json` | документ sing-box rule-set (`{"version":…,"rules":[…]}`) | не та форма → `ruleset.format_mismatch` |
| `geosite` | доменный список (грамматика `text-domain`) | принят, помечен `ruleset.requires_materialization` |
| `geoip` | адресный список (грамматика `text-cidr`) | то же |
| `srs` | бинарный sing-box rule-set (магия `SRS`) | **распознан, но `activatable=False`** |

`validate_ruleset(content, profile)` возвращает `RuleSetInfo` (`sha256`,
`size`, `records`, `activatable`, `warnings`) либо падает типизированной
`RuleSetError`:

* `ruleset.https_required` — URL профиля не https;
* `ruleset.format_mismatch` — содержимое не соответствует заявленному формату
  (в т. ч. CIDR в доменном наборе и домен в адресном — **не путаем**);
* `ruleset.invalid_record` — строка/правило не разобраны;
* `ruleset.empty` — нет ни одной записи;
* `ruleset.too_many_records` — `records > max_records` (по умолчанию 200 000);
* `ruleset.too_large` — `len(payload) > max_bytes` (по умолчанию 5 МБ);
* `ruleset.format_unknown` — защитный (закрытый Literal).

**`.srs`** распознаётся по магии и **честно помечается** «не активируется без
закреплённого инструмента»: возвращается `activatable=False` с предупреждением
`ruleset.srs_requires_pinned_tool` (плюс `ruleset.srs_magic_missing`, если магии
нет). Это не тихая активация и не молчаливый отказ.

**Stale/возраст:** `rulesets.staleness(now=…, last_success=…,
stale_after_seconds=…)` → `Staleness(stale, age_seconds)`; никогда не успешный
набор — `stale=True` с неизвестным возрастом. Аналогичный помощник есть и в
планировщике.

## Каталог пресетов (`presets`)

Каталог — **данные/адаптер**, не Keenetic-логика: `PresetSource(key, name,
format, url, hosts, kind, license, license_verified, provenance, notes)`.

* `catalog_sources()` — адаптер в `downloader.BuiltinSource` (URL + хосты +
  kind), то есть в **allowlist** downloader'а. Формат downloader'у отдаётся
  `auto`: строгий формат набора проверяется отдельно `rulesets`.
* `catalog_view()` — сериализуемый read-only вид для панели/API.
* Встроенный минимальный набор-пример (`CATALOG`): `v2fly_domains` (geosite),
  `sing_geosite` (json), `rockblack_ip` (text-cidr), `cjk_cdn_ip` (text-cidr).

### Лицензия и провенанс (честно)

`license_verified=True` означало бы «права на переупаковку **внутри продукта**
проверены независимо». Это **не сделано** ни для одного стороннего набора,
поэтому у всех записей `license_verified=False` и предупреждение:

* `preset.license_missing` — лицензии нет вовсе (`123jjck/cdn-ip-ranges`: файл
  лицензии в репозитории не найден);
* `preset.license_unverified` — лицензия заявлена upstream, но не подтверждена
  для переупаковки.

Это данные для ревьюера, а не гарантия. Подключение каталога в
`downloader.BUILTIN_SOURCES` — осознанный opt-in (по умолчанию он пуст), чтобы
импорт модуля не менял поведение фетча.

## Интеграция с downloader (`SourceUpdater.run_scheduled`)

Типизированный метод (только данные, без shell и произвольных аргументов):

```
run_scheduled(*, name, url, kind="rule_set", format="auto", authorized=False,
              schedule, now, max_bytes=…, timeout=…, rng=None) -> dict
```

Считает `RunState` из собственной истории хранилища и `is_due`; если не пора —
возвращает `{"ran": False, "status": "not_due", …, "next_run": …}` без фетча.
Если пора — вызывает обычный `update` (та же SSRF-политика, проверка формата,
атомарная активация) и возвращает `status` `ok`/`failed`, запись истории,
типизированный `error` и проекцию `next_run` (с учётом backoff после сбоя).

## Тесты

`backend/tests/test_source_schedule.py` (20), `test_rulesets.py` (11),
`test_presets.py` (7) — суммарно 38 тестов, без сети:

* расписание: интервал/пора/ожидание, overdue → ровно один запуск без
  догоняющей серии, опора на last_attempt; окно — до/внутри/после, один запуск
  за сутки; DST (`America/New_York`: фиксированное локальное время даёт разный
  UTC-офсет); backoff рост+кап; джиттер инъектируемый и не меняет due;
  `from_contract`; `state_from_history`; `describe`; `staleness`; интеграция
  `run_scheduled` (интервал между вызовами, запись сбоя + backoff).
* rule-set: домен↔CIDR mismatch в обе стороны, json-форма, geosite/geoip
  materialization-warning, `.srs` распознан/не активируется, лимиты
  записей/байт, empty, https-требование, закрытый формат, хеш/размер, stale.
* каталог: непустой, каждый хост в allowlist, все лицензии `verified=False`,
  `cjk_cdn_ip` без лицензии → `preset.license_missing`, отсортированный
  `catalog_view`, адаптер в `BuiltinSource`, `build_spec` принимает
  allowlist-запись и отвергает расхождение URL.

Текущий прогон: `PATH="$PWD/.venv/bin:$PATH" .venv/bin/pytest -q` из `backend/` —
**829 passed**. `uv` в среде проверки отсутствовал.

## Что НЕ покрыто (сознательно вне объёма)

* **Реальный `sing-box check`** для собранного конфига с новым набором —
  `config_validator` остаётся инъектируемым (бинарник не закреплён, ADR-0005);
  в тестах — фейковый валидатор.
* **Каталог не включён по умолчанию** — opt-in разрешает только выбранные ключи;
  `tproxy.not_available` не открывается.
* **Бинарные `.srs`** — нет байт-точного хранилища и закреплённого компилятора;
  распознаются и честно помечаются, но не активируются.
* **Живой фетч / одноразовая VM** — весь транспорт мокирован.
* **Гарантия прав на переупаковку** каталога — только провенанс и флаги; юридически
  не подтверждено (см. выше).
* **Открытие `tproxy.not_available`** — gate не тронут.

## Что добавлено поверх планировщика

* **Условный HTTP** (`ETag`/`Last-Modified` → `If-None-Match`/`If-Modified-Since`)
  и корректная обработка `304` (активный набор не меняется, пишется
  `not_modified`, который считается `last_success`) — в `agent/downloader.py`;
  валидаторы хранятся в `validators.json` и сбрасываются при смене URL. Детали
  — в `docs/tproxy-sources-downloader.md`.
* **Read-only web-контракт**: `schema.RuleSetSource` + `Configuration.rule_sets`
  (пусто/выключено, без секретов, строгая валидация); `GET /api/rulesets`
  (status/stale из истории агента) и admin-only `POST /api/rulesets/update`;
  UI во вкладке «Rule-set» показывает список и ручное обновление.
