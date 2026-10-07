# Интеграция sing-box TProxy в apply/boot: каркас

**Статус: каркас, публичный gate закрыт, не доказано на реальном deploy.**
`tproxy.enabled=True` по-прежнему отвергается `tproxy.not_available`
(`validators.py`), поэтому новый код **инертен** для любой валидной
(`enabled=False`) конфигурации: он не добавляет файлов, фаз, маркеров и не
меняет поведение текущих apply/rollback/boot. Всё описанное ниже достижимо
только из офлайн-снапшота `model_copy` — того же идиома, которым пользуются
офлайн-генераторы `tproxy_dns.py`/nftables. Golden-файлы и существующие
ожидания тестов не менялись.

## Что добавлено

| Файл | Роль |
| --- | --- |
| `backend/src/vs_router/agent/tproxy_apply.py` | Контракт каркаса: `TPROXY_FILES`, `TPROXY_VALIDATORS`, `PHASE_ORDER`, `required`, `build_artifacts`, `guard_content`, `cleanup_content`, `owned_tables`, `describe`. Нового контента не рендерит — только композиция существующих генераторов. |
| `backend/src/vs_router/agent/apply.py` | Условное подключение каркаса: `_tproxy_branch`, `_tproxy_branch_from_snapshot`, `_merged_validators`; `_install`/`_backup` принимают явную карту файлов; компенсация в rollback и в провале первого apply. |
| `backend/src/vs_router/agent/boot_restore.py` | `restore_tproxy_protection()` (загружает guard первым), teardown в `recover_interrupted_apply`, порядок в `main()`. |
| `backend/tests/test_tproxy_apply_integration.py` | Интеграционные тесты каркаса (инертность, порядок, откат, первый apply, boot). |

## Порядок и фазы (осознанный, не должен переставляться)

```
1. guards       — защитные nftables-таблицы (containment + preauthorization +
                  DNS ingress/listener), ставятся ДО любого перехвата.
                  Если не загрузились — дальше не идём.
2. readiness    — артефакт sing-box (config) выкладывается и проверяется,
                  чтобы движок был заведомо готов до разрешения перехвата.
3. interception — правила захвата (mark/redirect). ПУСТО СОЗНАТЕЛЬНО:
                  генератора захвата нет, gate закрыт, тракт не открывается.
4. compensation — при отказе восстанавливается подтверждённая цель и
                  явно сносится каждая TProxy-таблица (cleanup_content).
```

Внутри одного apply файлы активируются в порядке `FILES` → `tproxy_guards`
→ `singbox` (dict-порядок `TPROXY_FILES`). Порядок зафиксирован тестом
`test_enabled_apply_installs_guards_before_engine`.

Композиция `guards` (из существующих генераторов, байт-в-байт):
`generate_tproxy_containment` (FORWARD -10) + `generate_tproxy_preauthorization`
(PREROUTING -90) + `generate_tproxy_dns_ingress_guard` (-110) +
`generate_tproxy_dns_listener_guard` (INPUT -10). DNS OUTPUT guard намеренно
не включён: ему нужен выбранный UID резолвера, которого пока нет в схеме.

## Компенсация и краевые случаи

- **Rollback к старому снапшоту без sing-box-файла.** `_tproxy_branch_from_snapshot`
  возвращает пустую ветку (в т.ч. если снапшот не перевалидируется). Если при
  этом прерванный apply уже выложил TProxy-артефакты, rollback пишет
  `tproxy-cleanup.nft` (`destroy table` для всех owned-таблиц из
  `generators.marks`) — установка старого продуктового nftables их не трогает.
- **Первый apply без confirmed-baseline.** При провале после выкладывания
  артефактов и отсутствии цели отката каркас выполняет тот же teardown
  best-effort, чтобы не оставить полусобранный guard.
- **Boot.** `recover_interrupted_apply` никогда не подтверждает pending
  (как и раньше): статус → `rolled_back`, причина `reboot`. Если прерванный
  apply нёс TProxy-артефакты, а подтверждённая цель — не TProxy, guard-файл
  перезаписывается destroy-only текстом, чтобы boot снёс полуперехват, а не
  восстановил его. `restore_tproxy_protection()` загружает этот файл первым,
  до продуктового nftables и до открытия любых слушателей.

## Доказательство инертности

- `enabled=False`: `_tproxy_branch` → `({}, {})`, `build_artifacts` → `{}`,
  `marker` без ключа `tproxy`, состав файлов/валидаторов == `FILES`/`VALIDATORS`.
  Число вызовов валидаторов в apply равно `len(FILES)` (тест
  `test_disabled_apply_adds_no_tproxy_file_or_marker_key`).
- `_install`/`_backup` с `files=None` по умолчанию эквивалентны прежним
  `FILES`; все существующие тесты `test_agent_apply.py`, `test_agent_services.py`,
  `test_management.py`, `test_tunnel_proxy.py` проходят без правок и без
  изменений golden.

## Что остаётся непроверенным на реальном deploy

- Публичный gate `tproxy.not_available` **не открыт**; ни один валидный
  конфиг не попадает в ветку каркаса.
- Нет генератора **перехвата** (mark/redirect) и нет управляемого policy route:
  фаза `interception` пуста, тракт не поднимается.
- Нет типизированного загрузчика TProxy-артефактов: в тестах активация —
  это размещение файлов; на хосте guard должен грузиться через
  whitelisted-адаптер агента (не добавлен; произвольный shell запрещён).
- Валидатор sing-box (`sing-box check -c`) — предполагаемый, но бинарник не
  выбран/не закреплён (ADR-0005), поэтому на реальном хосте проверка не
  гарантируется.
- DNS OUTPUT guard (selected UID), srs/rule-set, подписки, планировщик,
  lifecycle процесса sing-box/Unbound, packet-path матрица отказов и
  reboot с реальным перехватом — по-прежнему открыты (см.
  `docs/sing-box-tproxy-plan.md`, `docs/lab-*`).
- Тесты каркаса — unit/офлайн на `FakeFS`/`FakeExecutor`; фактического
  применения nftables/policy route/sing-box на Debian VM не выполнялось.
