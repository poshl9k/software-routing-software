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
| `backend/src/vs_router/agent/singbox_service.py` | Типизированный адаптер движка: закреплённые константы бинарника (ADR-0012), юнит с `ExecStart` по закреплённому пути, fail-closed проверка версии/провенанс-ревизии/SHA256 бинарника, `sing-box check -c` на выложенном конфиге, `start`/`stop`/readiness через фиксированный argv. |
| `backend/src/vs_router/agent/unbound_service.py` | Типизированный адаптер DNS-контура (ADR-0014): детерминированные юниты `vs-router-unbound-selected`/`-ordinary` с разными UID (29092/29093) и `CAP_NET_BIND_SERVICE`, фиксированный argv `unbound-checkconf`/`systemctl`, fail-closed readiness обоих резолверов до перехвата, best-effort stop. |
| `backend/src/vs_router/agent/apply.py` | Условное подключение каркаса: `_tproxy_branch`, `_tproxy_branch_from_snapshot`, `_merged_validators`; `_install`/`_backup` принимают явную карту файлов; компенсация в rollback и в провале первого apply. |
| `backend/src/vs_router/agent/boot_restore.py` | `restore_tproxy_protection()` (загружает guard первым), teardown в `recover_interrupted_apply`, порядок в `main()`. |
| `backend/tests/test_tproxy_apply_integration.py` | Интеграционные тесты каркаса (инертность, порядок, откат, первый apply, boot). |

## Порядок и фазы (осознанный, не должен переставляться)

```
1. guards       — защитные nftables-таблицы (containment + preauthorization +
                  DNS ingress/listener), ставятся ДО любого перехвата.
                  Если не загрузились — дальше не идём.
2. readiness    — артефакты sing-box (config) и два split-конфига Unbound
                  выкладываются и проверяются; затем типизированные шаги
                  поднимают оба резолвера (`unbound_service`, fail-closed
                  `unbound-checkconf` + `is-active`) и движок
                  (`singbox_service`), чтобы и DNS-контур, и движок были
                  заведомо готовы до разрешения перехвата.
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
  `restore_tproxy_resolvers()` поднимает оба резолвера ADR-0014 после guards и
  строго до тракта (no-op, если split-конфигов нет); при прерванном apply
  `recover_interrupted_apply` останавливает их.

## Доказательство инертности

- `enabled=False`: `_tproxy_branch` → `({}, {})`, `build_artifacts` → `{}`,
  `marker` без ключа `tproxy`, состав файлов/валидаторов == `FILES`/`VALIDATORS`.
  Число вызовов валидаторов в apply равно `len(FILES)` (тест
  `test_disabled_apply_adds_no_tproxy_file_or_marker_key`).
- `_install`/`_backup` с `files=None` по умолчанию эквивалентны прежним
  `FILES`; все существующие тесты `test_agent_apply.py`, `test_agent_services.py`,
  `test_management.py`, `test_tunnel_proxy.py` проходят без правок и без
  изменений golden.

## Пиннинг бинарника и readiness движка

Адаптер `agent/singbox_service.py` закрепляет движок по ADR-0012 и не запускает
его, пока артефакт и конфиг не подтверждены (fail-closed).

Закреплённые модульные константы:

| Константа | Значение |
| --- | --- |
| `SINGBOX_BINARY` | `/usr/local/lib/vs-router/sing-box` (путь `ExecStart`) |
| `SINGBOX_CONFIG` | `/etc/vs-router/applied/singbox.json` |
| `SINGBOX_VERSION` | `1.14.2` |
| `SINGBOX_ARCHIVE_SHA256` | `a684484d…a0c6` (ассет `sing-box-1.14.2-linux-amd64.tar.gz`, ADR-0012) |
| `SINGBOX_BINARY_SHA256` | `fc9c6e6a…d7b8` (извлечённый ELF, исполняется юнитом) |
| `SINGBOX_PROVENANCE_REVISION` | `af6e64c3…6709` (провенанс-коммит сборки) |

`unit_content()` рендерит `ExecStart={SINGBOX_BINARY} run -c {SINGBOX_CONFIG}` —
путь берётся из константы, не из RPC.

Порядок `SingboxService.start()` (фиксированный argv, без шелла; шаг
`singbox_process` фазы readiness, строго до `tproxy_interception`):

1. `verify_binary()` — `sing-box version` (проверка строки версии **и**
   провенанс-ревизии) + `sha256sum <SINGBOX_BINARY>`. Любое отсутствие,
   ненулевой код, чужой билд или расхождение хеша → `agent.singbox_binary_unverified`,
   юнит **не включается**.
2. `install_unit()` — идемпотентная запись юнита из закреплённых констант.
3. `check_config()` — `sing-box check -c <SINGBOX_CONFIG>`; ненулевой код →
   `agent.singbox_config_invalid`, юнит не включается (перехват блокируется).
4. `systemctl enable --now <unit>`, затем ожидание `systemctl is-active --quiet`
   (readiness-петля).

Вывод команд не логируется; в журнал не попадают ни секреты, ни содержимое
конфига (адаптер сообщает только коды ошибок). Тесты —
`backend/tests/test_agent_singbox_service.py` (пиннинг, негатив по
версии/SHA256/отсутствию, проверка «argv без инъекции», блокировка readiness
при провале `check`, инертность при `enabled=False`).

### Фактическая проверка `sing-box check -c` (2026-10-07, VM `vsr-tproxy-lab`)

Конфиг сгенерирован офлайн из `generators/singbox.py`
(`generate_singbox(ConfigurationVersion())`, gate закрыт) и доставлен на
одноразовую VM; вызывался пробник `/var/cache/vsr-singbox-probe` (та же сборка
1.14.2, revision `af6e64c3…`, SHA256 `fc9c6e6a…`, размер 81 297 637 B):

- `/var/cache/vsr-singbox-probe check -c singbox-valid.json` → exit `0`.
- `… check -c singbox-broken.json` (неизвестный тип inbound) → exit `1`
  (`FATAL … unknown inbound type`).
- `… check -c /root/vsr-probe/nope.json` (отсутствующий конфиг) → exit `1`
  (`FATAL … no such file or directory`).

Публичный gate при этом закрыт; конфиг из `generators/singbox.py` — offline-превью.

## Что остаётся непроверенным на реальном deploy

- Публичный gate `tproxy.not_available` **не открыт**; ни один валидный
  конфиг не попадает в ветку каркаса.
- Нет генератора **перехвата** (mark/redirect) и нет управляемого policy route:
  фаза `interception` пуста, тракт не поднимается.
- Нет типизированного загрузчика TProxy-артефактов: в тестах активация —
  это размещение файлов; на хосте guard должен грузиться через
  whitelisted-адаптер агента (не добавлен; произвольный shell запрещён).
- Адаптер движка `singbox_service` подключён к фазе readiness, но **живого
  deploy не было**: на реальном Debian-хосте (systemd, pinned-бинарник в
  `/usr/local/lib/vs-router/sing-box`, выложенный `singbox.json`) `start` не
  запускался. Подтверждена только команда проверки конфига на одноразовой VM
  `vsr-tproxy-lab` (см. §«Пиннинг бинарника и readiness движка»).
- DNS OUTPUT guard (selected UID), srs/rule-set, подписки, планировщик,
  lifecycle процесса sing-box/Unbound, packet-path матрица отказов и
  reboot с реальным перехватом — по-прежнему открыты (см.
  `docs/sing-box-tproxy-plan.md`, `docs/lab-*`). Адаптер DNS-контура
  `unbound_service` и его VM-lifecycle закрыты отдельно (см.
  `docs/lab-34-tproxy-unbound-lifecycle.md`): доказаны два реальных процесса
  с разными UID, но на VM юниты ставились напрямую, а не через apply-цикл, и
  остаются открытыми AppArmor-оверрайд (упаковка) и общий pidfile.
- Тесты каркаса — unit/офлайн на `FakeFS`/`FakeExecutor`; фактического
  применения nftables/policy route/sing-box на Debian VM не выполнялось.
