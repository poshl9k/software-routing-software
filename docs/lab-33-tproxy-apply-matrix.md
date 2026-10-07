# lab-33: engine-матрица apply/rollback/safe-mode TProxy + нативные валидаторы

**Статус: оффлайн engine-матрица (FakeFS/FakeExecutor) + нативная проверка
сгенерированных текстов на одноразовой VM. Публичный gate `tproxy.not_available`
закрыт; реального reboot с продуктовым подтверждением не было.**

Матрица закрывает «пункт 1» плана (`docs/sing-box-tproxy-plan.md` §«1. Контракт
и контролируемый процесс»): доказать, что новые фазы
(guards → readiness → interception, см. `agent/tproxy_apply.py`) не ломают
существующую атомарность/безопасность apply, и подтвердить сгенерированные
тексты нативными валидаторами. Ветка достижима только оффлайн через
`model_copy` — как и остальной TProxy-каркас.

Файлы этой задачи:

| Файл | Роль |
| --- | --- |
| `backend/tests/test_tproxy_apply_matrix.py` | новый: 16 тестов engine-матрицы (инъекция сбоя на каждой фазе, safe-mode таймер, первый apply, старый снапшот, boot). |
| `backend/src/vs_router/agent/tproxy_apply.py` | + `teardown_files()` (что удалять при teardown, кроме boot-loaded guard). |
| `backend/src/vs_router/agent/apply.py` | `_teardown_tproxy_artifacts()` (boot-safe компенсация) вместо `_remove_tproxy_readiness_files()`; `confirm_version` бэкапит весь файловый набор. |

Штатная команда из `backend/`: `uv run --no-sync pytest -q` → **784 passed**
(было 768; +16 новых, 0 падений).

## Engine-матрица (оффлайн, `FakeFS`/`FakeExecutor`, сбой на каждой фазе)

Подтверждённая база — обычный (`enabled=False`) снапшот; проверяемый —
оффлайн-enabled (`test_tproxy_apply_integration.enabled_version`). Инъекция —
через `reload_commands` (тот же шов, что у файловых сервисов) и подменённый
executor/validator, без systemd и без shell.

| Сценарий / фаза | Точка инъекции | Наблюдаемый результат | Тест |
| --- | --- | --- | --- |
| успешная активация (staged→commit) | — | guards и `singbox.json` live на шаге readiness, capture ещё нет; все фазы `applied`; commit (`confirmed`, whole-file backup) | `test_successful_activation_commits_every_phase` |
| **guards** | reload `tproxy_guards` rc≠0 | `rolled_back`, база восстановлена, guard → destroy-only, движок остановлен, policy route снят | `test_failure_at_each_phase_rolls_back…[guards_reload]` |
| **readiness** (файл движка) | reload `singbox` rc≠0 | `rolled_back`, `reason_service=singbox` | `…[readiness_engine_reload]` |
| **readiness** (шаг policy route) | шаг `tproxy_policy_route` raises | `rolled_back`, interception **не** активирован | `…[readiness_policy_step]` |
| **readiness** (шаг процесса движка) | шаг `singbox_process` raises | `rolled_back` | `…[readiness_process_step]` |
| **interception** | reload `tproxy_interception` rc≠0 | `rolled_back`, capture снят, база восстановлена | `…[interception_reload]` |
| отказ валидации guards | validator rc≠0 | `failed`, **ни одной мутации**, rollback не запускается | `test_validation_failure_before_any_mutation…` |
| именование сбойного сервиса | reload guards/singbox/interception | `reason_service` = имя фазы сохраняется в маркере | `test_reload_failure_names_the_failing_service` |
| safe-mode таймер (провал подтверждения) | deadline без confirm | `pending` → `rolled_back`, `reason=timeout`, база восстановлена | `test_safe_mode_deadline_rolls_back_pending_tproxy` |
| подтверждение pending-TProxy | `confirm_version` | backup содержит все TProxy-файлы | `test_confirmed_tproxy_version_backs_up_the_whole_file_map` |
| первый apply без baseline | шаг `singbox_process` raises | `failed`, цели отката нет → teardown всех owned-артефактов, guard destroy-only, `snapshot.json` не создан | `test_first_apply_without_baseline_tears_everything_down` |
| старый снапшот без sing-box-файла | rollback к non-TProxy базе | `_tproxy_branch_from_snapshot` → `({}, {})` (в т.ч. для enabled-снапшота, без исключения); cleanup installed, `singbox.json` не воскрешён | `test_old_snapshot_has_no_singbox_file_and_rolls_back_cleanly` |
| boot: pending не подтверждается | `recover_interrupted_apply` | `rolled_back`, `reason=reboot`; guard → destroy-only; split-конфиги удалены | `test_boot_recover_never_promotes_pending…` |
| boot: guards ДО тракта | `restore_tproxy_protection` | `nft -f <guard>` идёт раньше `nft -f nftables.conf` в `main()` | `test_boot_restores_guards_before_the_product_tract` |

Инвариант «возврат к подтверждённому состоянию» проверяется в каждом отказе:
`APPLIED/nftables.conf` байт-в-байт равен подтверждённой базе, а единственный
выживший TProxy-артефакт — guard — содержит **только** `destroy table`
(`cleanup_content()`), чтобы reboot не поднял защитные таблицы на не-TProxy
состоянии.

## Дефекты, вскрытые матрицей (исправлены)

1. **Rollback к не-TProxy цели оставлял protective guard.** После отката
   `APPLIED/tproxy-guards.nft` сохранял боевой текст защитных таблиц.
   `boot_restore.restore_tproxy_protection()` загружает этот файл первым на
   каждом boot, поэтому reboot поднял бы fail-closed guard-таблицы на
   подтверждённом не-TProxy состоянии. Исправление:
   `ApplyEngine._teardown_tproxy_artifacts()` перезаписывает guard destroy-only
   текстом (как `recover_interrupted_apply`) и удаляет остальные owned-артефакты
   (split Unbound, `singbox.json`, capture). Вызывается и в rollback, и в
   teardown провалившегося первого apply.
2. **`confirm_version` бэкапил только `FILES`.** При подтверждении
   pending-TProxy версии в подтверждённый снапшот не попадали guard/движок/
   capture: нарушение «whole-configuration snapshot». Исправление: файловый
   набор восстанавливается из `marker['tproxy']`
   (`{**FILES, **TPROXY_FILES}`), обычные конфигурации не затронуты.

## Нативные валидаторы (VM `vsr-tproxy-lab`, не `vsr-live-403ab3a`)

Все тексты сгенерированы оффлайн генераторами (`generators/nftables.py`,
`generators/unbound.py`, `generators/singbox.py`) из оффлайн-enabled снапшота,
без изменений golden. Пробник движка — `/var/cache/vsr-singbox-probe`
(та же сборка 1.14.2, revision `af6e64c3…`, SHA256 `fc9c6e6a…d7b8`, размер 81 297 637 B).

Композиция таблиц проверена по содержимому сгенерированных файлов:

| Артефакт | nft-таблицы | Команда | Результат |
| --- | --- | --- | --- |
| `ordinary-firewall.nft` (продуктовый) | `inet vs_router` | `nft -c -f` | exit 0 |
| `containment.nft` | `vs_router_tproxy_guard` (FORWARD -10) | `nft -c -f` | exit 0 |
| `preauth.nft` | `vs_router_tproxy_preauth` (PREROUTING -90) | `nft -c -f` | exit 0 |
| `interception.nft` (3 таблицы) | `_ct_reset` (-85) / `_interception` (-80) / `_input` (-20) | `nft -c -f` | exit 0 |
| `dns-ingress.nft` | `vs_router_tproxy_dns_ingress` (-110) | `nft -c -f` | exit 0 |
| `dns-listener.nft` | `vs_router_tproxy_dns_listener` (INPUT -10) | `nft -c -f` | exit 0 |
| `dns-output.nft` | `vs_router_tproxy_dns_output` (OUTPUT -20, skuid 29092) | `nft -c -f` | exit 0 |
| `guards.nft` (композиция фазы 1) | guard + preauth + 3 DNS | `nft -c -f` | exit 0 |
| `cleanup.nft` (фаза 4) | destroy × 8 owned-таблиц | `nft -c -f` | exit 0 |
| `unbound-selected.conf` | — | `unbound-checkconf` | exit 0 (no errors) |
| `unbound-ordinary.conf` | — | `unbound-checkconf` | exit 0 (no errors) |
| `singbox.json` | — | `/var/cache/vsr-singbox-probe check -c` | exit 0 |

Сводка прогона на VM: `FAILS=0`, `EXIT=0`. Доставка — `vm-push.sh`
(tar → guest dir → `runchecks.sh`); HTTP-сервер на `192.168.122.1:8099` поднят.
`nft -c` — синтаксическая проверка, а не packet-path: фактический тракт/матрица
отказов уже покрыты lab-27…lab-32.

## Что остаётся

- **enabled→enabled rollback не восстанавливается.** `_tproxy_branch_from_snapshot`
  не может ревалидировать enabled-снапшот (публичный gate закрыт), поэтому откат
  к подтверждённому **TProxy**-состоянию теряет TProxy-файлы. Достижимо только
  оффлайн; первый apply и rollback к не-TProxy базе закрыты этой матрицей.
- **Реальный reboot с продуктовым подтверждением** требует установки продукта
  (systemd-юниты, закреплённый бинарник в `/usr/local/lib/vs-router/sing-box`,
  загрузчик nft-артефактов агента — он ещё не добавлен). Проверена только
  нативная валидация текстов и оффлайн-порядок boot.
- Публичный gate `tproxy.not_available` **не открыт**; всё выше — оффлайн-ветка
  каркаса.
