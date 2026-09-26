# Протокол развёртывания и проверки этапа 1 — безопасное применение

Дата: 26 сентября 2026 · VM: lab (192.168.122.198), Debian 13.7, python 3.13
Компоненты: vs-router-web (uvicorn, unix socket), vs-router-agent (root, AF_UNIX+SO_PEERCRED, CAP_NET_ADMIN), vs-router-rollback.timer (15 с)

## Результаты

| Проверка | Результат | Детали |
| --- | --- | --- |
| Тесты на VM | ✅ 122 passed | тот же набор, что в CI |
| Системные юниты | ✅ agent/web/timer активны | agent.sock + web/web.sock |
| Админ setup + login (argon2id, cookie) | ✅ | /api/setup только при пустой users |
| Draft + validate | ✅ | генераторы + доменные валидаторы |
| **Apply (bootstrap, safe_mode=false)** | ✅ confirmed | nft -c ✅, unbound-checkconf ✅, kea-dhcp4 -t ✅; /etc/vs-router/{applied,confirmed}/ + маркер |
| **Apply safe_mode=true** | ✅ pending | маркер с deadline, подтвердил → confirmed, маркер удалён |
| **Проба панели** (web остановлен, safe-mode apply через RPC) | ✅ rollback мгновенный | маркер: `rolled_back, reason: panel.unavailable`; applied = confirmed-конфиг |
| **Сценарий-«гроб»** (apply + не подтверждать) | ✅ автооткат по таймеру | через deadline rollback_check вернул applied к confirmed-конфигу; draft остался draft |

## Исправленные блокеры (закоммичены в packaging/install.sh, af62bef)

1. `ExecStart=python` → `/usr/bin/python3` (3 юнита).
2. **DAC_OVERRIDE при NoNewPrivileges**: агент root+`Group=vs-router-web` не пишет в БД 640 → **chmod 660** (group-write) в install.sh.
3. Каталоги /etc/vs-router, /run/vs-router: 770 + chgrp vs-router-web.
4. AppArmor-профиль kea-dhcp4 блокировал чтение staged-конфигов → local-override `/run/vs-router/** r,` (install.sh делает сам).
5. Alembic bootstrap: install.sh создаёт БД и применяет миграции до старта сервисов.

## Критерий этапа 1

✅ Ошибочная конфигурация (v3) не оставила устройство в сломанном состоянии:
применена (pending) → не подтверждена → откатана автоматически по таймеру;
applied/confirmed снова содержит последнюю стабильную конфигурацию.

## Осталось по этапу 1

- Onboarding-флоу (мастер первого запуска в UI) — макет готов, API готов.
- Фронтенд (макеты → React/MUI) — следующий этап.
- Установщик целиком (сценарий install.sh на чистой VM).
