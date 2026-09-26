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

## Подключение реальных сервисов (после лабораторного прогона)

Агент теперь применяет nftables, Unbound и Kea при apply и при rollback через
один `_install`. Фаза `applied` записывается после успешного reload; итоговый
`rolled_back` — после восстановления всех трёх сервисов. networkd пока не подключён.

- nft: сгенерированный файл начинается с `destroy table inet vs_router`, затем
  создаёт таблицу в той же транзакции `nft -f`. Другие таблицы не меняются.
  `destroy` допускает отсутствие таблицы ([руководство nft](https://www.netfilter.org/projects/nftables/manpage.html)).
- Unbound: `/etc/unbound/unbound.conf.d/vs-router.conf` включает
  `/etc/vs-router/applied/unbound.conf`; полный `unbound-checkconf` предшествует
  `systemctl reload unbound`. При ненулевом коде reload отправляется HUP главному
  процессу. Успешная отправка HUP не является проверкой работоспособности DNS.
- Kea: агент атомарно копирует конфиг в `/etc/kea/kea-dhcp4.conf`, затем вызывает
  `config-reload` для `dhcp4` на `127.0.0.1:8000`. Basic auth: `kea-api`, пароль
  читается из `/etc/kea/kea-api-password` при каждом вызове и не попадает в argv.
  Генератор сохраняет `/run/kea/kea4-ctrl-socket` для следующих reload.

Перед первым apply должны быть запущены сервисы и настроен ctrl-agent из lab-01:
пароль непустой, его dhcp4 control-socket указывает на указанный unix-сокет,
а текущий конфиг DHCPv4 уже открывает этот сокет. Установщик не создаёт пароль
и не меняет конфиг ctrl-agent. Include Unbound начинает работать после первого
apply, когда появится сгенерированный файл; до этого не перезапускайте Unbound
с новым include. Основной Debian-конфиг должен подключать `unbound.conf.d/*.conf`.

Packaging разрешает агенту AF_INET и запись в каталоги Kea/Unbound. Добавлена
CAP_DAC_OVERRIDE для доступа root-агента с Group=vs-router-web к каталогу
`/etc/kea` (0750, `_kea:_kea`) и файлу пароля. БД сохраняет режим 0660,
ExecStart использует `/usr/bin/python3`. Unbound получает право прохода через
каталоги `/etc/vs-router` и `applied`, его конфиг и include — 0644;
остальные генерируемые файлы остаются закрытыми. Установщик дополняет local
AppArmor-профиль Unbound правом чтения включённого файла, если профиль установлен.

Новые проверки выполняются с fake executor/HTTP, без системных команд и сети.
Живой apply/rollback с этими адаптерами на VM ещё требует отдельного прогона;
результаты предыдущей таблицы относятся к прежнему этапу установки файлов.

## Живое применение подтверждено (вторая итерация)

- **nftables**: таблица `inet vs_router` реально создана в ядре (atomic swap
  `destroy table` + `add`), правило `allow_ssh_wan` присутствует и считает
  пакеты (1/60B — наша же SSH-сессия).
- **Unbound**: include подключён в `/etc/unbound/unbound.conf.d/`,
  `unbound-checkconf` полного конфига прошёл, `systemctl reload` отработал.
- **Kea**: конфиг скопирован в `/etc/kea/kea-dhcp4.conf`, `config-reload` через
  ctrl-agent прошёл (reload counter = 15).
- **Anti-lockout** правило в таблице (br0 tcp/443).
- Урок: тест-кейс v3 (только WAN без allow-ssh) реально заблокировал SSH —
  **firewall работает как задумано**, доступ вернулся после reboot (nft не
  персистентен в схеме без reload при загрузке — добавить restore-on-boot в
  установщик, задача этапа 2).
