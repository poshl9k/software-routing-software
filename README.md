# vs-router — программный роутер на Linux

Веб-панель управления сетевым роутером на Linux: сеть, DHCP, DNS, firewall, VPN-туннели, входящий прокси и DDNS — без ручного редактирования конфигурационных файлов. Ошибочное изменение откатывается из панели или автоматически по таймеру.

- **Платформа:** Debian 13 (Ubuntu — в планах), systemd-networkd, nftables, Kea DHCPv4, Unbound, WireGuard / AmneziaWG, Caddy
- **Архитектура:** непривилегированный FastAPI + привилегированный агент через unix socket (JSON-RPC, whitelist методов)
- **Безопасное применение:** черновик → проверка → применение → подтверждение; при включённой «безопасной настройке» — окно подтверждения с автооткатом по таймеру и пробой доступности панели

## Два продукта, одно ядро

Репозиторий собирает два продукта (ADR-0018), и решает не сборка, а **профиль хоста**: установщик пишет маркер `/etc/vs-router/profile`, приложение сверяет его с хранимыми документами и отказывает при расхождении (ADR-0026).

| | `vs-router` | `vs-panel` (по ADR-0021) |
|---|---|---|
| Хост | VM или железо с локальной консолью | VPS с одним аплинком, без консоли |
| Владеет | сетью целиком: адресами, DHCP, DNS, firewall, SSH | своей зоной: захват и анти-утечка, туннели, панель; **не** адресами аплинка и **не** `sshd` |
| Не ставит | — | Kea, консольное меню, ISO |
| Установка | загрузка с ISO (`installer/README.md`) | по сети, по SSH: `online-install.sh` (ADR-0017) |

Статус (17 окт 2026): профиль и маркер реализованы; панель публикуется по HTTPS (ACME, HTTP-01), ядро и `sshd` она не трогает, Kea и консольный юнит на неё не ставятся; обновление несёт профиль хоста и откатывается вместе с ревизией БД. **Ещё не соответствует замыслу:** панель по-прежнему пишет `/etc/systemd/network/10-vs-router-eth0.network` и переопределяет адресацию аплинка — правка ждёт прогона на VM (ADR-0027, статус «предложен»). Абоненты, устройства и маршрутизация `sing-box` (ADR-0019/0020) — в работе. Полные детали и открытые вопросы: `docs/panel-router-split.md`.

## Структура репозитория

| Каталог | Содержимое |
|---|---|
| `backend/` | FastAPI-приложение, агент применения, генераторы конфигураций, тесты |
| `frontend/` | Веб-панель (React + TypeScript + MUI), сборка Vite |
| `installer/` | Сборка установочного ISO (preseed + авто-bootstrap) |
| `mockups/` | Статичные макеты экранов (этап 0) |
| `docs/` | Протоколы лабораторных проверок, ADR |
| `docs/adr/` | Архитектурные решения |
| `CONTEXT.md` | Глоссарий доменных терминов и принятых решений |
| `router_project_plan.md` | План работ и статус этапов |

## Установка

Самый быстрый путь — установочный ISO (`installer/README.md`): одна сборка и загрузка машины с него.

Полная пошаговая инструкция: **[docs/install.md](docs/install.md)**. Кратко:

Требования: Debian 13, `python3` (3.11+), `uv` (или pip), системные пакеты `kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor caddy wireguard-tools amneziawg-tools amneziawg-go`. Пакеты Kea нужны только роутеру: панель по ADR-0021 DHCP-сервер не ставит, и её DHCP-фаза отсутствует.

Сборка фронта (один раз):

```sh
cd frontend && npm install && npm run build
```

Установка:

```sh
cd backend
uv build                      # или pip wheel .
sudo pip install --break-system-packages dist/vs_router_backend-*.whl
sudo ./packaging/install.sh   # каталоги, БД+миграции, AppArmor, systemd-юниты, статика UI
```

Сервисы:

- `vs-router-web.service` — веб-панель (unix socket `/run/vs-router/web/web.sock`)
- `vs-router-agent.service` — агент применения (unix socket, root, CAP_NET_ADMIN)
- `vs-router-rollback.timer` — проверка дедлайна подтверждения (15 с)
- `vs-router-bootrestore.service` — восстановление конфигураций при загрузке (до сети)
- `vs-router-ddns.timer` — обновления DDNS (5 мин)
- `vs-router-wg@<iface>.service`, `vs-router-awg@<iface>.service` — userspace-туннели

Ключ шифрования секретов: создайте `/etc/vs-router/secrets.env` (0600, root):

```sh
echo "VS_ROUTER_SECRET_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" | sudo tee /etc/vs-router/secrets.env
```

Первый вход: `POST /api/setup` (или мастер первого запуска в UI) — работает, пока таблица пользователей пуста. Мастер первого запуска («Базовая сеть») выбирает LAN-интерфейс из реальных портов системы (`GET /api/host/interfaces`, в опциях виден MAC), а не из свободного текста.

## Обновление

Обновить код и собранный дистрибутив на уже установленном сервере (без переустановки ОС-пакетов и пересборки тулчейна Caddy/AWG/WG):

```sh
cd /opt/vs-router
sudo ./backend/packaging/update.sh --release <40-символьный-коммит> --manifest-url <https-URL release.json>
# без аргументов — пересобрать и развернуть текущее дерево
# опции: --manifest <url>, --skip-build (развернуть уже собранное)
```

Канал обновлений — **зафиксированный выпуск, не git** (ADR-0005/0010): `update.sh` скачивает манифест и артефакт, сверяет `source_sha256` и `REVISION` с коммитом из манифеста, распаковывает в `/opt/vs-router.new` и оставляет прежнее дерево в `/opt/vs-router.prev`. `git fetch`, ветки и `latest` не используются; `--skip-pull` — устаревший no-op.

Скрипт накатывает миграции БД (`alembic upgrade head`) и, если после рестарта панель или SSH не отвечает, возвращает прежнее дерево **и ревизию БД**, а сломанное дерево оставляет в `.broken` (ADR-0010/0021). `install.sh` тоже применяет миграции — при каждом запуске, включая повторный. Полная переустановка зависимостей и тулчейна — через `bootstrap.sh`.

### Доступ к панели

Панель доступна через HTTPS-прокси (Caddy → unix socket).

## Известные ограничения MVP

- Туннели — userspace (производительность ниже kernel-WireGuard); kernel-модуль AmneziaWG — после MVP
- Ядро Linux обновляется только по уязвимостям; после обновления — обязательная проверка туннелей
- Caddy требуется сборка с `caddy-l4` (TLS passthrough) и `caddy-dns/cloudflare` (DNS-01)
- `host_cmds` (hook Kea) отсутствует в пакете Debian — резервации только через конфиг-файл
- IPv6 минимальный; DHCPv6/RA, policy routing, второй WAN, 2FA — после MVP (см. план)

## Разработка

```sh
cd backend  && uv sync && uv run pytest -q     # полный прогон; на 17 окт 2026 — 1299 passed / 2 skipped
cd frontend && npm install && npm test && npx tsc --noEmit
```

Golden-тесты генераторов сравнивают вывод с эталонами в `backend/tests/golden/` — правки генераторов требуют осознанного обновления эталонов.
