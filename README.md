# vs-router — программный роутер на Linux

Веб-панель управления сетевым роутером на Linux: сеть, DHCP, DNS, firewall, VPN-туннели, входящий прокси и DDNS — без ручного редактирования конфигурационных файлов. Ошибочное изменение откатывается из панели или автоматически по таймеру.

- **Платформа:** Debian 13 (Ubuntu — в планах), systemd-networkd, nftables, Kea DHCPv4, Unbound, WireGuard / AmneziaWG, Caddy
- **Архитектура:** непривилегированный FastAPI + привилегированный агент через unix socket (JSON-RPC, whitelist методов)
- **Безопасное применение:** черновик → проверка → применение → подтверждение; при включённой «безопасной настройке» — окно подтверждения с автооткатом по таймеру и пробой доступности панели

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

Требования: Debian 13, `python3` (3.11+), `uv` (или pip), системные пакеты `kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor caddy wireguard-tools amneziawg-tools amneziawg-go`.

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
sudo ./backend/packaging/update.sh          # git pull + сборка фронта/бэкенда + миграции + рестарт сервисов
# опции: --skip-pull (не тянуть git), --skip-build (не пересобирать, деплоить готовое)
```

Скрипт обновляет только приложение и статику UI; он явно накатывает миграции БД (`alembic upgrade head`), чего не делает `install.sh` при обновлении. Полная переустановка зависимостей и тулчейна — через `bootstrap.sh`.

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
cd backend  && uv sync && uv run pytest -q     # 186+ тестов
cd frontend && npm install && npm test && npx tsc --noEmit
```

Golden-тесты генераторов сравнивают вывод с эталонами в `backend/tests/golden/` — правки генераторов требуют осознанного обновления эталонов.
