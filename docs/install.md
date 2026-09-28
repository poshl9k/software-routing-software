# Установка vs-router на выделенную машину или VM

Целевая система: **Debian 13 (trixie)**, amd64. Ресурсы: минимум 2 vCPU / 2 ГБ RAM / 16 ГБ диска (рекомендуется 4/4/20). Проверено на тестовой VM — см. `docs/lab-04` и историю чистой установки.

Панель управляет сетью, firewall'ом, DHCP, DNS, туннелями, прокси и DDNS без правки конфигов руками. Все изменения проходят цикл: черновик → проверка → применение → подтверждение.

## Quick start (одна команда на чистой машине)

Альтернатива: соберите ISO командой `bash installer/make-iso.sh`.
Загрузите машину с ISO — установка и bootstrap выполнятся автоматически; креды см. `installer/README.md`.

Debian поставляется **без sudo** — сначала один раз через root:

```sh
su -c 'apt update && apt install -y sudo git && usermod -aG sudo $USER'
# выйдите и войдите заново, чтобы применилась группа sudo, затем:
git clone https://github.com/poshl9k/software-routing-software.git
cd software-routing-software/backend/packaging
sudo ./bootstrap.sh --lab      # лаба: tcp-bridge 8080, cookie без Secure
# или без --lab — прод: всё, кроме tcp-bridge
```

Скрипт идемпотентен (повторный запуск продолжает с места остановки), сам ставит apt-зависимости, собирает Caddy с L4 и AmneziaWG 3.1, собирает фронт и wheel, устанавливает сервисы и печатает в конце креды Kea ctrl-agent. Требуется: root, интернет (apt/PyPI/npm/Go). Ручной путь — ниже.

## 1. Системные пакеты

```sh
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git \
  kea-dhcp4-server kea-ctrl-agent unbound nftables apparmor \
  wireguard-tools socat curl
```

`kea-ctrl-agent` нужен для live-аренд и статистики; при чистой установке Debian спросит про backend Kea — memfile подходит.

## 2. Туннели: WireGuard и AmneziaWG (userspace)

WireGuard: пакетный `wireguard-tools` + демон `wg-go` (userspace) в `/usr/local/bin`:

```sh
sudo apt install -y golang-go build-essential
git clone https://git.zx2c4.com/wireguard-go && cd wireguard-go
make && sudo cp wireguard-go /usr/local/bin/wg-go
```

AmneziaWG — **версия 3.1+** (параметры обфускации и профили валидированы на 3.1):

```sh
git clone https://github.com/amnezia-vpn/amneziawg-go && cd amneziawg-go
make && sudo cp amneziawg-go /usr/local/bin/
git clone https://github.com/amnezia-vpn/amneziawg-tools && cd ../amneziawg-tools
cd src && make && sudo cp awg awg-quick /usr/local/bin/
```

Подробности и проверенный паттерн запуска (`awg-go <iface>` + `awg setconf`) — `docs/lab-02-amneziawg.md`.

## 3. Caddy с L4 (TLS passthrough) и DNS-провайдерами

Пакетный Caddy не содержит L4-модуль — собирается через xcaddy (см. `docs/lab-03-caddy.md`). Репозиторий Cloudsmith для apt ненадёжен, поэтому xcaddy ставится через Go (уже установлен на шаге 2):

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/mholt/caddy-l4 --with github.com/caddy-dns/cloudflare \
  --output /usr/local/bin/caddy
```

Если TLS passthrough и Cloudflare DNS-01 не нужны — достаточно пакетного Caddy (`sudo apt install -y caddy`).

## 4. Сборка и установка vs-router

Node.js (для сборки UI) и uv (для backend):

```sh
sudo apt install -y nodejs npm   # Debian 13: nodejs >= 18
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Сборка:

```sh
git clone https://github.com/poshl9k/software-routing-software.git
cd software-routing-software
(cd frontend && npm install && npm run build)   # dist → отдаётся бэкендом
(cd backend && uv build)                         # wheel в backend/dist/
sudo pip install --break-system-packages backend/dist/vs_router_backend-*.whl
```

## 5. Секреты

Ключ шифрования секретов (Fernet) — обязателен до первого запуска:

```sh
sudo install -d -m 0700 /etc/vs-router
echo "VS_ROUTER_SECRET_KEY=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" \
  | sudo tee /etc/vs-router/secrets.env
sudo chmod 0600 /etc/vs-router/secrets.env
```

Файл подключён к сервисам web и agent через `EnvironmentFile`. Дополнительные переменные (опционально):

| Переменная | Назначение |
|---|---|
| `VS_ROUTER_KEA_API_USER` / `VS_ROUTER_KEA_API_PASSWORD` | basic-auth к Kea ctrl-agent (live-аренды). Имя/пароль берутся из `/etc/kea/kea-ctrl-agent.conf` и `/etc/kea/kea-api-password` |
| `VS_ROUTER_COOKIE_SECURE=0` | только для лабы с plain-HTTP доступом к панели; в проде панель за HTTPS — не задавать |
| `VS_ROUTER_AGENT_SOCKET`, `VS_ROUTER_PANEL_SOCKET`, `VS_ROUTER_KEA_CTRL_URL` | пути/адреса IPC, дефолты разумны |

## 6. install.sh

```sh
cd backend/packaging
sudo ./install.sh
```

Скрипт создаёт пользователей (`vs-router-web`, root-агент отдельно), каталоги `/etc/vs-router/{applied,confirmed}` (группа web — запись, агент читает/пишет), БД с миграциями Alembic, профили AppArmor для kea/unbound, деплоит UI в `/var/lib/vs-router/ui` (если `../frontend/dist` существует), включает `vs-router-bootrestore.service` (восстановление конфигураций при загрузке до старта сети) и делает `daemon-reload`.

Предупреждение о версии AmneziaWG (<3.1) появится здесь, если шаг 2 пропущен.

## 7. Kea ctrl-agent (live-аренды в UI)

Генерируемые Kea-конфиги включают hooks `lease_cmds`/`stat_cmds`. Для авторизации ctrl-agent создайте пароль:

```sh
echo "vsr-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')" | sudo tee /etc/kea/kea-api-password
sudo chmod 0640 /etc/kea/kea-api-password && sudo chown root:_kea /etc/kea/kea-api-password
sudo systemctl restart kea-ctrl-agent kea-dhcp4-server
```

Логин/пароль передайте в web-сервис (см. таблицу в п.5 — через `secrets.env` или drop-in `vs-router-web.service.d`).

## 8. Первый запуск и доступ к панели

1. Запустите сервисы: `sudo systemctl enable --now vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer`
2. При первом входе панель предложит **onboarding**: учётка администратора (`/api/setup` работает, пока таблица пользователей пуста), базовая сеть, выбор «безопасной настройки» (окно подтверждения с автооткатом).
3. Доступ:
   - **Лаба**: `sudo systemctl enable --now vs-router-web-tcp.service` (порт 8080, plain HTTP). Firewall по умолчанию режет всё с WAN, кроме SSH — правило для 8080 добавьте **в самой панели** (Правила → правило `pass tcp/8080` на зоне wan → Применить).
   - **Прод**: HTTPS-прокси (Caddy) → unix socket `/run/vs-router/web/web.sock`; cookie `Secure` остаётся включённым.

## 9. Проверка установки

```sh
systemctl is-active vs-router-web vs-router-agent vs-router-rollback.timer
sudo ls /run/vs-router/agent.sock /run/vs-router/web/web.sock
curl -s http://127.0.0.1:8080/health            # через tcp-bridge или прокси
```

Цикл применения: правьте конфигурацию в UI → «Сохранить черновик» → «Проверить» (валидаторы `nft -c`, `unbound-checkconf`, `kea-dhcp4 -t`, `caddy validate`) → «Применить» → «Подтвердить». При включённой «безопасной настройке» неподтверждённое применение откатится само.

## 10. Известные особенности

- `systemd-networkd` в Debian не активен по умолчанию — при отсутствии генератор сетевых файлов просто раскладывает их, применение не падает (обёртка устойчива).
- `host_cmds` (hook Kea) в пакете Debian отсутствует — резервации только через конфиг-файл (наша модель так и устроена).
- Туннели — userspace (производительность ниже kernel-WG); kernel-модуль AmneziaWG — после MVP.
- Ядро обновляется только по уязвимостям; после обновления — проверка туннелей (см. план, «Обновления»).
- Сессии панели in-memory: рестарт `vs-router-web` сбрасывает входы.
- Бэкап: `GET /api/backup/export` (экран «Обслуживание»); без пароля секреты в экспорте — маркеры.
