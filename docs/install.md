# Установка vs-router на выделенную машину или VM

Целевая система: **Debian 13 (trixie)**, amd64. Ресурсы: минимум 2 vCPU / 2 ГБ RAM / 16 ГБ диска (рекомендуется 4/4/20). Проверено на тестовой VM — см. `docs/lab-04` и историю чистой установки.

Панель управляет сетью, firewall'ом, DHCP, DNS, туннелями, прокси и DDNS без правки конфигов руками. Все изменения проходят цикл: черновик → проверка → применение → подтверждение.

## Quick start (одна команда на чистой машине)

Альтернатива: соберите ISO командой `bash installer/make-iso.sh`.
Сборка требует проверенного SHA-256 ISO Debian 13 и полного commit ID. Обычный ISO запрашивает пароль ОС; SSH закрыт. Текущие ограничения и явный lab-режим — в `installer/README.md`. Для первичного LAN HTTPS после установки требуется отдельная команда с локальной консоли (см. ниже); VM-проверка этого контура ещё не выполнена.

Debian поставляется **без sudo** — сначала один раз через root:

```sh
su -c 'apt update && apt install -y sudo git && usermod -aG sudo $USER'
# выйдите и войдите заново, чтобы применилась группа sudo, затем:
git clone https://github.com/poshl9k/software-routing-software.git
cd software-routing-software/backend/packaging
sudo ./bootstrap.sh
```

Bootstrap поддерживает только Debian 13. Python runtime-зависимости закреплены версиями и SHA-256 wheel-хешами для проверенной цели amd64 / CPython 3.13. Версии Node.js 20.19.2, npm 9.2.0 и Go toolchain 1.25.1 проверяются перед сборкой. Пакеты Debian, включая базовый набор Debian Installer, берутся из подписанного snapshot `20261002T000000Z`: production и lab preseeds закрепляют зеркало, updates и security. Проверка срока действия отключается только для неизменяемых snapshot-записей. Исходные APT-источники установленной системы bootstrap не меняет. Официальный netinst ISO проверен по detached-подписи Debian CD и SHA-256; полный ISO-install ещё нужно подтвердить на чистой VM.

## 1. Системные пакеты

Команды ниже — ручной путь для разработки и диагностики; они используют текущие APT-репозитории и не воспроизводят зафиксированный выпуск. Для установки по выпуску используйте `bootstrap.sh` выше.

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
git init wireguard-go && cd wireguard-go
git fetch --depth 1 https://github.com/WireGuard/wireguard-go ecfc5a8d54462e18e13c72173e2623d16d8e25a0
git checkout --detach FETCH_HEAD
make && sudo cp wireguard-go /usr/local/bin/wg-go
```

AmneziaWG — **версия 3.1+** (параметры обфускации и профили валидированы на 3.1):

```sh
git clone --branch v3.1.20260812 https://github.com/amnezia-vpn/amneziawg-go && cd amneziawg-go
make && sudo cp amneziawg-go /usr/local/bin/
git clone --branch v3.1.20260812 https://github.com/amnezia-vpn/amneziawg-tools && cd ../amneziawg-tools
cd src && make && sudo cp awg awg-quick /usr/local/bin/
```

Подробности и проверенный паттерн запуска (`awg-go <iface>` + `awg setconf`) — `docs/lab-02-amneziawg.md`.

## 3. Caddy с L4 (TLS passthrough) и DNS-провайдерами

Пакетный Caddy не содержит L4-модуль — собирается через xcaddy (см. `docs/lab-03-caddy.md`). Репозиторий Cloudsmith для apt ненадёжен, поэтому xcaddy ставится через Go (уже установлен на шаге 2):

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7
xcaddy build v2.11.4 \
  --with github.com/mholt/caddy-l4@v0.1.2 \
  --with github.com/caddy-dns/cloudflare@v0.2.4 \
  --output /usr/local/bin/caddy
```

Если TLS passthrough и Cloudflare DNS-01 не нужны — достаточно пакетного Caddy (`sudo apt install -y caddy`).

## 4. Сборка и установка vs-router

Node.js (для сборки UI) и uv (для backend):

```sh
sudo apt install -y nodejs npm   # Проверено на Debian 13: Node 20.19.2, достаточно для Vite 7
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Сборка:

```sh
git clone https://github.com/poshl9k/software-routing-software.git
cd software-routing-software
(cd frontend && npm ci && npm run build)   # dist → отдаётся бэкендом
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
| `VS_ROUTER_AGENT_SOCKET`, `VS_ROUTER_PANEL_SOCKET`, `VS_ROUTER_KEA_CTRL_URL` | пути/адреса IPC, дефолты разумны |

## 6. install.sh

```sh
cd backend/packaging
sudo ./install.sh
```

Скрипт создаёт пользователей (`vs-router-web`, root-агент отдельно), каталоги `/etc/vs-router/{applied,confirmed}` (группа web — запись, агент читает/пишет), БД с миграциями Alembic, профили AppArmor для kea/unbound, деплоит UI в `/var/lib/vs-router/ui` (если `../frontend/dist` существует), включает `vs-router-bootrestore.service` (восстановление конфигураций при загрузке до старта сети) и делает `daemon-reload`.

Профиль Unbound получает локальный оверрайд `/etc/apparmor.d/local/usr.sbin.unbound` с каталоговым правилом `/etc/vs-router/applied/** r,`, чтобы ограниченный Debian-профиль `usr.sbin.unbound` разрешал сгенерированные конфиги (в т.ч. split-конфиги TProxy DNS-контура, ADR-0014). Заголовочный `#include <local/usr.sbin.unbound>` — активная директива AppArmor, поэтому локальный файл создаётся перед `apparmor_parser -r`.

Отдельный install-time шаг `backend/packaging/bootstrap.sh` (`stage_singbox`, скрипт `install-singbox.sh`) доставляет закреплённый по ADR-0012 бинарник sing-box в `/usr/local/lib/vs-router/sing-box`: скачивание по пиннутому URL, сверка SHA256 архива и ELF, проверка `version`/`Revision`, установка. Шаг идемпотентен и fail-closed; повторный запуск не трогает сеть. Подробности — `docs/lab-35-pinned-binary-and-apparmor.md`.

Предупреждение о версии AmneziaWG (<3.1) появится здесь, если шаг 2 пропущен.

## 7. Kea ctrl-agent (live-аренды в UI)

Генерируемые Kea-конфиги включают hooks `lease_cmds`/`stat_cmds`. Для авторизации ctrl-agent создайте пароль:

```sh
sudo python3 -c 'import os,secrets; os.umask(0o077); open("/etc/kea/kea-api-password", "x").write(secrets.token_urlsafe(32) + "\n")'
sudo chmod 0640 /etc/kea/kea-api-password && sudo chown root:_kea /etc/kea/kea-api-password
sudo systemctl restart kea-ctrl-agent kea-dhcp4-server
```

Bootstrap передаёт пароль через systemd `LoadCredential` и путь `%d/kea-api-password` в `VS_ROUTER_KEA_API_PASSWORD_FILE`. Не помещайте пароль в открытый drop-in и не выводите его в журнал.

## 8. Первый запуск и доступ к панели

**Первичный доступ:** bootstrap не назначает LAN автоматически. Сначала выполните консольную команду из раздела «Первичный management LAN» ниже и проверьте доступ с LAN.

1. Запустите сервисы: `sudo systemctl enable --now vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer`
2. При первом входе панель предложит **onboarding**: учётка администратора (`/api/setup` работает, пока таблица пользователей пуста), базовая сеть, выбор «безопасной настройки» (окно подтверждения с автооткатом).
3. Доступ:
   - HTTPS-прокси (Caddy) → unix socket `/run/vs-router/web/web.sock`; cookie `Secure` остаётся включённым.

## 9. Проверка установки

```sh
systemctl is-active vs-router-web vs-router-agent vs-router-rollback.timer
sudo ls /run/vs-router/agent.sock /run/vs-router/web/web.sock
```

Цикл применения: правьте конфигурацию в UI → «Сохранить черновик» → «Проверить» (валидаторы `nft -c`, `unbound-checkconf`, `kea-dhcp4 -t`, `caddy validate`) → «Применить» → «Подтвердить». При включённой «безопасной настройке» неподтверждённое применение откатится само.

## 10. Известные особенности

- `systemd-networkd` в Debian не активен по умолчанию — при отсутствии генератор сетевых файлов просто раскладывает их, применение не падает (обёртка устойчива).
- `host_cmds` (hook Kea) в пакете Debian отсутствует — резервации только через конфиг-файл (наша модель так и устроена).
- Туннели — userspace (производительность ниже kernel-WG); kernel-модуль AmneziaWG — после MVP.
- Ядро обновляется только по уязвимостям; после обновления — проверка туннелей (см. план, «Обновления»).
- Сессии панели in-memory: рестарт `vs-router-web` сбрасывает входы.
- Бэкап: `GET /api/backup/export` (экран «Обслуживание»); без пароля секреты в экспорте — маркеры.

## Первичный management LAN (реализованный ограниченный контур)

После установки ПО, **из локальной root-консоли**, определите MAC отдельного
проводного физического порта через `ip link` и выполните:

```sh
python3 -m vs_router.agent.management_console --mac <фактический-MAC-LAN> --address 192.168.10.1/24
```

Адрес можно изменить при первом запуске команды. Uplink установщика нельзя
выбирать как LAN; требуется минимум два физических проводных порта. Имя и MAC
сохраняются в root-only `/var/lib/vs-router-bootstrap/management.json`.
Повтор той же команды до apply сохраняет CA и ключи. Несовпадение идентичности
блокирует загрузку Caddy и восстановление правил; исправление требует консоли.

Команда создаёт RSA-3072 CA и серверный сертификат с IP SAN, печатает SHA-256
отпечаток CA, проверяет запуск сервисов и локальный HTTPS с проверкой доверия.
CA private key хранится отдельно, root-only (0700 каталог / 0600 файл).
Публичный CA находится в `/etc/caddy/management/ca.crt`; сверяйте его отпечаток
с консолью перед добавлением доверия на компьютере администратора.

На компьютере администратора вручную назначьте свободный адрес той же подсети
(например, `192.168.10.2/24`) и откройте `https://192.168.10.1/`.
Локальная HTTPS-проба **не подтверждает доступ из LAN**: отдельно проверьте
доступ с LAN и отсутствие доступа с WAN. DHCP до первого apply не включается.

Первый черновик должен содержать точные имя LAN, статический адрес/префикс,
тип physical и зону lan, panel_port=443. Первое применение не имеет автоотката;
ошибка не создаёт искусственную confirmed-версию. HTTPS-маршрут остаётся даже
при пустом списке сайтов. Неявные wildcard listener сайтов и конфликтующие
port forwards запрещены. После confirmed изменения параметров выбранного LAN
принудительно включают таймер. Перенос самого endpoint (имя/адрес/порт) пока
**запрещён**, а не реализован как безопасная миграция.
Если запись о LAN с локальной консоли отсутствует, агент отвергает применение
до любых изменений (`management.assignment_required`). Работоспособный Unix-сокет
web-сервиса не заменяет проверку HTTPS на назначенном management-адресе.
При первом применении без подтверждённой версии агент проверяет этот HTTPS
**до** изменения системы: если панель уже недоступна, первый apply отвергается
без попытки отката к несуществующей версии. Локальная проверка агента не заменяет
отдельную проверку доступа с компьютера в LAN.
Если HTTPS-probe агента не подключён, первый apply также отвергается до записи
файлов: отсутствие проверки не считается успешным результатом.

Осталось: SSH UI/модель/защита WAN/служба и её откат; транзакционная миграция
management endpoint и сертификата; автоматическое продление сертификата
(серверный сертификат действует 397 дней); испытания чистой Debian 13 VM,
reboot/rollback и доступ с настоящих LAN/WAN клиентов. `/api/setup` pairing
не изменён. Проверки на временных деревьях не заменяют эти VM-испытания.
