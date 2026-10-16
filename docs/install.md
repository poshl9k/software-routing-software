# Установка vs-router на выделенную машину или VM

Целевая система: **Debian 13 (trixie)**, amd64. Ресурсы: минимум 2 vCPU / 2 ГБ RAM / 16 ГБ диска (рекомендуется 4/4/20). Проверено на тестовой VM — см. `docs/lab-04` и историю чистой установки.

Панель управляет сетью, firewall'ом, DHCP, DNS, туннелями, прокси и DDNS без правки конфигов руками. Все изменения проходят цикл: черновик → проверка → применение → подтверждение.

## Quick start (одна команда на чистой машине)

Альтернатива: соберите ISO командой `bash installer/make-iso.sh`.
Сборка требует проверенного SHA-256 ISO Debian 13 и полного commit ID. Обычный ISO запрашивает пароль ОС; SSH маскирован по правилам установки. Текущие ограничения и явный lab-режим — в `installer/README.md`. Целевой первый доступ через меню локальной консоли описан ниже; реализация меню и VM-проверка этого контура ещё не завершены.

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

Отдельный install-time шаг `backend/packaging/bootstrap.sh` (`stage_singbox`, скрипт `install-singbox.sh`) доставляет закреплённый по ADR-0012 бинарник sing-box в `/usr/local/lib/vs-router/sing-box`: скачивание по пиннутому URL, сверка SHA256 архива, ELF и `libcronet.so`, проверка `version`/`Revision`, установка обоих файлов с владельцем root. SHA256 библиотеки закреплён в `backend/packaging/singbox-libcronet.sha256` (`23109c55b08829bb1a68682a61a64852b1bbf243753b153cbd8f6e4ea2c05294`); для локального проверенного зеркала путь к манифесту можно задать через `VS_ROUTER_SINGBOX_LIBCRONET_MANIFEST`. Установка при обновлении также проверяет оба файла, а агент проверяет их SHA256 перед запуском. Шаг идемпотентен и fail-closed; повторный запуск не трогает сеть. Подробности — `docs/lab-35-pinned-binary-and-apparmor.md`.

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

**Целевой первый доступ (по аналогии с pfSense):** после установки перезагрузите машину. При загрузке на `tty1` должно открыться локальное консольное меню: назначьте физические WAN и LAN, задайте статический IP/префикс LAN (адрес выбирается, не фиксирован), затем выберите «Сохранить и применить». Подключите компьютер к выбранному LAN, вручную задайте ему свободный адрес той же подсети и откройте `https://<выбранный-IP-LAN>/`. Сверьте отпечаток CA с консолью до добавления доверия. Не назначайте uplink установщика как LAN. DHCP-сервер до первого apply не включён.

**Текущее ограничение:** это проектный сценарий из `docs/console-menu.md` (в основном репозитории); модуль `vs_router.agent.console_menu` пока отсутствует; подготовленный unit для `tty1` сам по себе меню не запускает. Поэтому автоматический доступ к меню и LAN HTTPS после перезагрузки не подтверждён; VM-проверка не сделана. Не используйте этот текст как подтверждение готовности установки.

1. Запустите сервисы: `sudo systemctl enable --now vs-router-agent vs-router-web vs-router-rollback.timer vs-router-ddns.timer`
2. После появления LAN HTTPS при первом входе панель предложит **onboarding**: учётка администратора (`/api/setup` работает, пока таблица пользователей пуста), базовая сеть, выбор «безопасной настройки» (окно подтверждения с автооткатом).
3. Доступ:
   - HTTPS-прокси (Caddy) → unix socket `/run/vs-router/web/web.sock`; cookie `Secure` остаётся включённым. SSH остаётся маскированным, пока штатные правила доступа не разрешат его.

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

## Первичный management LAN: меню локальной консоли (проектный сценарий)

После reboot/boot локальная root-консоль `tty1` должна показывать меню, как у
pfSense: `1) Assign interfaces (WAN/LAN)` → `2) Set interface IP address` →
`5) Save and apply`. Меню намеренно на английском: консольный шрифт установленного
образа не имеет кириллицы, и русские подписи выводились мусором. Выберите отдельный физический порт для LAN (не uplink
установщика), укажите статический IP/префикс выбранного LAN. Адрес не закреплён
установщиком: выбирайте подходящую подсеть без пересечения с WAN. После
применения проверьте адрес панели и отпечаток CA на консоли. Компьютеру в LAN
назначьте свободный адрес той же подсети вручную; откройте
`https://<выбранный-IP-LAN>/`. DHCP-сервер до первого apply не включён.
Проверьте доступ с LAN и отсутствие доступа с WAN: локальная HTTPS-проба
не доказывает сетевую доступность.

Меню задумано только для локального root TTY, не для SSH. Дизайн —
`docs/console-menu.md` основного репозитория. Пока модуль меню отсутствует,
сценарий не работает автоматически даже при наличии `vs-router-console.service`;
VM-проверка reboot → меню → LAN HTTPS не выполнена. SSH при установке маскируется;
доступ регулируется штатными правилами, а не открывается для входа в меню.

Существующий ограниченный контур management сохраняет идентичность выбранного
LAN (имя/MAC) в root-only `/var/lib/vs-router-bootstrap/management.json`;
несовпадение блокирует загрузку Caddy и восстановление правил. Сертификат с IP SAN
выдаётся локальным RSA-3072 CA; приватный ключ CA хранится root-only (каталог
0700, файл 0600), публичный — `/etc/caddy/management/ca.crt`. Сверяйте
отпечаток с консолью перед добавлением доверия на компьютере администратора.

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

Осталось: реализация и VM-проверка консольного меню; транзакционная миграция
management endpoint и сертификата; автоматическое продление сертификата
(серверный сертификат действует 397 дней); испытания чистой Debian 13 VM,
reboot/rollback и доступ с настоящих LAN/WAN клиентов. `/api/setup` pairing
не изменён. Проверки на временных деревьях не заменяют эти VM-испытания.

## Онлайн-установка на VPS с одним NIC (ADR-0017)

`backend/packaging/online-install.sh` ставит панель на хост, к которому есть
только сетевой доступ. В отличие от ISO-пути он **не трогает sshd и порт 22**:
у установщика нет локальной консоли, и fail-closed SSH был бы необратим.
Порядок:

1. ставит `nftables`, `unbound`, `kea`, `ppp`, `fail2ban`, Go/Node и прочее;
2. собирает `amneziawg-go`/`awg` и Caddy с модулем L4 (`xcaddy`);
3. ставит зависимости панели и wheel, кладёт статику в `/var/lib/vs-router/ui`;
4. запускает `install.sh` с `VS_ROUTER_KEEP_SSH=1` (пропускает маскирование SSH,
   drop-in `ssh.service.d/vs-router.conf` и `/etc/vs-router-ssh`);
5. провизионит режим `single-uplink` (`management_console --single-uplink`);
6. проверяет, что `sshd` активен, `:22` слушает и таблицы `vs_router_ssh_lock` нет.

```sh
sh packaging/online-install.sh \
  --wheel vs_router_backend-0.1.0-py3-none-any.whl \
  --ui dist \
  --hostname <ip>.nip.io \
  --ssh-port 22
```

Открытые порты на одноруком хосте: `443` (панель), `80` (ACME HTTP-01 и
редирект; нужен и для продления) и SSH. Пока нет первого apply, действует
временный набор `vs_router`; при первом apply его заменяет генерируемый правилами
снимок. Запись `Management.path_prefix` публикует панель по секретному пути, а
корень отдаёт 404; `/health` остаётся вне префикса.

Свой домен панели можно привязать позже — из самой панели («Обслуживание → Домен
панели», ADR-0025): агентом записывается `custom_hostname` в `management.json`
рядом с резервным `hostname` (`<ip>.nip.io`), Caddy перегенерируется и выпускает
сертификаты Let's Encrypt для обоих имён, а правило `:80` добавляется в
применённый nftables, пока есть хоть одно публичное имя. Панель отвечает по обоим
адресам — потеря одного не уводит администратора. Операция транзакционная: если
свой домен не разрешается или сертификат не выдаётся, прежний адрес панели
сохраняется.

`/etc/vs-router/online-install` пишется до первого старта агента: `SSHController`
считает его достаточным основанием не включать fail-closed контур, поскольку на
момент запуска записи `management.json` ещё нет.

Проверено вживую (Debian 13, один NIC, `92.51.36.131`): сертификат Let's Encrypt
по HTTP-01 для `<ip>.nip.io`, редирект `80 → 443`, `/health` → `200`, SPA и
`/assets/*` отдаются, `/api/auth/login` без сессии → `401`, SSH не тронут.
