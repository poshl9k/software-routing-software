# vs-router installer ISO

Сборка из корня репозитория (нужны `xorriso`, `isolinux` и интернет для загрузки ISO, если его ещё нет):

```sh
sudo apt install xorriso isolinux
bash installer/make-iso.sh
```

Скрипт берёт `/var/lib/libvirt/images/debian-13.7.0-amd64-netinst.iso` или скачивает образ Debian 13.7 netinst в `/tmp`. Можно передать другой ISO первым аргументом. Результат: `vs-router-installer-13.7.0-amd64.iso`.

Загрузите компьютер или VM с полученного ISO и подключите сеть с доступом в интернет. Установка Debian и запуск bootstrap выполнятся автоматически; сеть нужна для загрузки bootstrap и пакетов/исходников. В конце откройте панель на порту **8080**. Учетная запись системы: **vsr-admin / vsr-install**, для неё настроен `sudo NOPASSWD`. Лог bootstrap: `/root/bootstrap.log`.

**Wi‑Fi:** в авто-режиме Wi‑Fi отключён намеренно: `netcfg/choose_interface=auto` гоняет интерфейсы, wlan часто линкуется раньше Ethernet, и установка умирала на вопросе WPA-пароля («Invalid passphrase»). Авто-запись установщика грузится с `modprobe.blacklist=mac80211,cfg80211` — беспроводные драйверы не поднимаются, netcfg видит только проводные NIC. Это касается только установщика: установленная система загружается со своим cmdline и Wi‑Fi сохраняет. Секреты в ISO не вшиваются; если установку по Wi‑Fi всё же нужно провести, есть аварийный хук `VS_ROUTER_WIFI="essid пароль" bash installer/make-iso.sh` (креды открытым текстом в файле ISO — избегайте; лучше Ethernet или полуавто, где сеть выбирается явно и Wi‑Fi остаётся). Спасение прямо на экране ошибки: Go Back → Execute a shell → `rmmod <wifi-модуль>` (имя через `lspci -k | grep -A3 Network`) → Go Back → продолжить. Учтите: в netinst может не оказаться firmware вашего адаптера — тогда интерфейса не будет в списке вовсе.

## Режимы установки

- **Авто (по умолчанию):** полностью автоматическая установка без вопросов.
- **Полуавто:** выберите в GRUB/isolinux пункт **Semi-automatic install (expert)**. Установщик идёт обычным линейным потоком (priority=high, без главного меню) и спрашивает только: язык, локацию, раскладку клавиатуры, hostname, учётную запись (SSH-креды; пароль задаёте вы) и разметку диска с подтверждением. Значения из preseed предложены как значения по умолчанию. Роли WAN/LAN и настройки роутера задаются в мастере первого запуска веб-панели.

## Что получается на выходе

| Компонент | Значение |
|---|---|
| Панель | `http://<ip-машины>:8080` (лабовый tcp-bridge; в проде — HTTPS через Caddy) |
| Учётка ОС | `vsr-admin` / `vsr-install`, sudo NOPASSWD |
| Учётка панели | создаётся в onboarding при первом входе (панель открыта, пока таблица пользователей пуста) |
| Сервисы | `vs-router-agent`, `vs-router-web`, `vs-router-rollback.timer`, `vs-router-ddns.timer`, `vs-router-web-tcp` (лаба), `caddy` |
| Креды Kea ctrl-agent | печатаются в конце bootstrap-лога (и в сводке), user `kea-api` |
| Лог установки | `/root/bootstrap.log` (весь вывод bootstrap) |
| Репозиторий | `/opt/vs-router` (клон); обновление кода и дистрибутива — `sudo ./backend/packaging/update.sh`; полная переустановка зависимостей/тулчейна — `git pull` + `sudo ./backend/packaging/bootstrap.sh` |
| Требования к сети | DHCP-адрес + интернет во время установки (apt, PyPI, npm, Go-модули); после — как настроите |

## Проверенный статус

Автоустановка (preseed → late_command → первый запуск → bootstrap) проверена end-to-end
на тестовой VM (`qemu:///system`, сеть default/virbr0, диск 20G, 3 ГБ RAM): phone-home
`?bootstrap=0` (честный код возврата), все сервисы active, панель HTTP 200.

Bootstrap выполняется сервисом `vs-router-bootstrap-firstboot.service` при первом
запуске, а не в late_command: в chroot d-i pipelined-скачивания apt воспроизводимо
заклинивают (http-метод крутит CPU без соединений и таймаутов — наблюдено на slirp и
virbr0 NAT); на загруженной системе тот же bootstrap проходит целиком. Тестовые хуки
сборки: `VS_ROUTER_TEST_SEMIAUTO` (грузить полуавто-запись), `VS_ROUTER_PHONEHOME_IP`
(подмена адреса phone-home в staged-копиях preseed), `VS_ROUTER_STATIC_NET` (статическая
сеть вместо DHCP — обход молчаливого DHCP passt).
