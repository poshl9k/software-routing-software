# vs-router installer ISO

Сборка из корня репозитория (нужны `xorriso`, `isolinux` и интернет для загрузки ISO, если его ещё нет):

```sh
sudo apt install xorriso isolinux
bash installer/make-iso.sh
```

Скрипт берёт `/var/lib/libvirt/images/debian-13.7.0-amd64-netinst.iso` или скачивает образ Debian 13.7 netinst в `/tmp`. Можно передать другой ISO первым аргументом. Результат: `vs-router-installer-13.7.0-amd64.iso`.

Загрузите компьютер или VM с полученного ISO и подключите сеть с доступом в интернет. Установка Debian и запуск bootstrap выполнятся автоматически; сеть нужна для загрузки bootstrap и пакетов/исходников. В конце откройте панель на порту **8080**. Учетная запись системы: **vsr-admin / vsr-install**, для неё настроен `sudo NOPASSWD`. Лог bootstrap: `/root/bootstrap.log`.

## Что получается на выходе

| Компонент | Значение |
|---|---|
| Панель | `http://<ip-машины>:8080` (лабовый tcp-bridge; в проде — HTTPS через Caddy) |
| Учётка ОС | `vsr-admin` / `vsr-install`, sudo NOPASSWD |
| Учётка панели | создаётся в onboarding при первом входе (панель открыта, пока таблица пользователей пуста) |
| Сервисы | `vs-router-agent`, `vs-router-web`, `vs-router-rollback.timer`, `vs-router-ddns.timer`, `vs-router-web-tcp` (лаба), `caddy` |
| Креды Kea ctrl-agent | печатаются в конце bootstrap-лога (и в сводке), user `kea-api` |
| Лог установки | `/root/bootstrap.log` (весь вывод bootstrap) |
| Репозиторий | `/opt/vs-router` (клон, из которого собрано; `git pull` + `sudo ./backend/packaging/bootstrap.sh` для обновления) |
| Требования к сети | DHCP-адрес + интернет во время установки (apt, PyPI, npm, Go-модули); после — как настроите |

## Проверенный статус

Автоустановка (preseed → late_command → bootstrap) проверяется на тестовой VM
(`qemu:///session`, диск 20G, 3 ГБ RAM). Критерий: phone-home `?bootstrap=0`
после завершения без единого интерактивного шага.
