# vs-router installer ISO

Сборка из корня репозитория (нужны `xorriso`, `isolinux` и интернет для загрузки ISO, если его ещё нет):

```sh
sudo apt install xorriso isolinux
bash installer/make-iso.sh
```

Скрипт берёт `/var/lib/libvirt/images/debian-13.7.0-amd64-netinst.iso` или скачивает образ Debian 13.7 netinst в `/tmp`. Можно передать другой ISO первым аргументом. Результат: `vs-router-installer-13.7.0-amd64.iso`.

Загрузите компьютер или VM с полученного ISO и подключите сеть с доступом в интернет. Установка Debian и запуск bootstrap выполнятся автоматически; сеть нужна для загрузки bootstrap и пакетов/исходников. В конце откройте панель на порту **8080**. Учетная запись системы: **vsr-admin / vsr-install**, для неё настроен `sudo NOPASSWD`. Лог bootstrap: `/root/bootstrap.log`.
