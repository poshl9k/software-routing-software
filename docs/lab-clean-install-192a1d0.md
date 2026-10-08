# Чистая установка installer-ISO на disposable VM — 2026-10-09

Прогон закрывает путь «installer ISO → firstboot-bootstrap → management LAN» на
**локальном, неопубликованном** коммите `192a1d0ab436cf96e7d640326f45840b69d86964`
(ADR-0008 self-contained image, ADR-0005).

## Сборка образа (без push)

`make-iso.sh` вендорит `git archive` ревизии — публикация в remote не нужна. Собрано
из **локального клона** (`git clone --local`), т.к. `REPO_ROOT` выводится из места
скрипта:

```
cp-клон → правка клона installer/preseed.cfg: +qemu-guest-agent в pkgsel/include
VS_ROUTER_UNATTENDED_LAB=1 VS_ROUTER_TEST_POWER_OFF=1 \
VS_ROUTER_REVISION=192a1d0… VS_ROUTER_ISO_SHA256=a7ef94ac… \
OUT=~/VMs/vsr-clean-192a1d0.iso bash installer/make-iso.sh <debian-13.7.0-netinst.iso>
```

Проверено в образе: `poweroff boolean true`, `pkgsel/include` содержит
`qemu-guest-agent`, `late_command` копирует `/cdrom/vs-router/{source.tar.gz,sha256.txt,
REVISION,install-source.sh}` (self-contained).

## Установка

BIOS/isolinux-меню **не** авто-стартует установку (`isolinux.cfg: timeout 0`), а по
истечении ждёт-таймера уходит в speech-synthesis (звуковой карты нет) — тупик. Поэтому
использован **прямой kernel-boot**: `vmlinuz`+`initrd.gz` из ISO + cmdline
`auto=true priority=critical preseed/file=/cdrom/preseed.cfg file=/cdrom/preseed.cfg …`
и cdrom подключён (для `/cdrom`). Установка прошла без вопросов, диск 1.53 GiB, d-i
выключил ВМ (`VS_ROUTER_TEST_POWER_OFF`).

Затем домен переопределён без `kernel/initrd/cmdline` и без cdrom, boot `hd`.

## Проверки (verified)

- `cat /etc/os-release` → Debian 13 trixie; `/opt/vs-router/REVISION` = `192a1d0…`;
  `.git` отсутствует (self-contained); `/etc/vs-router/version.json` `source=iso`.
- `installer-uplink` = `enp1s0 52:54:00:cc:00:01`; bootstrap `succeeded`;
  `vs-router-agent/web/caddy` — active; `unbound` — active.
- Фикс «include только после apply»: `/etc/unbound/unbound.conf.d/` **без**
  `vs-router.conf` до первого apply.
- `management_console --mac 52:54:00:cc:00:02 --address 192.168.10.1/24` (через
  `script -qec … /dev/null`) → `Local HTTPS check passed: https://192.168.10.1/`,
  CA SHA-256 `ef:1e:9d:88:…`.
- LAN: `https://192.168.10.1/` = 200, `/health` = `{"status":"ok"}`,
  `<title>vs-router — Панель управления</title>`. WAN (NAT-адрес): 443 → 000, SSH 22 closed.
- После reboot: сервисы active, LAN 200 / WAN denied сохраняются, boot-restore
  восстанавливает `table inet vs_router`.

## Дефект, найденный и исправленный

**Симптом:** после установки uplink нёс **два** IPv4-адреса (`.197` от networkd,
`.198` от dhcpcd) и два default-маршрута; после reboot — снова два адреса.

**Корень (доказан журналом):** `stage_networkd` отключает `networking.service`, но
оставляет в `/etc/network/interfaces` строку `allow-hotplug enp1s0`. Udev-правило
`80-ifupdown.rules` запускает `ifup` для `auto`/`allow-hotplug` интерфейсов при
link-up **независимо** от `networking.service`, поэтому на каждом boot dhcpcd брал
второй адрес (`journalctl`: `ifup[688]: enp1s0: leased 192.168.122.198`).

**Фикс** (`backend/packaging/bootstrap.sh`, `stage_networkd`): после успешной миграции
для uplink удаляются строки `auto`/`allow-hotplug` (сам блок `iface` сохранён, чтобы
предусловие миграции держалось при rerun; бэкап — `/etc/network/interfaces.vs-router-backup`).

**Проверка фикса на этой же ВМ:** после правки и reboot — `ifup` не запускался
(0 совпадений в журнале), на `enp1s0` **один** адрес, один default-route; LAN/WAN
инварианты сохранены.

## Артефакты

- ISO: `~/VMs/vsr-clean-192a1d0.iso`; домен `vsr-clean-192a1d0` (WAN = NAT `default`,
  управление = host-only `vsr-verify-lan`).
