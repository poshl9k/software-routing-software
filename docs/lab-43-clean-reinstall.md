# Lab 43 — чистая переустановка VM из ISO

## Область и исходники

Только disposable libvirt VM; сеть хоста не менялась, `sudo` и `git push` не применялись. Исходный домен `vsr-clean-192a1d0` был работающим, с двумя NIC: `default` (WAN, MAC `52:54:00:cc:00:01`) и `vsr-verify-lan` (bridge `virbr-vsr`, management, MAC `52:54:00:cc:00:02`). Перед выключением создан внешний disk snapshot `pre-lab43-reinstall`; старые `pre-pppoe-lab42`, `pre-pppoe-wave-c` и **`pre-tproxy-1791616579`** не удалены. Старый домен и вся его цепочка дисков оставлены выключенными, а не уничтожены.

```text
git -C /home/poshl9k/GitHub/software-routing-software rev-parse HEAD
16e76bf39c4135138b6065401ebc97753565a738
git ls-remote origin refs/heads/main
16e76bf39c4135138b6065401ebc97753565a738 refs/heads/main
git status --short
<пусто до работы>
sha256sum /home/poshl9k/Загрузки/debian-13.7.0-amd64-netinst.iso
a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355  /home/poshl9k/Загрузки/debian-13.7.0-amd64-netinst.iso
```

Контрольная сумма базового ISO повторно вычислена; detached-подпись Debian в этом прогоне отдельно не проверялась. Исходный ISO уже находился на хосте.

## ISO и чистый диск

```sh
git clone --local --no-hardlinks /home/poshl9k/GitHub/software-routing-software /home/poshl9k/.hermes/cache/scratch/vsr-lab43-repo
git -C /home/poshl9k/.hermes/cache/scratch/vsr-lab43-repo checkout --detach 16e76bf39c4135138b6065401ebc97753565a738
# Только в копии installer/preseed.cfg: добавить qemu-guest-agent к pkgsel/include.
cd /home/poshl9k/.hermes/cache/scratch/vsr-lab43-repo
env -u PYTHONPATH VS_ROUTER_REVISION=16e76bf39c4135138b6065401ebc97753565a738 VS_ROUTER_ISO_SHA256=a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355 VS_ROUTER_UNATTENDED_LAB=1 VS_ROUTER_TEST_POWER_OFF=1 OUT=/home/poshl9k/VMs/vsr-clean-16e76bf.iso bash installer/make-iso.sh /home/poshl9k/Загрузки/debian-13.7.0-amd64-netinst.iso
chmod 0644 /home/poshl9k/VMs/vsr-clean-16e76bf.iso
xorriso -osirrox on -indev /home/poshl9k/VMs/vsr-clean-16e76bf.iso -extract /preseed.cfg /home/poshl9k/.hermes/cache/scratch/vsr43-preseed.cfg -extract /vs-router/REVISION /home/poshl9k/.hermes/cache/scratch/vsr43-revision -extract /install.amd/vmlinuz /home/poshl9k/VMs/vsr43-vmlinuz -extract /install.amd/initrd.gz /home/poshl9k/VMs/vsr43-initrd.gz
qemu-img create -f qcow2 /home/poshl9k/VMs/vsr-clean-16e76bf.qcow2 20G
```

`make-iso.sh`: `...netinst.iso: OK`, `Vendored release 16e76bf39c4135138b6065401ebc97753565a738 (2.3M)`, `Created /home/poshl9k/VMs/vsr-clean-16e76bf.iso`. SHA-256 готового ISO: `db24bc67b47249711af0516507256a27339fffeab9775a691e7d72fef33e8bbb`.

Извлечённый `/preseed.cfg` проверен **до установки**:

```text
d-i pkgsel/include string curl ca-certificates sudo git nftables qemu-guest-agent
d-i debian-installer/exit/poweroff boolean true
d-i preseed/late_command string mkdir -p /target/opt/vs-router && cp /cdrom/vs-router/source.tar.gz /cdrom/vs-router/sha256.txt /cdrom/vs-router/REVISION /cdrom/vs-router/install-source.sh /target/opt/vs-router/ && in-target sh /opt/vs-router/install-source.sh
/vs-router/REVISION: 16e76bf39c4135138b6065401ebc97753565a738
```

Итак, `late_command` копирует и проверяет **вендорный tar**, не клонирует GitHub. Изменения в рабочем дереве не попали в образ; `.git` внутри установленного продукта ожидаемо отсутствует.

## Установка и первый запуск

Создан новый домен `vsr-clean-16e76bf`: отдельный свежий qcow2 (20 GiB), 3072 MiB RAM, 2 vCPU, q35 с `pcie-root` index 0, обе указанные NIC, канал `org.qemu.guest_agent.0`. На первом запуске XML использовал извлечённые из **этого** ISO kernel/initrd и `cmdline`:

```text
auto=true priority=critical preseed/file=/cdrom/preseed.cfg file=/cdrom/preseed.cfg locale=en_US.UTF-8 modprobe.blacklist=mac80211,cfg80211 ---
```

ISO подключён как SATA CD-ROM. `virsh screenshot vsr-clean-16e76bf .../vsr43-install-progress.png` показывал последовательно настройку часов (53%) и установку пакетов (91%); интерактивного запроса не было. Затем:

```text
virsh -c qemu:///system domstate vsr-clean-16e76bf
выключен
qemu-img info /home/poshl9k/VMs/vsr-clean-16e76bf.qcow2
virtual size: 20 GiB (21474836480 bytes)
disk size: 1.53 GiB
corrupt: false
```

Перед следующим `start` домен переопределён: **удалены** kernel, initrd, cmdline и CD-ROM, boot только `hd`; `domblklist` показывает один `vda`. После загрузки guest agent ответил `{"return":{}}`. Наблюдение в госте:

```text
cat /opt/vs-router/REVISION
16e76bf39c4135138b6065401ebc97753565a738
cat /etc/vs-router/version.json
{"commit":"16e76bf39c4135138b6065401ebc97753565a738","semver":"0.1.0","installed_at":"2026-10-10T22:34:45Z","source":"iso"}
cat /var/lib/vs-router-bootstrap/installer-uplink
enp1s0 52:54:00:cc:00:01
test -e /var/lib/vs-router-bootstrap/succeeded && printf 'succeeded\n'
succeeded
grep 'Completed stage' /root/bootstrap.log
... check:_root, firewall, apt:deps, networkd, caddy, awg, singbox, build, install, summary
systemctl is-active vs-router-bootstrap-firstboot.service
inactive
systemctl is-active vs-router-web vs-router-agent caddy unbound kea-dhcp4-server
active
active
active
active
active
```

Сразу после bootstrap на WAN были **две** DHCP-аренды (`192.168.122.199` и `.198`): это переход ifupdown → networkd до перезагрузки, не финальный результат. В `/etc/network/interfaces` строка `auto enp1s0` удалена, `iface enp1s0 inet dhcp` осталась. После `virsh reboot`:

```text
ip -4 -br addr show enp1s0
enp1s0 UP 192.168.122.198/24 metric 1024
ip -4 route show default
default via 192.168.122.1 dev enp1s0 proto dhcp src 192.168.122.198 metric 1024
journalctl -b --no-pager -g 'ifup\[|leased ' -o cat
<нет записей ifup/второй аренды; только след вызова guest-exec с самой командой>
```

Это WAN в libvirt `default` NAT, **не** внешняя сеть оператора.

Management назначен на отдельном LAN интерфейсе посредством штатного TTY-guarded пути (не обхода guard):

```sh
# В госте через guest agent:
script -qec 'python3 -m vs_router.agent.management_console --mac 52:54:00:cc:00:02 --address 192.168.10.1/24' /dev/null
```

Вывод: `Local HTTPS check passed: https://192.168.10.1/`, `CA SHA-256: cc:ed:0a:8d:68:97:17:7b:da:9c:1e:5f:30:18:1d:83:ba:05:59:21:5b:d3:bd:ec:8d:f6:a9:18:a2:1c:66:4d`; `script_status=0`. `/var/lib/vs-router-bootstrap/management.json` содержит `{"interface":"enp2s0","mac":"52:54:00:cc:00:02","address":"192.168.10.1/24"}`. Caddy слушает `192.168.10.1:443`, не `0.0.0.0:443`. Публичный CA взят из `/etc/caddy/management/ca.crt`; отпечаток `openssl x509 -fingerprint -sha256` совпал с консольным. С хоста на bridge `virbr-vsr`:

```text
curl --noproxy '*' --cacert <публичный-ca.crt> -o /dev/null -w 'HTTP=%{http_code} verify=%{ssl_verify_result}' https://192.168.10.1/
HTTP=200 verify=0
# Аналогично /health: HTTP=200 verify=0.
curl --noproxy '*' -k --connect-timeout 3 https://192.168.122.198/
Connection timed out after 3002 milliseconds; HTTP=000
```

Второй reboot после назначения management: все пять сервисов `active`, `succeeded` сохранился, LAN `/` и `/health` снова `200 verify=0`, WAN по-прежнему имеет один адрес `.198`, default route сохранён, `/opt/vs-router/REVISION` совпал с pinned. Отдельный физический LAN-клиент не участвовал; проверяющим клиентом выступил хост через `virbr-vsr`.

## Чистая исходная конфигурация и откат

На новой VM: в SQLite `users=0`, `configuration_versions=0`; отсутствуют `/run/vs-router/marker.json`, `/etc/vs-router/confirmed/snapshot.json`, `/etc/vs-router/applied/snapshot.json`, `/etc/vs-router/applied/unbound.conf`, `/etc/unbound/unbound.conf.d/vs-router.conf`, `/var/lib/vs-router-bootstrap/incomplete`, `vs-router-web-tcp.service`, `vs-router-lab-tcp.service`. В `systemctl show vs-router-web -p Environment` нет LAB_MODE или insecure-cookie override. Порт 8000 Kea ctrl-agent — только `127.0.0.1`, Unbound 53 — только loopback. Это исходное состояние **до первого черновика/apply**; проверка первого применения конфигурации не входила в clean-baseline прогон и не проводилась. Не открывали `tproxy.not_available`. `/api/release` без панели-сессии вернул `401`, поэтому выпуск сверялся через root-only `version.json` и `REVISION`.

```text
virsh -c qemu:///system list --all
vsr-clean-16e76bf   работает
vsr-clean-192a1d0   выключен
virsh -c qemu:///system snapshot-current vsr-clean-16e76bf --name
clean-16e76bf-firstboot
virsh -c qemu:///system snapshot-current vsr-clean-192a1d0 --name
pre-lab43-reinstall
```

Новая VM оставлена запущенной. На ней создан внешний disk-only снимок `clean-16e76bf-firstboot`. Для быстрого отката к старой машине: выключить новую `virsh -c qemu:///system shutdown vsr-clean-16e76bf` и запустить старую `virsh -c qemu:///system start vsr-clean-192a1d0` (обе VM используют одинаковые MAC и management IP, **не запускать одновременно**). Старый домен оставлен с собственными диск-цепочкой и метаданными snapshot; `pre-tproxy-1791616579` сохранён, но **не является состоянием новой чистой VM**. Внешний libvirt disk-snapshot не обещает автоматического `snapshot-revert`: перед возвратом к более раннему снимку отдельно проверяйте цепочку qcow2. Повторный запуск старой VM восстановит её остаточное состояние, не чистую установку.

Повторно пригодный ISO: `/home/poshl9k/VMs/vsr-clean-16e76bf.iso` (включает lab preseed с известной учёткой; не использовать как production-образ). Временные clone, извлечённые kernel/initrd, preseed, CA и скриншоты удалены после проверки. Хостовых HTTP-серверов не запускали.
