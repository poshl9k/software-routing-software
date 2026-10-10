# Lab-41: PPPoE live — отдельный access concentrator

10 октября 2026. Одноразовый `vsr-clean-192a1d0`, ISP `vsr-pppoe-isp41`. Итог: не все критерии выполнены. Ни commit/push, ни sudo, ни изменения сети хоста, ни открытие `tproxy.not_available` не выполнялись. Пароль в отчёте не приводится.

## Стенд и воспроизводимые команды

Команды в гостях: `python3 /home/poshl9k/.hermes/cache/scratch/ui-ux-review/gexec.py <domain> '<shell>'` (qemu guest agent); файлы: `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py <domain> --push <host> <guest>`. Временные скрипты и пароль на хосте после теста удалены.

```
virsh -c qemu:///system snapshot-list vsr-clean-192a1d0
# pre-tproxy-1791616579 disk-snapshot
virsh -c qemu:///system snapshot-create-as vsr-clean-192a1d0 pre-pppoe-wave-c --disk-only --atomic
# Снимок создан
uv build backend --wheel
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# fafcc8d88d1239757b194c295015a57db6a8d362eb18ddf7d82dc6fcbe64f9e0
uv run --project backend --with pytest pytest -q backend/tests/test_pppoe.py backend/tests/test_pppoe_apply.py backend/tests/test_pppoe_boot.py backend/tests/test_pppoe_packaging.py
# 21 passed in 0.21s
```

Libvirt network `vsr-pppoe-lab41`: `<bridge name='virbr-ppp41' stp='off' delay='0'/>`, без `<ip>`, DHCP и NAT. ISP: `qemu-img create -f qcow2 -F qcow2 -b /home/poshl9k/VMs/vsr-clean-192a1d0.qcow2 /home/poshl9k/VMs/vsr-pppoe-isp41.qcow2`; `chgrp kvm`, `chmod 664`; домен `pc-i440fx-10.2`, qemu guest agent, NIC default для установки пакетов и NIC `vsr-pppoe-lab41` (`52:54:00:cc:41:02`). `apt-get install -y pppoe` → `Setting up ppp (2.5.2-1+1)`, `Setting up pppoe (4.0-1)`. AC: `pppoe-server -I enp0s4 -L 10.41.0.1 -R 10.41.0.2 -N 4 -C ISP41`; `/etc/ppp/pppoe-server-options` содержал `require-chap`, `auth`, `name isp41`, `nodefaultroute`. Ранняя ошибка конфигурации AC (`noauth`) была исправлена до значимых проверок отказа. Учётная запись `lab41`, случайный пароль в root-only файлах.

Роутер: `apt-get install -y ppp` → `Setting up ppp (2.5.2-1+1)`; wheel передан по HTTP с management bridge `192.168.10.254:18992`, SHA-256 на госте совпал с host, установлен `python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl`. Из `backend/packaging/` перенесены `vs-router-agent.service` (новый `ReadWritePaths` включает `/etc/ppp`), `vs-router-pppoe@.service`, `vs-router-pppoe-postboot.service`; создан root-only `/etc/ppp/peers`, `systemctl daemon-reload`, `systemctl enable vs-router-pppoe-postboot`, перезапуск agent/web. Полный `install.sh` НЕ запускался — лишь целевое PPPoE provisioning. Начальные RPC до установки нового agent unit возвращали `agent.rollback_failed` из-за отсутствия `/etc/ppp` в `ReadWritePaths`; после обновления unit RPC работал. Router WAN перенесён `virsh detach-interface ... --mac 52:54:00:cc:00:01 --live --config` и `virsh attach-interface ... --source vsr-pppoe-lab41 --mac 52:54:00:cc:00:01 --live --config`. Management NIC `52:54:00:cc:00:02` не трогали.

Draft создавался через `vs_router.api.configuration.validate` → `parse_configuration` → `check_roles` → `materialize_addresses` → SQLAlchemy `ConfigurationRow` commit (эквивалент POST/PUT `/api/draft`, не сырой SQL update). Для шифрования пароля процесс загружал `/etc/vs-router/secrets.env`, в API путь подавался `{'plaintext': password}`; в DB сохранялся encrypted secret. Agent RPC:

```
from vs_router.agent.daemon import UnixSocketTransport
from vs_router.agent.rpc import AgentClient
c = AgentClient(UnixSocketTransport('/run/vs-router/agent.sock'))
c.call('apply_version', {'version_id': 9, 'safe_mode': False})
# {'version_id': 9, 'status': 'confirmed', 'phases': {..., 'pppoe': 'applied'}, ...}
```

## Таблица приёмки

| № | Сценарий | Итог | Наблюдение |
|---|---|---|---|
| 1 | Успешная CHAP/IPCP сессия | PASS до reboot | Draft 8: `CHAP authentication succeeded: Access granted`; `ppp0 10.41.0.5 peer 10.41.0.1/32`, `default dev ppp0`; сервис `vs-router-pppoe@enp1s0 active`, marker `version_id=8 status=confirmed phases.pppoe=applied`. Сразу после apply физический `enp1s0` без IP, `.network` отсутствовал. |
| 2 | Неверный пароль → отказ и автоматический rollback | FAIL | Draft 9 с неверным паролем: RPC вернул `version_id=9 status=confirmed`, `phases.pppoe=applied`, `deadline=null`. Затем журнал: `CHAP authentication failed: Access denied`, `Connection terminated`; `ip`: `Device "ppp0" does not exist`. Маркер остался `confirmed`; автоматического rollback нет. Нужно проверять CHAP/IPCP readiness до подтверждения и откатывать отказ. |
| 3 | PPPoE ↔ static/DHCP | PARTIAL | Из PPPoE в static: draft 10 `confirmed`, `.network` появилась, `enp1s0 10.41.99.2/24`, peer удалён. Затем DHCP draft 11: `.network` содержит `Name=enp1s0`, `DHCP=ipv4`, peer отсутствует. Обратно в PPPoE draft 12: `.network` убрана, peer запущен. Но после реального reboot `.network` с DHCP появилась на `enp1s0` одновременно с `ppp0` (см. №5). |
| 4 | Права и журнал | PASS в проверенном объёме | `stat -c '%a %U:%G %n'`: peer, `chap-secrets`, `pap-secrets` → `600 root:root`; manifest → `600 root:vs-router-web`. Проверка содержания `journalctl -u vs-router-agent -u vs-router-pppoe@enp1s0` на совпадение с паролем → `SECRET_IN_AGENT_OR_PPPD_JOURNAL False`. Секреты не печатались. |
| 5 | Реальный reboot и non-fatal отказ | FAIL штатного packaging; PARTIAL с workaround | После подтверждения draft 12 и `virsh reboot` agent/web active, но postboot и Caddy ожидали `network-online.target`, `ppp0` отсутствовал: `systemd-networkd-wait-online` ждал DHCP на изолированном WAN. Временная гостевая правка postboot unit (`After=vs-router-bootrestore.service network.target`, убрать `Wants=network-online.target`) и второй reboot: oneshot завершился, `ppp0 10.41.0.3 peer 10.41.0.1/32`; agent/web active. Caddy всё равно ждал network-online, позже стал active по timeout. Отдельный reboot при отказе AC не проводился. Штатный критерий НЕ пройден. |
| 6 | Reboot с pending apply | PASS для rollback | От confirmed DHCP draft 11 применён PPPoE draft 12 с `safe_mode=True, confirmation_timeout=600`: RPC `status=pending`, deadline `1791657019.1789453`, `phases.pppoe=applied`. Сразу `virsh reboot`. После загрузки marker: `{"version_id":11,"status":"rolled_back","deadline":null,"reason":"reboot","phases":{"rollback":"rolled_back"}}`; applied и confirmed snapshots version 11 с addressing `dhcp`; PPP peer отсутствовал. Ложного confirm нет. Caddy задерживался из-за wait-online — отдельный дефект №5. |

`vs-router-pppoe-postboot` — oneshot: успешное завершение показывает `inactive (dead)`, журнал `Deactivated successfully`. Начальные `agent.rollback_failed` до обновления unit — ошибка неполного provisioning, не доказательство сценария 2.

## Очистка и конечное состояние

```
virsh -c qemu:///system destroy vsr-pppoe-isp41
virsh -c qemu:///system undefine vsr-pppoe-isp41
rm /home/poshl9k/VMs/vsr-pppoe-isp41.qcow2
virsh -c qemu:///system snapshot-revert vsr-clean-192a1d0 pre-pppoe-wave-c
# reverted, домен выключен; domiflist: default cc:00:01 + vsr-verify-lan cc:00:02
virsh -c qemu:///system net-destroy vsr-pppoe-lab41
virsh -c qemu:///system net-undefine vsr-pppoe-lab41
virsh -c qemu:///system start vsr-clean-192a1d0
# guest-ping return {}; marker version_id=5 status=confirmed
# agent/web/caddy active; pppd отсутствует; /root/pppoe41.password отсутствует
# enp1s0 192.168.122.197/24
```

Host HTTP server `18992` остановлен (`fuser -k 18992/tcp`); host scratch файлы с паролем удалены. Временная правка postboot unit и PPP-конфиги в госте удалены snapshot revert. Панель осталась LAN-only, WAN снова `default`. `git status --short` → `?? docs/lab-41-pppoe-live.md`; `git diff --check` → exit 0. Ничего не закоммичено и не отправлено.
