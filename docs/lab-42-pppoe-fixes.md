# Lab-42: PPPoE readiness, откат и порядок загрузки

10 октября 2026. Одноразовый router `vsr-clean-192a1d0`, ISP `vsr-pppoe-isp42`, изолированная сеть `vsr-pppoe-lab42` (`virbr-ppp42`, без IP/DHCP/NAT). Публикации, commit, sudo, изменения сети хоста и открытие `tproxy.not_available` не выполнялись. Пароль здесь не записан. Исходный дефект и конфигурация стенда: `docs/lab-41-pppoe-live.md`.

## Исправление

- `agent/pppoe_apply.py`, `agent/apply.py`: после запуска pppd ожидаются активный unit, интерфейс `ppp*` с `LOWER_UP`, локальный и peer IPv4 адрес IPCP (в JSON `ip` peer находится в поле `address`, не `peer`), маршрут через этот интерфейс. Ожидание ограничено 30 сек, executor и clock/sleep внедряемы. Отказ возвращает `pppoe.not_ready`, `reason_service=pppoe`, откатывает к подтверждённой версии до confirm. Проверка повторяется перед ручным confirm pending. В обычном apply без PPPoE новых фаз/проверок нет.
- `vs-router-pppoe-postboot.service` и `caddy.service`: нет ожидания `network-online.target`; запуск после `network.target`. Шаблон `vs-router-pppoe@.service` поднимает транспортный NIC через `ip link set dev %i up` до pppd: без обычного `.network` физический NIC после reboot был DOWN.
- `reconcile-networkd-boot.py`: после восстановления applied bundle, но до networkd удаляются только лишние `10-vs-router-*.network/.netdev`. DHCP `.network` не возвращается на PPPoE WAN; при static/DHCP файл остаётся. Скрипт не трогает прочие файлы.
- `kea-network-order.py`: Debian Kea vendor units ждут `network-online.target` и на изолированном DHCP WAN остаются в очереди, что ломало apply/rollback. Systemd drop-in не умеет очищать `After`/`Wants`; `install.sh` устанавливает полные копии двух Kea unit-файлов с заменой только этой зависимости на `network.target`. При обновлении Debian unit-файлов повторный `install.sh` обязателен. `bootrestore` разрешена запись в `/etc/ppp`; при прерванном pending восстановление удаляет неподтверждённые PPP peer/секреты/артефакт либо восстанавливает подтверждённые, не стартуя pppd в раннем oneshot.

## Команды стенда и сборка

Запуск гостевых команд: `python3 /home/poshl9k/.hermes/cache/scratch/ui-ux-review/gexec.py <domain> '<shell>'`; передача файлов: `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py <domain> --push <host-file> <guest-file>`. Временные скрипты под `.hermes/cache/scratch/pppoe42-*` не содержат пароль; пароль был в отдельном файле с mode 0600, удалён в конце. Создание draft: гостевой `/root/pppoe42-draft.py` вызывает `validate` → `parse_configuration` → `check_roles` → `materialize_addresses` → `ConfigurationRow` commit, затем agent RPC `apply_version`. В уже существовавшем draft 6 имелся stale WAN site без WAN-адреса; для лабораторного apply он удалён из draft (`sites=[]`), не изменяя production gate и подтверждённую версию. В конце snapshot revert убрал это изменение.

```
virsh -c qemu:///system snapshot-create-as vsr-clean-192a1d0 pre-pppoe-lab42 --disk-only --atomic
# Снимок домена pre-pppoe-lab42 создан
virsh -c qemu:///system net-define /home/poshl9k/.hermes/cache/scratch/pppoe42-net.xml
virsh -c qemu:///system net-start vsr-pppoe-lab42
qemu-img create -f qcow2 -F qcow2 -b /home/poshl9k/VMs/vsr-clean-192a1d0.qcow2 /home/poshl9k/VMs/vsr-pppoe-isp42.qcow2
# Formatting ... size=21474836480 ...
virsh -c qemu:///system define /home/poshl9k/.hermes/cache/scratch/pppoe42-domain.xml
virsh -c qemu:///system start vsr-pppoe-isp42
# Domain 'vsr-pppoe-isp42' started
```

ISP имеет две NIC (NAT для установки пакетов, лабораторная для PPPoE); на нём `apt-get install -y pppoe` → `Setting up pppoe (4.0-1)`; `pppoe-server -I ens4 -L 10.42.0.1 -R 10.42.0.2 -N 4 -C ISP42`, `require-chap`, `auth`, `name isp42`. Роутер: `apt-get install -y ppp` → `Setting up ppp (2.5.2-1+1)`. WAN `52:54:00:cc:00:01` перенесён из `default` в `vsr-pppoe-lab42` через `virsh detach-interface/attach-interface --live --config`; management MAC `52:54:00:cc:00:02` не менялся. Текущий wheel передан в guest с совпадающим SHA-256, установлен через `python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl`, agent/web перезапущены. Релевантные packaging units и boot helper скопированы в гостя, `systemctl daemon-reload`, `systemctl enable vs-router-pppoe-postboot.service`. Полный `install.sh` на госте не запускался.

```
uv run --project backend --with pytest pytest -q backend/tests
# 1000 passed, 1 skipped in 34.62s
uv build backend --wheel
# Successfully built backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# 23b3fa139489e815fc13327767e1887d060efc5a1971b20ce2329762a8cdb578
# guest sha256sum того же wheel: 23b3fa139489e815fc13327767e1887d060efc5a1971b20ce2329762a8cdb578
```

Сборка и повторный deploy wheel выполнялись после обнаруженного на живом ppp0 различия `ip -j addr` (`address`, а не `peer`). Ещё одна живая итерация показала `enp1s0 DOWN` после reboot без `.network`: добавлен `ExecStartPre`. Следующая итерация показала ожидающие Kea units; попытка drop-in не сняла vendor `After=network-online.target`, поэтому заменена полными unit-копиями. При первом reboot pending ранний bootrestore не имел `ReadWritePaths=/etc/ppp` и завершился `interrupted apply recovery failed`; исправлено, после этого успешный повторный тест указан ниже. Не выдаём промежуточные падения за PASS.

## Живой повтор: команды, наблюдения, решение

| Сценарий | Результат | Фактический вывод |
|---|---|---|
| CHAP/IPCP успех | PASS | `python3 /root/pppoe42-draft.py pppoe` → draft 6 `status=confirmed`, `phases.pppoe=applied`, `phases.pppoe_readiness=applied`; `ip -br addr show ppp0` → `ppp0 UNKNOWN 10.42.0.4 peer 10.42.0.1/32`; `ip -4 route show default` → `default dev ppp0 scope link`; `journalctl -u vs-router-pppoe@enp1s0.service` → `CHAP authentication succeeded: Access granted`, `local IP address 10.42.0.4`. `.network` на enp1s0 отсутствует. |
| Неверный пароль и auto rollback | PASS | `python3 /root/pppoe42-draft.py bad` → draft 7, RPC `status=rolled_back`, `version_id=6`, `reason=pppoe.not_ready`, `reason_service=pppoe`, `phases.rollback=rolled_back`; `journalctl` → `CHAP authentication failed: Access denied`, `Connection terminated`; `status=confirmed` для draft 7 НЕ было. После отката правильный peer заново получил `ppp0 10.42.0.3 peer 10.42.0.1/32`, `default dev ppp0`. |
| PPPoE → static → DHCP → PPPoE | PASS | Draft 7 static `confirmed`, `enp1s0 10.42.99.2/24`, peer удалён; draft 8 DHCP `confirmed`, файл `10-vs-router-enp1s0.network` содержит `DHCP=ipv4`, peer удалён; draft 9 PPPoE `confirmed` с `pppoe_readiness=applied`, файл `.network` отсутствует, ppp0 поднят. |
| Reboot с подтверждённым PPPoE | PASS после исправления | `virsh -c qemu:///system reboot vsr-clean-192a1d0` → `systemctl is-active vs-router-bootrestore vs-router-agent vs-router-web caddy vs-router-pppoe@enp1s0.service` → пять `active`; `systemctl show -p Result vs-router-pppoe-postboot.service` → `Result=success`; `enp1s0 UP`, `ppp0 UNKNOWN 10.42.0.2 peer 10.42.0.1/32`, `default dev ppp0`; `test ! -e /etc/systemd/network/10-vs-router-enp1s0.network` → true; журнал → `CHAP authentication succeeded`. |
| Static/DHCP после reboot | PASS | Draft 10 static `confirmed`, после reboot `enp1s0 UP 10.42.99.2/24`, static `.network` присутствует, `Device "ppp0" does not exist`, peer отсутствует, agent/web/caddy `active`. Draft 11 DHCP `confirmed`, после reboot `DHCP=ipv4`, peer отсутствует, `Device "ppp0" does not exist`, agent/web/caddy `active`. Отсутствие DHCP-адреса ожидаемо: ISP-сегмент DHCP не предоставляет. |
| Reboot при pending apply | PASS после исправления | От подтверждённого DHCP draft 11: `python3 /root/pppoe42-draft.py pppoe --safe` → draft 12 `status=pending`, `deadline=1791659322.8797488`, PPP readiness `applied`; сразу `virsh reboot`. После boot `ApplyEngine().status()` → `{'version_id': 11, 'status': 'rolled_back', 'deadline': None, 'reason': 'reboot', 'phases': {'rollback': 'rolled_back'}}`; DHCP `.network` с `DHCP=ipv4`, `pppoe.json`, peer, chap/pap-secrets отсутствуют; bootrestore/agent/web/caddy/Kea ctrl/Kea DHCP → шесть `active`. Ложного confirm нет. |
| Изоляция/секреты | PASS | `ss -ltnp` → только `192.168.10.1:443` для Caddy; `curl --cacert <CA из /etc/caddy/management/ca.crt> https://192.168.10.1/` → `LAN_HTTPS=200`; `curl --connect-timeout 2 -k https://192.168.122.197/` → timeout, `WAN_HTTPS=000`; `SECRET_IN_AGENT_OR_PPPD_JOURNAL False`; PPP manifest mode `600 root:root`. |

Промежуточный fail pending apply до Kea override: `agent.rollback_failed`; `systemctl list-jobs` показывал `kea-ctrl-agent.service`, `kea-dhcp4-server.service` ожидающими `network-online.target`, `systemd-networkd-wait-online.service start running`. После полных unit-копий `systemctl show -p After -p Wants kea-dhcp4-server kea-ctrl-agent` не содержит `network-online.target`, обе службы `active`, `No jobs running.` Это не меняло продуктовый закрытый gate TProxy.

## Очистка и итоговое состояние

```
virsh -c qemu:///system destroy vsr-pppoe-isp42
virsh -c qemu:///system undefine vsr-pppoe-isp42
rm /home/poshl9k/VMs/vsr-pppoe-isp42.qcow2
virsh -c qemu:///system destroy vsr-clean-192a1d0
virsh -c qemu:///system snapshot-revert vsr-clean-192a1d0 pre-pppoe-lab42
virsh -c qemu:///system net-destroy vsr-pppoe-lab42
virsh -c qemu:///system net-undefine vsr-pppoe-lab42
virsh -c qemu:///system start vsr-clean-192a1d0
# guest-ping {}; agent/web/caddy active; WAN enp1s0 192.168.122.197/24;
# /root/isp42.password и /etc/ppp/peers/vs-router-enp1s0 отсутствуют;
# marker version_id=5 status=confirmed; domiflist default + vsr-verify-lan.
```

Host secret-файл удалён, ISP overlay и сеть удалены. Snapshot revert убрал гостевые units, тестовый draft, пароль, временное выключение rollback timer и любые лабораторные файлы. Панель вернулась к исходному состоянию LAN-only. Изменения кода и этот отчёт оставлены в рабочем дереве без commit/push.

`git diff --check` → exit 0; итоговый `git status --short`:

```
 M backend/packaging/caddy.service
 M backend/packaging/install.sh
 M backend/packaging/vs-router-bootrestore.service
 M backend/packaging/vs-router-pppoe-postboot.service
 M backend/packaging/vs-router-pppoe@.service
 M backend/src/vs_router/agent/apply.py
 M backend/src/vs_router/agent/boot_restore.py
 M backend/src/vs_router/agent/pppoe_apply.py
 M backend/tests/test_pppoe_apply.py
 M backend/tests/test_pppoe_boot.py
 M backend/tests/test_pppoe_packaging.py
?? backend/packaging/kea-network-order.py
?? backend/packaging/reconcile-networkd-boot.py
?? docs/lab-41-pppoe-live.md
?? docs/lab-42-pppoe-fixes.md
```

`docs/lab-41-pppoe-live.md` уже был untracked до начала этой задачи; он сохранён без изменения.
