# Lab-39 — boot restore: reboot PASS, packet-proof FAIL

10 октября 2026. Одноразовая `vsr-clean-192a1d0`, snapshot `pre-tproxy-1791616579`. Публичный `tproxy.not_available` не менялся; commit/push нет. Все гостевые команды ниже запускались root через `python3 /home/poshl9k/.hermes/cache/scratch/ui-ux-review/gexec.py vsr-clean-192a1d0 '<команда>'`; короткие файлы передавались через `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py vsr-clean-192a1d0 --push <host> <guest>`.

## Причина и исправление

`vs-router-bootrestore.service`: `Before=systemd-networkd.service`, oneshot с `DefaultDependencies=no`; старый код внутри него синхронно выполнял `systemctl restart` split Unbound/sing-box. У этих генерируемых юнитов `After=network-online.target`/`Wants=network-online.target`. Ожидание network-online, зависящее от networkd, зацикливало транзакцию по порядку. Каждый `systemctl` упирался в 15-секундный timeout. `Requires=vs-router-bootrestore.service` у agent и Caddy оставлял их inactive. Кроме того, `restore_ssh()` парсил confirmed TProxy snapshot с публично закрытым валидатором, если lab-bypass стоял только на agent: отдельная причина base exit=1 в прежнем прогоне.

Исправление: ранний oneshot загружает только защитные TProxy guards, устанавливает `ip_forward=1` и завершает base restore/SSH. Новый `vs-router-tproxy-postboot.service` (WantedBy=multi-user.target, After=bootrestore + network-online; без Requires у agent/Caddy) проверяет наличие защитных таблиц в ядре, затем запускает оба resolver и sing-box и лишь после readiness устанавливает policy route и capture. Его отказ не влияет на base units. `install.sh` устанавливает и включает новый unit, ставит `/etc/sysctl.d/90-vs-router-forward.conf`, применяет sysctl сразу. На VM для закрытого product gate bypass был необходим одновременно в agent и bootrestore; это НЕ изменение репозитория.

## Deploy и apply

```
virsh -c qemu:///system list --all                     # vsr-clean-192a1d0 работает
virsh -c qemu:///system snapshot-list vsr-clean-192a1d0 # pre-tproxy-1791616579 disk-snapshot
virsh -c qemu:///system domiflist vsr-clean-192a1d0   # default cc:00:01; vsr-verify-lan cc:00:02
virsh -c qemu:///system qemu-agent-command vsr-clean-192a1d0 '{"execute":"guest-ping"}' # {"return":{}}
uv build backend --wheel
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# 59c476c530360612ff43f91618514e4c308a3d7b1f8c53511dfd0a62a1a09780
python3 -m http.server 18992 --bind 192.168.10.254 # cwd backend/dist, временно
# guest:
curl -fsS -o /root/vs_router_backend-0.1.0-py3-none-any.whl http://192.168.10.254:18992/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum /root/vs_router_backend-0.1.0-py3-none-any.whl
# 59c476c530360612ff43f91618514e4c308a3d7b1f8c53511dfd0a62a1a09780
python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl
# Successfully installed vs-router-backend-0.1.0
systemctl daemon-reload; systemctl enable vs-router-tproxy-postboot.service
sysctl -w net.ipv4.ip_forward=1 # net.ipv4.ip_forward = 1
systemctl restart vs-router-agent vs-router-web
sha256sum /usr/local/lib/python3.13/dist-packages/vs_router/agent/boot_restore.py
# d3034c0d3aa8c87031ec199a59033125f08f04201ace27a2a9bf19b20c40430f (host at deploy; subsequent docstring-only edit)
```

В госте вручную исполнено ровно provisioning из install.sh, необходимое для split units: users UID 29092/29093, `chmod o+x /etc/vs-router{,/applied}`, AppArmor local rule `/etc/vs-router/applied/** r,` и `apparmor_parser -r`. Полный install.sh не запускался: он также маскирует SSH, перезаписывает release identity, мигрирует DB и заменяет UI. Переданы новые unit и sysctl файл. UI не изменён. Бypass: `/var/lib/vs-router/t2/sitecustomize.py` при `VSR_T2_OFFLINE=1` лишь на время оригинального `validators.validate_configuration` временно снимает `tproxy.enabled`, потом восстанавливает его; `/etc/systemd/system/{vs-router-agent,vs-router-bootrestore}.service.d/t2.conf` задают `Environment=VSR_T2_OFFLINE=1` и `Environment=PYTHONPATH=/var/lib/vs-router/t2`. Никаких overrides для web/public API. Метод тот же, что lab-38, дополнен bootrestore из-за парсинга confirmed snapshot в SSH restore.

Создание drafts 6/7/8 шло через `validate` → `parse_configuration` → `validate_management` → `validate_site_bindings` → DB ORM commit, не через сырой JSON в SQLite. Исходные LAN `enp2s0/192.168.10.1`, WAN `enp1s0`. Draft 6 как lab-38: ingress enp2s0, proxy direct, final block. Draft 7 добавил `dns.access_control=['127.0.0.0/8','192.168.10.0/24']`, обычный DNS upstream `192.168.122.1`, A record `lab-router.test. 198.18.0.42` и firewall pass `lab_transit_probe` (LAN, src `192.168.10.254`, dst `192.168.122.1`, TCP/18873). Draft 8 добавил pass UDP/53 `lab_dns_client` для host→selected resolver. Каждый draft `VALIDATE valid: true` (6 и 7 также `ARTIFACTS` = singbox, guards, interception, selected, ordinary). RPC каждого:

```
VSR_T2_OFFLINE=1 PYTHONPATH=/var/lib/vs-router/t2 python3 -c 'from vs_router.agent.daemon import UnixSocketTransport; from vs_router.agent.rpc import AgentClient; print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version", {"version_id":8,"safe_mode":False}))'
# version_id 8, status confirmed, error None;
# tproxy_guards/tproxy_interception/tproxy_policy_route/unbound_process/singbox_process: applied
nft list tables # 9 из 9 owned TProxy tables + vs_router + vs_router_ssh_bans
ip rule # 100: from all fwmark 0x100 lookup 100
ip route show table 100 # local default dev lo scope host
systemctl is-active vs-router-unbound-selected vs-router-unbound-ordinary vs-router-singbox
# active / active / active
```

Это проверка после RPC `confirmed`, а не отдельное инструментирование момента перед marker; порядок verify-before-confirm дополнительно покрыт кодом apply и существующим test suite.

## DNS и настоящий reboot

DNS wire probe: `python3 /var/lib/vs-router/t2/dns.py` посылает UDP A `lab-router.test` на `127.0.0.1:53` (ordinary): `rcode 0 answers 1 contains-198.18.0.42 True`. Отдельный host UDP probe на `192.168.10.1:53` (selected) после pass rule: `rcode 0 answers 1 token True`. С гостя `example.org` через ordinary с upstream `192.168.122.1`: `rcode 0 answers 2`, raw hex `...08062f4500...08067000` (A `8.47.69.0`, `8.6.112.0`). Это подтверждает живой upstream-ответ, но не подлинность данных публичной зоны: адреса выглядят необычно, независимую проверку не выполняли. Гостевой запрос непосредственно на selected LAN IP не репрезентативен (локальный пакет выходит через lo и отклоняется nft listener guard); host запрос успешен.

```
virsh -c qemu:///system reboot vsr-clean-192a1d0
# после 22 с guest-ping -> {"return":{}}
cat /proc/sys/kernel/random/boot_id  # 0e07a024-082c-41c9-a73d-69c1e8b5acc9 (до: 19f71721-1f51-4772-b5fa-dd1cac65b9d3)
cat /proc/sys/net/ipv4/ip_forward    # 1
systemctl is-active vs-router-bootrestore vs-router-tproxy-postboot vs-router-agent vs-router-web caddy vs-router-unbound-selected vs-router-unbound-ordinary vs-router-singbox
# active / inactive / active / active / active / active / active / active
systemctl show vs-router-tproxy-postboot -p Result -p ExecMainStatus -p ActiveState
# Result=success, ExecMainStatus=0, ActiveState=inactive (успешный Type=oneshot без RemainAfterExit)
journalctl -u vs-router-bootrestore -u vs-router-tproxy-postboot -b --no-pager -n 45
# 14:07:36 boot-restore: OK / Finished; 14:07:36 Starting postboot; 14:07:38 Finished postboot
nft list tables # все 9: guard ipv6_guard preauth dns_ingress dns_listener dns_output ct_reset interception input
ip rule # 100: from all fwmark 0x100 lookup 100
ip route show table 100 # local default dev lo scope host
ip route show default # default via 192.168.122.1 dev enp1s0
# повторный DNS probe: ordinary rcode 0 answers 1; selected host rcode 0 answers 1
```

Негативная инъекция: сохранён selected config, заменён строкой `invalid-unbound-config`, `unbound-checkconf` сообщил `unknown keyword`; настоящий второй `virsh reboot`. Boot ID `ce614508-0233-4b54-bbd1-a0eae73e0b24`: bootrestore `active`/`OK`; postboot `failed`, `ExecMainStatus=1`, журнал `TProxy resolver restore failed`; agent/web/Caddy все `active`, selected и sing-box `inactive`, только 6 guards без capture tables, нет fwmark 100, `ip_forward=1`. После `cp -a /root/t3-selected-good.conf /etc/vs-router/applied/tproxy-unbound-selected.conf; systemctl reset-failed vs-router-tproxy-postboot; systemctl start vs-router-tproxy-postboot` → `Result=success`, снова 9/9, fwmark 100 и все три процесса active. Это доказывает изоляцию substep failure и fail-closed по состоянию ядра, но НЕ packet proof.

## Packet proof: НЕ ПРОЙДЕН

Origin поднят на host `python3 -m http.server 18873 --bind 192.168.122.1`, token `T3-WAN-ORIGIN-7eaf12` в `token.txt`; `curl http://192.168.122.1:18873/token.txt` на host и guest оба получили token. Это доказывает достижимость origin от guest, но не LAN→router→WAN транзит. Подтверждённый firewall pass `lab_transit_probe` присутствовал в `nft list chain inet vs_router forward`; forwarding=1. Тем не менее `nft list chain inet vs_router_tproxy_guard forward` показывал `iifname "enp2s0" counter packets 0 bytes 0 drop comment "tproxy_containment"`; счётчик pass тоже `packets 0`. У host адрес origin `192.168.122.1` ЛОКАЛЬНЫЙ: `ip route get 192.168.122.1 from 192.168.10.254` → `local ... dev lo`. До внешнего `1.1.1.1` host идёт `via 10.10.10.1 dev br0`, тоже мимо VM. `sudo -n true` → `sudo: interactive authentication is required`; без изменения host маршрута/отдельного LAN клиента нельзя честно заставить host отправить пакет через `192.168.10.1`. Мы не подменяли counter искусственной записью и не выдаём гостевой curl за транзит. Положительный контроль доставки через РОУТЕР, Δ counter и отсутствие token при guard drop **не доказаны**. Это оставшийся блокер полного P2-4 acceptance; потребуются авторизованная host route/network namespace/дополнительный клиент и повторный опыт.

## Очистка и вердикт

```
# остановлены оба host HTTP сервера: 192.168.10.254:18992 и 192.168.122.1:18873
virsh -c qemu:///system snapshot-revert vsr-clean-192a1d0 pre-tproxy-1791616579
# reverted; guest выключен
virsh -c qemu:///system start vsr-clean-192a1d0
# guest-ping -> {"return":{}}
cat /etc/vs-router/marker.json # version_id 5, status confirmed
systemctl is-active vs-router-bootrestore vs-router-agent vs-router-web caddy unbound kea-dhcp4-server
# active / active / active / active / active / active
# test ! -f .../vs-router-agent.service.d/t2.conf && test ! -f .../vs-router-bootrestore.service.d/t2.conf -> bypass_absent
# test ! -f /etc/systemd/system/vs-router-tproxy-postboot.service -> postboot_experiment_absent
nft list tables # inet vs_router; inet vs_router_ssh_bans
curl -sk -o /dev/null -w '%{http_code}' https://192.168.10.1/ # 200
```

Снимок восстановил стабильную исходную VM, в том числе СТАРЫЙ wheel и исходный `ip_forward=0`: исправление остаётся только в рабочем дереве repo и требует повторного deploy при следующем прогоне. In-memory web sessions после reboot/revert недействительны; нужен повторный вход. `-k` в HTTPS probe не проверял CA. UI не менялся/не проверялся.

| Критерий | Результат |
|---|---|
| apply 9/9 + confirmed, ordering verify-before-confirm | PASS: 9/9 после apply; порядок проверен кодом и тестами, отдельного снимка до marker нет |
| split DNS отвечает (ordinary, selected и ordinary external) | PASS: rcode 0, ответы 1/1/2 |
| настоящий reboot: base agent/web/Caddy, 9/9, route, DNS/engine, forwarding | PASS: boot IDs, journal, ядро, процессы и DNS проверены |
| отказ TProxy не выключает base; capture withheld | PASS: второй reboot с испорченным конфигом, 6 guards, route отсутствует, base active |
| реальный fail-closed packet proof с positive transit control | **FAIL: нет транзитного пакета, containment=0** |
| cleanup VM и host серверов | PASS: snapshot, исходный marker и службы, bypass исчез |

`uv run --project backend pytest backend/tests -q` → `973 passed, 1 skipped in 28.00s`; `sh -n backend/packaging/install.sh`, `systemd-analyze verify ...`, `git diff --check` → exit 0. Общий P2-4 статус: **FAIL / не принимать**, gate закрыт.

`git status --short` (до создания этого отчёта):
```
 M backend/packaging/install.sh
 M backend/src/vs_router/agent/boot_restore.py
 M backend/tests/test_management.py
 M backend/tests/test_t4_boot.py
?? backend/packaging/90-vs-router-forward.conf
?? backend/packaging/vs-router-tproxy-postboot.service
```
Дополнительно `?? docs/lab-39-tproxy-boot-restore-fixed.md`. Все изменения без commit/push.
