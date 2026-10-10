# Lab-40 — пакетный fail-closed с отдельным LAN-клиентом

10 октября 2026. Одноразовый роутер `vsr-clean-192a1d0`, rollback `pre-tproxy-1791616579`; отдельный клиент `vsr-verify-lan` на host-only `virbr-vsr`. Публичный `tproxy.not_available` не менялся; commit/push, sudo и изменений сети host нет. Гостевые команды выполнялись root через `python3 /home/poshl9k/.hermes/cache/scratch/ui-ux-review/gexec.py <domain> '<команда>'`, короткие файлы — `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py <domain> --push <host> <guest>`. Сами probe-файлы лежали в scratch, не в repo.

## Развёртывание

```
virsh -c qemu:///system list --all
# vsr-clean-192a1d0 работает
virsh -c qemu:///system snapshot-list vsr-clean-192a1d0
# pre-tproxy-1791616579 disk-snapshot
virsh -c qemu:///system snapshot-current vsr-clean-192a1d0 --name
# pre-tproxy-1791616579
virsh -c qemu:///system domiflist vsr-clean-192a1d0
# default cc:00:01; vsr-verify-lan cc:00:02
virsh -c qemu:///system qemu-agent-command vsr-clean-192a1d0 '{"execute":"guest-ping"}'
# {"return":{}}
# guest: agent/web/caddy active; vs-router-backend 0.1.0; UI dir есть;
# management enp2s0/192.168.10.1/24; marker version_id=5 status=confirmed
uv build backend --wheel
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# aa7405da24d9b72cf4e0e5db712fc9d071e10a525554f6241fc074272be2d302
# host, cwd backend/dist:
python3 -m http.server 18992 --bind 192.168.10.254
# router guest:
curl -fsS --max-time 15 -o /root/vs_router_backend-0.1.0-py3-none-any.whl http://192.168.10.254:18992/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum /root/vs_router_backend-0.1.0-py3-none-any.whl
# aa7405da24d9b72cf4e0e5db712fc9d071e10a525554f6241fc074272be2d302
python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl
# Successfully installed vs-router-backend-0.1.0
systemctl restart vs-router-agent vs-router-web
# agent/web/caddy: active/active/active
```

На роутере выполнено только нужное provisioning из `backend/packaging/install.sh`: два системных UID 29092/29093 для split-Unbound, `chmod o+x /etc/vs-router /etc/vs-router/applied`, AppArmor local `/etc/vs-router/applied/** r,` + `apparmor_parser -r`, установлены `vs-router-tproxy-postboot.service` и `90-vs-router-forward.conf`, `systemctl daemon-reload; systemctl enable vs-router-tproxy-postboot.service; sysctl -w net.ipv4.ip_forward=1` → `net.ipv4.ip_forward = 1`. Полный install.sh не запускался. Временный, гостевой, непубличный bypass `sitecustomize.py` из `/home/poshl9k/.hermes/cache/scratch/t2-sitecustomize.py` установлен в `/var/lib/vs-router/t2/`: при `VSR_T2_OFFLINE=1` только `validators.validate_configuration` временно видит `tproxy.enabled=False`, после валидации флаг возвращается. Agent и bootrestore получили drop-in с `Environment=VSR_T2_OFFLINE=1`, `Environment=PYTHONPATH=/var/lib/vs-router/t2`. После передачи файла agent перезапущен повторно: первый RPC до повторного рестарта вернул `rpc.invalid_request` — запущенный процесс ещё не загрузил sitecustomize. Публичный web не получил bypass.

Клиентский overlay создавался без sudo:

```
qemu-img create -f qcow2 -F qcow2 -b /home/poshl9k/VMs/vsr-poke-20261007.qcow2 /home/poshl9k/VMs/vsr-verify-lan-t4.qcow2
chgrp kvm /home/poshl9k/VMs/vsr-verify-lan-t4.qcow2; chmod 664 /home/poshl9k/VMs/vsr-verify-lan-t4.qcow2
virsh -c qemu:///system define /home/poshl9k/.hermes/cache/scratch/t4-client.xml
virsh -c qemu:///system start vsr-verify-lan
```

Первая попытка с `q35` упала в initramfs: `ALERT! UUID=9a9b9536-9f20-4496-b39b-451f3f1d8c03 does not exist`; virtio-pci писал `Unable to change power state from D3cold to D0, device inaccessible`. Вторая попытка с overlay над `vsr-clean-192a1d0.qcow2` на `q35` упала аналогично (`UUID=f72580f3-afef-4623-a206-409d5af2802e does not exist`). После смены машины в XML на `pc-i440fx-10.2` тот же второй overlay загрузился: `guest-ping` → `{"return":{}}`. XML содержал только одну NIC `<source network='vsr-verify-lan'/>` (`52:54:00:cc:00:50`), virtio disk и канал `org.qemu.guest_agent.0`; WAN NIC у клиента не было. Клиент Debian 13. На нём:

```
systemctl stop vs-router-web vs-router-agent vs-router-bootrestore caddy 2>/dev/null || true
systemctl disable --now vs-router-web vs-router-agent vs-router-bootrestore caddy 2>/dev/null || true
ip link set enp0s3 up
ip addr replace 192.168.10.50/24 dev enp0s3
ip route replace default via 192.168.10.1 dev enp0s3
ip route get 192.168.122.1
# 192.168.122.1 via 192.168.10.1 dev enp0s3 src 192.168.10.50 uid 0
systemctl is-active vs-router-agent vs-router-web qemu-guest-agent
# inactive / inactive / active
```

Host-origin: файл `/home/poshl9k/.hermes/cache/scratch/t4-origin/token.txt` содержит `T4-TRANSIT-870fd0f0067ceb09`; `python3 -m http.server 18873 --bind 192.168.122.1` из этой директории. Host `curl --noproxy '*' -fsS http://192.168.122.1:18873/token.txt` вернул token. Это лишь проверка origin, не транзита.

Единственный draft создан из confirmed row 5 через `/home/poshl9k/.hermes/cache/scratch/t4-draft.py`: `validate(data,old)` → `parse_configuration` → `materialize_addresses` → `check_roles` → `validate_management` → `validate_site_bindings` → `build_artifacts` → ORM commit в draft row 6. Изменения: `dns.interfaces=['enp2s0']`, `dns.access_control=['127.0.0.0/8','192.168.10.0/24']`, upstream `192.168.122.1`; `proxies.enabled=True`, outbound `lab_direct` типа direct; TProxy ingress `enp2s0`, rule `198.18.0.0/15 → lab_direct`, `final=block`; firewall pass `lab_transit_probe`, `ingress_zone=lan`, TCP src `192.168.10.50`, dst `192.168.122.1`, dport `18873`. Вывод: `VALIDATE {"valid": true, "errors": [], "warnings": []}`, artifacts `singbox, tproxy_guards, tproxy_interception, tproxy_unbound_ordinary, tproxy_unbound_selected`, `DRAFT 6 baseline 5 ingress ('enp2s0',)`. Не редактировали SQLite напрямую.

```
VSR_T2_OFFLINE=1 PYTHONPATH=/var/lib/vs-router/t2 python3 -c 'from vs_router.agent.daemon import UnixSocketTransport; from vs_router.agent.rpc import AgentClient; print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version", {"version_id":6,"safe_mode":False}))'
# {'version_id': 6, 'status': 'confirmed', 'phases': {...,
# 'tproxy_guards': 'applied', 'tproxy_interception': 'applied',
# 'tproxy_policy_route': 'applied', 'unbound_process': 'applied',
# 'singbox_process': 'applied'}, 'error': None, 'reason': None, ...}
# nft list tables: base vs_router + vs_router_ssh_bans + все 9 TProxy-owned таблиц
# ip route show default: default via 192.168.122.1 dev enp1s0 ...
# sysctl -n net.ipv4.ip_forward: 1
# agent/web/caddy/selected/ordinary/sing-box: active/active/active/active/active/active
```

## Контроль и отказ: реальные пакеты

Важное ограничение смысла контроля: TProxy `tproxy_containment` — безусловный drop в FORWARD (priority -10), даже при здоровом sing-box. Здоровый TProxy перехватывает разрешённый поток в PREROUTING и ведёт его через локальный движок; такой поток не увеличивает counter `inet vs_router forward` правила `lab_transit_probe`. Поэтому для именно FORWARD-контроля на одноразовой VM **временно удалены только две TProxy-owned таблицы `interception` и `guard`**; конфигурация и подтверждённое firewall pass-правило остались прежними, forwarding и WAN route сохранены. Это доказательство обычного маршрутизируемого транзита, НЕ доказательство успешного healthy sing-box/direct-proxy трафика. Перед отрицательной пробой guard восстановлен из применённого артефакта.

```
# router, перед контролем:
nft -a list chain inet vs_router forward
# ... lab_transit_probe counter packets 0 bytes 0 accept ...
nft -a list chain inet vs_router_tproxy_guard forward
# ... tproxy_containment counter packets 0 bytes 0 drop
nft delete table inet vs_router_tproxy_interception
nft delete table inet vs_router_tproxy_guard
ip route get 192.168.122.1 from 192.168.10.50 iif enp2s0
# 192.168.122.1 from 192.168.10.50 dev enp1s0 cache iif enp2s0
# client:
curl --noproxy '*' -v --connect-timeout 4 --max-time 8 http://192.168.122.1:18873/token.txt
# Connected to 192.168.122.1 port 18873; HTTP/1.0 200 OK
# T4-TRANSIT-870fd0f0067ceb09 ; CLIENT_CURL_RC=0
# router после контроля:
nft list chain inet vs_router forward
# ... lab_transit_probe counter packets 1 bytes 60 accept ...
nft list chain inet vs_router_tproxy_preauth transit
# ... lab_transit_probe counter packets 5 bytes 360 return ...
```

Firewall pass Δ = +1 packet/+60 bytes. Host HTTP log подтвердил `192.168.122.197 ... "GET /token.txt HTTP/1.1" 200` (WAN-адрес router, source NAT); обратная достижимость также подтверждена body на клиенте. Это не host-local curl: у клиента единственная NIC на `virbr-vsr`, route via router, а у роутера forwarding-rule counter вырос.

Отказ: остановлены движок и выбранный resolver, capture уже отсутствует, защитный файл установлен обратно через `nft -f`. Base agent/web/Caddy остались active, `ip_forward=1`, WAN default route сохранён; pass-правило оставлено неизменным. Это **контролируемая имитация protective-state после отказа readiness**, а не повторный reboot или свидетельство того, что сервис сам отказал без вмешательства. Успешный настоящий reboot/readiness-failure отдельно доказан в lab-39.

```
# router:
systemctl stop vs-router-singbox vs-router-unbound-selected
nft -f /etc/vs-router/applied/tproxy-guards.nft
nft list chain inet vs_router_tproxy_guard forward
# ... tproxy_containment counter packets 0 bytes 0 drop
nft list chain inet vs_router forward
# ... lab_transit_probe counter packets 1 bytes 60 accept ...
# client, тот же URL:
curl --noproxy '*' -fsS --connect-timeout 3 --max-time 6 -o /root/t4-negative-body -w 'HTTP=%{http_code} bytes=%{size_download}\n' http://192.168.122.1:18873/token.txt
# curl: (28) Connection timed out after 3002 milliseconds
# HTTP=000 bytes=0 ; CLIENT_CURL_RC=28 ; TOKEN_ABSENT (файл пуст/отсутствует)
# router после запроса:
nft list chain inet vs_router_tproxy_guard forward
# ... tproxy_containment counter packets 3 bytes 180 drop ...
nft list chain inet vs_router forward
# ... lab_transit_probe counter packets 1 bytes 60 accept ... (не вырос)
# agent/web/caddy: active/active/active
```

Guard Δ = +3 packets/+180 bytes на TCP SYN retransmits. В host-origin log **нет второго GET**. Token отсутствует у клиента. Противоположные результаты для одного и того же URL при неизменном подтверждённом firewall pass и сохранённом forwarding доказывают реальный drop в TProxy guard, не отсутствие маршрута.

## Очистка

```
# остановлены оба host HTTP сервера (18873 на 192.168.122.1 и 18992 на 192.168.10.254)
virsh -c qemu:///system destroy vsr-verify-lan
virsh -c qemu:///system undefine vsr-verify-lan
rm /home/poshl9k/VMs/vsr-verify-lan-t4.qcow2 /home/poshl9k/VMs/vsr-verify-lan-t4b.qcow2
virsh -c qemu:///system snapshot-revert vsr-clean-192a1d0 pre-tproxy-1791616579
# reverted; router выключен
virsh -c qemu:///system start vsr-clean-192a1d0
virsh -c qemu:///system qemu-agent-command vsr-clean-192a1d0 '{"execute":"guest-ping"}'
# {"return":{}}
cat /etc/vs-router/marker.json # version_id=5 status=confirmed
systemctl is-active vs-router-bootrestore vs-router-agent vs-router-web caddy unbound kea-dhcp4-server
# active / active / active / active / active / active
# agent + bootrestore t2.conf absent; tproxy-postboot.service absent
nft list tables # inet vs_router; inet vs_router_ssh_bans
curl --noproxy '*' -sk -o /dev/null -w '%{http_code}\n' https://192.168.10.1/ # 200
# host curl :18873 и :18992 → HTTP 000, connect refused; client VM удалена
```

`git status --short` после очистки → `?? docs/lab-40-tproxy-failclosed-packet-proof.md` (только этот файл); `git diff --check` → exit 0. `virsh list --all` показывает только работающий `vsr-clean-192a1d0`; оба клиентских overlay отсутствуют.

Снимок вернул старый wheel/отключённый TProxy и убрал bypass; UI не обновлялся. Рестарт web и snapshot revert сбрасывают in-memory sessions: требуется повторный вход. HTTPS probe с `-k` не проверял цепочку доверия CA.

| Критерий | Итог |
|---|---|
| Отдельный LAN-клиент, единственный маршрут к origin через router | PASS: 192.168.10.50 via 192.168.10.1, одна NIC |
| Подтверждённый draft, firewall pass, forwarding и WAN route | PASS: RPC confirmed, правило реально в nft, forward=1, default via WAN |
| Положительный реальный FORWARD-контроль | PASS: token/HTTP 200 клиенту, pass Δ+1, origin видит WAN IP роутера; только при временно снятых guard/capture |
| Защитный packet drop в том же направлении | PASS: guard восстановлен, sing-box/selected остановлены; curl 28/HTTP 000/token absent; containment Δ+3, pass без прироста |
| Успешный healthy TProxy direct outbound end-to-end | НЕ ПРОВЕРЯЛСЯ: FORWARD-pass counter при TProxy-перехвате не может быть его контролем |
| Cleanup и исходная VM | PASS: client/overlay/серверы удалены, snapshot восстановлен, base службы active |

Вердикт по запрошенному **пакетному fail-closed с положительным контролем обычного транзита: PASS**. Это не означает, что протестирована доставка через sing-box в здоровом состоянии; для отдельного критерия healthy TProxy e2e нужна другая метрика (capture/engine), а не counter FORWARD pass. Ничего не закоммичено и не отправлено.
