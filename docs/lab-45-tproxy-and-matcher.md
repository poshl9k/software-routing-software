# Lab-45 — TProxy составной matcher: AND, пакетная перепроверка

11 октября 2026. Repo `930c106 merge ux/tpxfix`; ни commit, ни push, ни sudo, ни изменение сетевых настроек host. Одноразовый router `vsr-clean-16e76bf`, snapshot `clean-16e76bf-firstboot`; LAN-клиент `vsr-lab44-client` из overlay; host `br0=10.10.10.103` с теми же HTTP origins и Shadowsocks, что в lab-44. Проверка была именно с отдельной VM без WAN NIC. Секретов здесь нет: sing-box generator использует фиксированную тестовую заглушку, значение не приводится.

Команды гостю ниже: `G='python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py'`; запускать `$G <domain> '<shell>'`, передача `$G <domain> --push <host-file> <guest-file>`. Скрипты в `/home/poshl9k/.hermes/cache/scratch/lab45-draft.py` и `lab45-wan-draft.py`. У обоих продуктовый `create_draft` → `update_draft` → `validate_draft(body=None)` и management guards; прямых SQLite edits нет.

## Discovery, wheel

```
git status --short                         # пусто до опыта
git log -1 --oneline                       # 930c106 merge ux/tpxfix
virsh -c qemu:///system list --all          # vsr-clean-16e76bf running; vsr-clean-192a1d0 shut off
virsh -c qemu:///system snapshot-list vsr-clean-16e76bf
# clean-16e76bf-firstboot disk-snapshot
virsh -c qemu:///system snapshot-current vsr-clean-16e76bf --name
# clean-16e76bf-firstboot
virsh -c qemu:///system domiflist vsr-clean-16e76bf
# default 52:54:00:cc:00:01; vsr-verify-lan 52:54:00:cc:00:02
virsh -c qemu:///system domifaddr vsr-clean-16e76bf --source lease
# WAN 192.168.122.197/24
virsh -c qemu:///system qemu-agent-command vsr-clean-16e76bf '{"execute":"guest-ping"}'
# {"return":{}}
# guest: systemctl is-active vs-router-agent vs-router-web caddy -> active/active/active
# installed wheel 0.1.0; /var/lib/vs-router/ui exists;
# /var/lib/vs-router-bootstrap/management.json -> enp2s0/192.168.10.1/24;
# pre-test DB contained confirmed v1 (one LAN interface); marker confirmed v1.
uv build backend --wheel
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# 99992b2be822cabc55f60c9c7d577cb901e08d6ab1eb1c548e75799567ee4e28
uv run --directory backend pytest tests/test_singbox_outbounds.py -q
# 47 passed, 1 skipped
python3 -m http.server 18994 --bind 192.168.10.254  # host, backend/dist; stopped on cleanup
# guest:
curl -fsS -o /root/vs_router_backend-0.1.0-py3-none-any.whl http://192.168.10.254:18994/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum /root/vs_router_backend-0.1.0-py3-none-any.whl
# 99992b2be822cabc55f60c9c7d577cb901e08d6ab1eb1c548e75799567ee4e28
python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl
systemctl restart vs-router-agent
# agent/web/caddy active; installed vs_router.generators.singbox path
# /usr/local/lib/python3.13/dist-packages/vs_router/generators/singbox.py;
# route-part of installed generator contains no `logical` wrapper.
```

Перезапускали только agent: web-сессии этим шагом не сбрасывались. Снимок уже существовал. Panel HTTPS с `curl` без указания CA выдаёт ошибку issuer (код 60); отдельная диагностическая проверка `curl -k ... https://192.168.10.1/` вернула 200. Это НЕ подтверждение доверенной цепочки CA.

## Путь клиента и host services

Исходный VM WAN — libvirt NAT, не `br0`, в отличие от lab-44 до его отката. Чтобы origin увидел настоящий WAN router, подключена лишь временная NIC к уже существующему `br0` (`--live`, без `--config`), host bridge/IP/маршруты/firewall не менялись:

```
virsh -c qemu:///system attach-interface vsr-clean-16e76bf --type bridge --source br0 --model virtio --mac 52:54:00:cc:00:03 --live
# vnet63 bridge br0; guest MAC 52:54:00:cc:00:03 = enp7s0
# guest (временный файл; удалён возвратом snapshot):
printf '[Match]\nName=enp7s0\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n[DHCPv4]\nUseRoutes=false\n' > /etc/systemd/network/19-lab45-enp7s0.network
ip link set enp7s0 up
networkctl reload
networkctl reconfigure enp7s0
# ip -br addr show enp7s0 -> 10.10.10.148/24; DHCP via 10.10.10.1
# ip route get 10.10.10.103 -> dev enp7s0 src 10.10.10.148
qemu-img create -f qcow2 -F qcow2 -b /home/poshl9k/VMs/vsr-clean-192a1d0.qcow2 /home/poshl9k/VMs/vsr-lab44-client.qcow2
chgrp kvm /home/poshl9k/VMs/vsr-lab44-client.qcow2
chmod 664 /home/poshl9k/VMs/vsr-lab44-client.qcow2
virsh -c qemu:///system define /home/poshl9k/.hermes/cache/scratch/lab44-client.xml
virsh -c qemu:///system start vsr-lab44-client
virsh -c qemu:///system qemu-agent-command vsr-lab44-client '{"execute":"guest-ping"}'
# {"return":{}}
# client guest: stop/disable vs-router-web vs-router-agent vs-router-bootrestore caddy;
ip link set enp0s3 up
ip addr replace 192.168.10.50/24 dev enp0s3
ip route replace default via 192.168.10.1 dev enp0s3
ip route get 10.10.10.103
# via 192.168.10.1 dev enp0s3 src 192.168.10.50
```

Client XML как в lab-44: одна NIC `vsr-verify-lan` (MAC `52:54:00:cc:00:50`), `pc-i440fx-10.2`, guest agent. На host использован тот же `sing-box` 1.14.2 (revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`); архив SHA-256 `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6`. Команды запуска (отдельные фоновые процессы):

```
/home/poshl9k/.hermes/cache/scratch/sing-box-1.14.2-linux-amd64/sing-box check -c /home/poshl9k/.hermes/cache/scratch/lab44-proxy.json
# exit 0
/home/poshl9k/.hermes/cache/scratch/sing-box-1.14.2-linux-amd64/sing-box run -c /home/poshl9k/.hermes/cache/scratch/lab44-proxy.json > /home/poshl9k/.hermes/cache/scratch/lab45-proxy.log 2>&1
# из /home/poshl9k/.hermes/cache/scratch/lab44-origin:
python3 -m http.server 18874 --bind 10.10.10.103 > /home/poshl9k/.hermes/cache/scratch/lab45-origin-proxy.log 2>&1
python3 -m http.server 18875 --bind 10.10.10.103 > /home/poshl9k/.hermes/cache/scratch/lab45-origin-direct.log 2>&1
ss -ltnp '( sport = :18874 or sport = :18875 or sport = :18876 )'
# 10.10.10.103:18874 python3; :18875 python3; :18876 sing-box
```

## Продуктовый draft/apply, ошибка первого прогона и исправление

`lab45-draft.py` взял подтверждённую v1 через ORM: DNS listener enp2s0, ACL localhost+LAN, upstream `10.10.10.1`; proxies enabled, один Shadowsocks outbound `lab45_ss` к host `:18876`; TProxy ingress enp2s0, `final=direct`, ровно одно rule `ip_cidr=['10.10.10.103/32']`, `ports=['18874']`, `protocol=tcp`, `outbound=lab45_ss`; отдельные firewall pass для клиентского TCP к обоим портам. `validate(data, old)` и `validate_draft(body=None)` прошли; `validate_management`, `validate_site_bindings` прошли. Точный запуск:

```
$G vsr-clean-16e76bf --push /home/poshl9k/.hermes/cache/scratch/lab45-draft.py /root/lab45-draft.py
$G vsr-clean-16e76bf 'python3 /root/lab45-draft.py'
# VALIDATE {"valid": true, "errors": [], "warnings": []}
# CREATED 2
# DRAFT_VALIDATE {"valid": true, "errors": [], "warnings": []}
# FLAT_RULE {"ip_cidr": ["10.10.10.103/32"], "port": [18874], "network": ["tcp"], "action": "route", "outbound": "lab45_ss"}
# DRAFT 2 artifacts ['singbox', 'tproxy_guards', 'tproxy_interception', 'tproxy_unbound_ordinary', 'tproxy_unbound_selected']
$G vsr-clean-16e76bf 'python3 -c '\''from vs_router.agent.daemon import UnixSocketTransport;from vs_router.agent.rpc import AgentClient;print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version",{"version_id":2,"safe_mode":False}))'\'''
# status confirmed, all base and TProxy phases applied; error/reason/reason_service None
```

ПЕРВАЯ пара клиентских HTTP завершилась timeout (оба `RC=28`). Причина проверена по counters: `tproxy_preauth prerouting` drop 16 packets/2064 bytes, `tproxy_tcp=0`, transit-rule counters 0. В v1 единственный zoned interface был enp2s0 (LAN); FIB gate получился `fib daddr . mark oifname "enp2s0" goto transit`, а фактический egress `enp7s0`. Не считать первый apply доказательством AND.

Коррекция — продуктовый НОВЫЙ draft v3 на основе confirmed v2: добавить `{'name':'enp7s0','type':'physical','zone':'wan','addressing':'dhcp','addresses':[]}`. Ни изменённого matcher, ни bypass/gate, ни сырого UPDATE. Скрипт `lab45-wan-draft.py` выполняет этот переход:

```
$G vsr-clean-16e76bf --push /home/poshl9k/.hermes/cache/scratch/lab45-wan-draft.py /root/lab45-wan-draft.py
$G vsr-clean-16e76bf 'python3 /root/lab45-wan-draft.py'
# VALIDATE {"valid": true, "errors": [], "warnings": []}
# DRAFT_VALIDATE {"valid": true, "errors": [], "warnings": []}
# DRAFT 3 RULE {"ip_cidr": ["10.10.10.103/32"], "port": [18874], "network": ["tcp"], "action": "route", "outbound": "lab45_ss"}
$G vsr-clean-16e76bf 'python3 -c '\''from vs_router.agent.daemon import UnixSocketTransport;from vs_router.agent.rpc import AgentClient;print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version",{"version_id":3,"safe_mode":False}))'\'''
# {'version_id': 3, 'status': 'confirmed', 'phases': {'nftables': 'applied',
# 'unbound': 'applied', 'kea': 'applied', 'networkd': 'applied', 'wireguard':
# 'applied', 'caddy': 'applied', 'ddns': 'applied', 'ssh': 'applied',
# 'tproxy_guards': 'applied', 'tproxy_unbound_selected': 'applied',
# 'tproxy_unbound_ordinary': 'applied', 'singbox': 'applied',
# 'tproxy_interception': 'applied', 'tproxy_policy_route': 'applied',
# 'unbound_process': 'applied', 'singbox_process': 'applied'},
# 'error': None, 'reason': None, 'reason_service': None}
$G vsr-clean-16e76bf 'python3 -c '\''import json;print(json.load(open("/etc/vs-router/applied/singbox.json"))["route"])'\'''
# {'rules':[{'ip_cidr':['10.10.10.103/32'],'port':[18874],
#            'network':['tcp'],'action':'route','outbound':'lab45_ss'}],
#  'final':'direct','auto_detect_interface':True}
# preauth FIB gate: fib daddr . mark oifname { "enp2s0", "enp7s0" } goto transit
# ip route get 10.10.10.103 -> dev enp7s0 src 10.10.10.148
# agent/web/caddy/singbox/unbound-selected/unbound-ordinary -> active
```

## Решающий пакетный тест (v3)

Перед парой: `wc -l lab45-proxy.log lab45-origin-proxy.log lab45-origin-direct.log` → `6 / 1 / 1`. Перед парой counters вновь созданных preauth/transit, interception и containment были 0. С LAN-only client:

```
$G vsr-lab44-client 'curl --noproxy "*" -fsS --connect-timeout 4 --max-time 12 http://10.10.10.103:18874/proxy.txt; printf "SELECTED_RC=%s\n" "$?"; curl --noproxy "*" -fsS --connect-timeout 4 --max-time 12 http://10.10.10.103:18875/direct.txt; printf "NONMATCH_RC=%s\n" "$?"'
# LAB44-TARGET-THROUGH-PROXY
# SELECTED_RC=0
# LAB44-DIRECT-NONMATCH
# NONMATCH_RC=0
$G vsr-clean-16e76bf 'nft list chain inet vs_router_tproxy_preauth transit; nft list chain inet vs_router_tproxy_interception prerouting; nft list chain inet vs_router_tproxy_guard forward'
# preauth lab45_tcp_18874 counter packets 5 bytes 359
# preauth lab45_tcp_18875 counter packets 6 bytes 412
# tproxy_tcp counter packets 11 bytes 771; tproxy_udp 0
# tproxy_containment drop counter packets 0 bytes 0
```

Оба направления попали в TProxy capture (поэтому один только `tproxy_tcp` НЕ доказывает AND). Роутинг определяется flat sing-box rule. Только ПОСЛЕ исходной точки лог outbound содержит `inbound connection from 10.10.10.148:50844`, `inbound connection to 10.10.10.103:18874`, `outbound connection to 10.10.10.103:18874` (15:17:05); строки про `:18875` в outbound log нет. Origin :18874 зафиксировал `10.10.10.103 ... "GET /proxy.txt HTTP/1.1" 200` (локальный выход host proxy), origin :18875 зафиксировал `10.10.10.148 ... "GET /direct.txt HTTP/1.1" 200` (WAN router). И `:18874`, и `:18875` ведут на ОДИН IP, отличается только порт. Так исключено ложное OR-поведение lab-44 v3.

| Критерий | Итог |
|---|---|
| Current local wheel развернут и agent перезапущен; сохранённое составное правило flat, без logical OR | PASS: wheel SHA совпал, applied JSON показан выше |
| Продуктовый validate/apply без bypass | PASS: v3 confirmed, все TProxy фазы applied |
| IP И port совпадают (`:18874`): outbound, token | PASS: outbound log `:18874`, origin source proxy, HTTP 200 |
| Тот же IP, другой port (`:18875`): не outbound, direct | PASS: нет строки в outbound log, origin source `10.10.10.148`, HTTP 200 |
| Counters показывают реальные LAN packets | PASS: preauth `5+6`, capture `11`, containment `0` |
| Первый apply v2 до назначения zoned WAN | FAIL как тест пакетов: preauth drop 16, оба timeout; исправлен v3 |
| Очистка extra resources / snapshot | PASS для rollback snapshot, но НЕ для восстановления pre-test confirmed v1 (ниже) |

## Очистка и границы отката

```
# остановить только созданные в этом прогоне host процессы :18874/:18875/:18876/:18994
ss -ltnp '( sport = :18874 or sport = :18875 or sport = :18876 or sport = :18994 )'
# пусто
virsh -c qemu:///system destroy vsr-lab44-client
virsh -c qemu:///system undefine vsr-lab44-client
rm /home/poshl9k/VMs/vsr-lab44-client.qcow2
virsh -c qemu:///system snapshot-revert vsr-clean-16e76bf clean-16e76bf-firstboot
virsh -c qemu:///system start vsr-clean-16e76bf
# сразу guest-ping: QEMU guest agent not connected; через 15 секунд: {"return":{}}
```

После revert `domiflist` → исходные `default` + `vsr-verify-lan`, временная br0 NIC исчезла; client overlay отсутствует; `virsh list --all` → только router running и `vsr-clean-192a1d0` shut off. Guest agent/web/Caddy active, LAN HTTPS с `curl -k` HTTP 200. `nft list tables` → только `inet vs_router` и `inet vs_router_ssh_lock`, lab DHCP file отсутствует, marker отсутствует. `ss` по четырём временным портам пуст. Созданная раньше сеть `vsr-verify-lan` не менялась и не удалялась.

ВАЖНО: как в lab-44, `clean-16e76bf-firstboot` предшествует confirmed конфигурациям. Непосредственно перед тестом существовала v1; ПОСЛЕ rollback `ConfigurationRow` → `[]`, `/run/vs-router/marker.json` отсутствует, старый установленный wheel опять содержит `tproxy.not_available` (`True`). Это корректный откат к snapshot, но НЕ восстановление прежней v1 или проверенной v3. Чтобы повторить опыт, заново установить wheel и создать baseline/draft; не считать guest после отката готовым router config.

`git status --short` до создания этого отчёта был пуст; после — только `?? docs/lab-45-tproxy-and-matcher.md`. `git diff --check` → exit 0. Ни commit, ни push.
