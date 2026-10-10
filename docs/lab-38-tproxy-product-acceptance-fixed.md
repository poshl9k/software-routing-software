# Lab-38 — TProxy product acceptance round 2: FAIL

10 октября 2026; одноразовая VM `vsr-clean-192a1d0`, branch `main`, локальный `c7927ad466f00c777c632b18d7e9916000261626`. Никаких commit/push и изменения публичного gate `tproxy.not_available`. Команды гостя выполнялись через `python3 /home/poshl9k/.hermes/cache/scratch/ui-ux-review/gexec.py vsr-clean-192a1d0 '<команда>'`; файлы переданы через `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py vsr-clean-192a1d0 --push <host> <guest>`. Ниже — наблюдения, не результат unit-теста.

## Исходное состояние и deploy

```
virsh -c qemu:///system list --all                # vsr-clean-192a1d0 работает
virsh -c qemu:///system snapshot-list vsr-clean-192a1d0
# pre-tproxy-1791616579 disk-snapshot
virsh -c qemu:///system snapshot-current vsr-clean-192a1d0 --name
# pre-tproxy-1791616579
virsh -c qemu:///system domiflist vsr-clean-192a1d0
# default 52:54:00:cc:00:01; vsr-verify-lan 52:54:00:cc:00:02
virsh -c qemu:///system domifaddr vsr-clean-192a1d0 --source lease
# vnet34 192.168.122.197/24
virsh -c qemu:///system qemu-agent-command vsr-clean-192a1d0 '{"execute":"guest-ping"}'
# {"return":{}}
```

В госте `vs-router-web`, `vs-router-agent`, `caddy` → `active`; Python distribution `vs-router-backend 0.1.0`, `/var/lib/vs-router/ui` присутствует, `/etc/vs-router/version.json` фиксирует ISO `192a1d0ab436cf96e7d640326f45840b69d86964`, management `enp2s0/192.168.10.1/24`. Проверен исходный marker: `version_id=5,status=confirmed`. VM — разрешённая одноразовая; rollback point существовал до вмешательства.

```
cd /home/poshl9k/GitHub/software-routing-software
uv build backend --wheel
# Successfully built backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# 9de3c3031a39c89ce0af11b252bf0d2b51504033c4235654b384c5ec304c1ca6
python3 -m http.server 18992 --bind 192.168.10.254 # cwd backend/dist, временный host server
# guest:
curl -fsS --max-time 15 -o /root/vs_router_backend-0.1.0-py3-none-any.whl http://192.168.10.254:18992/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum /root/vs_router_backend-0.1.0-py3-none-any.whl
# 9de3c3031a39c89ce0af11b252bf0d2b51504033c4235654b384c5ec304c1ca6
python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl
# Successfully installed vs-router-backend-0.1.0
systemctl restart vs-router-agent vs-router-web
systemctl is-active vs-router-agent vs-router-web caddy
# active / active / active
```

После wheel выполнены только необходимые provisioning-действия из `backend/packaging/install.sh`, а не полный install.sh (полный скрипт также останавливает web/agent, мигрирует DB, перезаписывает release identity и UI). Гостевые команды:

```
for spec in vs-router-unbound-selected:29092 vs-router-unbound-ordinary:29093; do
  name=${spec%:*}; uid=${spec#*:}
  if id -u "$name" >/dev/null 2>&1; then test "$(id -u "$name")" = "$uid" || exit 2;
  else useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --uid "$uid" "$name"; fi
  id "$name"
done
chmod o+x /etc/vs-router /etc/vs-router/applied
install -d /etc/apparmor.d/local; touch /etc/apparmor.d/local/usr.sbin.unbound
grep -qsF '/etc/vs-router/applied/** r,' /etc/apparmor.d/local/usr.sbin.unbound || printf '%s\n' '/etc/vs-router/applied/** r,' >> /etc/apparmor.d/local/usr.sbin.unbound
apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound
# uid=29092(...selected), uid=29093(...ordinary); paths 771 root:vs-router-web;
# local AppArmor rule /etc/vs-router/applied/** r,
```

`sha256sum backend/src/vs_router/agent/{apply,tproxy_apply,boot_restore,unbound_service,singbox_service}.py` на host и `sha256sum /usr/local/lib/python3.13/dist-packages/vs_router/agent/{apply,tproxy_apply,boot_restore,unbound_service,singbox_service}.py` в guest совпали попарно:

```
apply.py            0f2735a04a55ded27dce51ced613525de812fcddea2a5c66306933cae04726ce
tproxy_apply.py     6e77dbbc6c6bdc18c296e12c74f3d385f596fb1d6e6b97d9ef5738096b9f7cb2
boot_restore.py     bfdb39388194856162e9e78bebf7cdc9227d3d70c258108ddc879b92e689e08b
unbound_service.py  f97da789f26a6ebae08a8722f05d4d221ec151b98032dfa75844988399d881c6
singbox_service.py  871b23adb473d96bc3b3ffdf783d3fd45183ded5d41bba10ce9ea6fefb82a6ff
```

Первая попытка hash в `/usr/local/lib/python3.11/dist-packages` была ошибкой адреса: реальный guest Python — 3.13; повторена по фактическому import path. `version.json` умышленно не обновлён in-place deploy.

## Lab-bypass, draft, RPC

Временный `sitecustomize.py` (`/var/lib/vs-router/t2/sitecustomize.py`) при `VSR_T2_OFFLINE=1` оборачивает только `vs_router.validators.validate_configuration`: сохраняет `c.tproxy.enabled`, временно устанавливает `False` через `object.__setattr__`, вызывает оригинальную функцию, восстанавливает флаг в `finally`. Другие валидации/генераторы не подменены. Только agent получил `/etc/systemd/system/vs-router-agent.service.d/t2.conf`:

```
[Service]
Environment=VSR_T2_OFFLINE=1
Environment=PYTHONPATH=/var/lib/vs-router/t2
```

После `systemctl daemon-reload; systemctl restart vs-router-agent` гостевой `/var/lib/vs-router/t2/draft.py` прочёл confirmed row 5, обновил существующую draft row 6 посредством `api.configuration.validate(data, old)` → `parse_configuration(data, old)` → `validate_management(config, host_management())` → `validate_site_bindings(version, host_management())` → `tproxy_apply.build_artifacts(version)` → `draft.configuration=config; session.commit()`. Изменения относительно confirmed: `dns.interfaces=['enp2s0']`, `proxies.enabled=True`, direct outbound `lab_direct`, `tproxy.enabled=True`, ingress `enp2s0`, `lab_route` для `198.18.0.0/15` → `lab_direct`, `final='block'`. stdout:

```
VALIDATE {"valid": true, "errors": [], "warnings": []}
ARTIFACTS ['singbox', 'tproxy_guards', 'tproxy_interception', 'tproxy_unbound_ordinary', 'tproxy_unbound_selected']
DRAFT 6 baseline 5 ingress ('enp2s0',)
```

Гостевой RPC:

```
VSR_T2_OFFLINE=1 PYTHONPATH=/var/lib/vs-router/t2 python3 -c 'from vs_router.agent.daemon import UnixSocketTransport; from vs_router.agent.rpc import AgentClient; print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version", {"version_id":6,"safe_mode":False}))'
# {'version_id': 6, 'status': 'confirmed', 'phases': {... 'tproxy_guards': 'applied',
# 'tproxy_interception': 'applied', 'tproxy_policy_route': 'applied',
# 'unbound_process': 'applied', 'singbox_process': 'applied'}, 'error': None, ...}
cat /etc/vs-router/marker.json # version_id=6, status=confirmed
nft list tables
# inet vs_router, inet vs_router_tproxy_guard, inet vs_router_tproxy_ipv6_guard,
# inet vs_router_tproxy_preauth, inet vs_router_tproxy_dns_ingress,
# inet vs_router_tproxy_dns_listener, inet vs_router_tproxy_dns_output,
# inet vs_router_tproxy_ct_reset, inet vs_router_tproxy_interception,
# inet vs_router_tproxy_input, inet vs_router_ssh_bans
ip rule # 100: from all fwmark 0x100 lookup 100
ip route show table 100 # local default dev lo scope host
```

Машинное сравнение `owned_tables()` с `nft list tables` требовало префикс `table `: `owned_tables()` возвращает строки вида `inet vs_router_tproxy_guard`, а nft — `table inet vs_router_tproxy_guard`. Исправленный probe выдал `owned-present 9 / 9; missing []`. Промежуточный probe без префикса ложно выдал 0/9; он не принят за свидетельство пропажи.

## Split resolver

```
systemctl show vs-router-unbound-selected vs-router-unbound-ordinary -p User -p ExecMainStatus -p ActiveState
# selected User=29092 ExecMainStatus=0 ActiveState=active
# ordinary User=29093 ExecMainStatus=0 ActiveState=active
systemctl status vs-router-unbound-selected vs-router-unbound-ordinary --no-pager -l
# selected: /usr/sbin/unbound -d -c /etc/vs-router/applied/tproxy-unbound-selected.conf
# ordinary: /usr/sbin/unbound -d -c /etc/vs-router/applied/tproxy-unbound-ordinary.conf
stat -c '%a %U:%G %n' /etc/vs-router/applied/tproxy-unbound-{selected,ordinary}.conf
# 600 vs-router-unbound-selected:vs-router-web ...selected.conf
# 600 vs-router-unbound-ordinary:vs-router-web ...ordinary.conf
/usr/sbin/unbound-checkconf /etc/vs-router/applied/tproxy-unbound-selected.conf
/usr/sbin/unbound-checkconf /etc/vs-router/applied/tproxy-unbound-ordinary.conf
# no errors (оба)
ss -lntup
# selected 192.168.10.1:53 TCP/UDP, ordinary 127.0.0.1:53 TCP/UDP,
# sing-box 127.0.0.1:51271 UDP и :51272 TCP
```

Оба журнала содержат `error: cannot open pidfile /run/unbound.pid: Permission denied`, но процесс остаётся active. UDP DNS query `example.org A` через Python socket к `127.0.0.1:53` дал ответ с header `123485850001000000000000` (rcode 5/REFUSED для этого запроса); та же проба к `192.168.10.1:53` из guest истекла по timeout (локальный nft policy может блокировать этот путь). Поэтому запуск и чтение конфигов доказаны, а успешное разрешение публичного имени обычным resolver — **не доказано**. Не приравнивать active к working DNS. `dig` отсутствует.

## Настоящий reboot: FAIL

```
virsh -c qemu:///system reboot vsr-clean-192a1d0
# гостевой агент временно не подключён; через 15 секунд guest-ping → {"return":{}}
cat /proc/sys/kernel/random/boot_id
# a1083b1c-315d-43fc-af77-7058f35809c9
cat /etc/vs-router/marker.json
# version_id=6,status=confirmed (маркер от до-reboot apply, НЕ подтверждение post-boot readiness)
nft list tables
# есть guard, ipv6_guard, preauth, dns_ingress, dns_listener, dns_output;
# НЕТ interception, ct_reset, input
ip rule # только local/main/default, НЕТ fwmark 0x100
ip route show table 100 # Error: ipv4: FIB table does not exist.
systemctl is-active vs-router-bootrestore vs-router-agent vs-router-web caddy vs-router-unbound-selected vs-router-unbound-ordinary vs-router-singbox
# activating / inactive / active / inactive / inactive / inactive / inactive
journalctl -u vs-router-bootrestore -b --no-pager -n 45
# 13:49:37 TProxy resolver restore failed
# 13:49:53 TProxy engine restore failed
# 13:49:53 TProxy readiness incomplete; capture withheld (fail-closed)
# 13:49:53 SSH protection restore failed
# 13:49:53 boot-restore: TProxy fail-closed (1 substep failure(s))
# 13:49:53 boot-restore: 1 failures
# 13:49:53 vs-router-bootrestore.service: Failed with result 'exit-code'.
# затем повторный запуск, те же resolver/engine timeouts каждые ~16 с
systemctl status vs-router-bootrestore --no-pager -l
# Active: activating (start), child: systemctl restart vs-router-singbox.service
```

После дополнительного ожидания 36 секунд статус не восстановился; базовые agent/Caddy по-прежнему inactive, split DNS и sing-box inactive. `boot_restore.main()` не считает TProxy failures фатальными, но `restore_ssh()` при base restore печатает `SSH protection restore failed`, увеличивает `failures`, возвращает 1; следующий старт повторяет цепь. Внутренние `systemctl restart` резолверов/engine во время oneshot блокируются по зависимостям; первопричина этих блокировок по графу systemd отдельно не установлена. Нельзя утверждать, что agent/Caddy «всегда возвращаются»; на этой VM не вернулись. Защитные шесть таблиц остались; capture намеренно withheld. `sysctl -n net.ipv4.ip_forward` после reboot → `0`, `ip route show default` пусто.

## Fail-closed packet proof: FAIL / не выполнен

```
nft list chain inet vs_router_tproxy_guard forward
# iifname "enp2s0" counter packets 0 bytes 0 drop comment "tproxy_containment"
nft list chain inet vs_router forward
# policy drop; нет разрешающего lan→wan правила
```

НЕТ доказанного транзитного пакета: counter 0, нет reachable WAN origin с контрольной доставкой и конфигурацией разрешающего LAN→WAN firewall-правила, guest forwarding=0. Из «не дошло» нельзя сделать вывод о срабатывании guard; не отключали защиту для искусственного positive control на сломанном reboot. Для будущего доказательства нужны внешний LAN client через `enp2s0`, достижимый origin на WAN, подтверждённый pass firewall и ip_forward=1; сравнить полученный token при разрешённом пути с drop при fail-closed, показать Δ`tproxy_containment` и отсутствие token на origin. Этот критерий НЕ закрыт данным запуском.

## Откат и состояние VM

```
virsh -c qemu:///system snapshot-revert vsr-clean-192a1d0 pre-tproxy-1791616579
# Domain snapshot pre-tproxy-1791616579 reverted; domstate: выключен
virsh -c qemu:///system start vsr-clean-192a1d0
# запущен; guest-ping после boot → {"return":{}}
cat /etc/vs-router/marker.json # version_id=5,status=confirmed
systemctl is-active vs-router-bootrestore vs-router-agent vs-router-web caddy unbound kea-dhcp4-server
# active / active / active / active / active / active
nft list tables # inet vs_router; inet vs_router_ssh_bans
ip rule # local/main/default; нет fwmark 100
# test ! -f /etc/systemd/system/vs-router-agent.service.d/t2.conf → bypass-absent
# test ! -f /etc/vs-router/applied/tproxy-intercept.nft → intercept-absent
virsh -c qemu:///system snapshot-list vsr-clean-192a1d0
# pre-tproxy-1791616579 disk-snapshot сохранился
curl -sk -o /dev/null -w '%{http_code}\n' https://192.168.10.1/
# 200 (TLS trust НЕ проверен: -k)
git status --short # только этот новый docs/lab-38... файл
```

Rollback возвратил также старый wheel/UID/AppArmor: фикс НЕ оставлен в VM; это ожидаемое восстановление снимка. Рестарт web и rollback инвалидировали in-memory panel sessions: оператору нужно войти снова. Host HTTP сервер wheel выключить после работы. UI не деплоили: этот запуск проверяет backend + systemd, но панельный display не принят. Для проверки панели понадобится собрать и развернуть актуальный frontend bundle, подтвердить byte hash и изменённые строки по management-LAN HTTPS, а не судить по текущему ISO UI. Для нового прогона backend wheel и provisioning опять обязательны.

| Критерий | Итог |
|---|---|
| nft loaded before `confirmed` | PASS в момент apply: marker confirmed и все 9 owned tables присутствуют; causal ordering подтверждается реализацией, инструментального снимка прямо до записи marker нет |
| split Unbound | PARTIAL: юниты active, конфиги читаются, нет 217/USER; ordinary external DNS success не доказан, после reboot inactive |
| boot restore guards + interception + route + resolvers | FAIL: guards 6/9, interception 0/3, route отсутствует, resolvers inactive |
| fail-closed real packet + positive control | FAIL / не проверено: counter=0, forwarding=0, origin/control отсутствуют |
| reboot resilience agent/Caddy | FAIL: оба inactive после неоднократных попыток bootrestore |

Общий вердикт: **FAIL**. Публичный gate не открывать.
