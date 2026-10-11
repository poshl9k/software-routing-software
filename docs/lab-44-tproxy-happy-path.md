# Lab-44 — здоровый TProxy → outbound (пакетный E2E)

11 октября 2026. Одноразовый `vsr-clean-16e76bf` (ISO revision `16e76bf39c4135138b6065401ebc97753565a738`, disk snapshot `clean-16e76bf-firstboot`), одноинтерфейсный клиент `vsr-lab44-client` на существующей host-only сети `vsr-verify-lan`, sing-box Shadowsocks-сервер и два HTTP origin на host `br0` (`10.10.10.103`). Host bridge/IP/маршруты/firewall не изменялись; `sudo`, push и commit не применялись. Proxy listener на реальном LAN host запускался только на время опыта и выключен при очистке. Фиксированный пароль из генератора — тестовая заглушка, не пользовательский секрет; значение не приводится.

Команды гостю ниже выполнялись через `python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py <domain> '<shell>'`; файлы передавались этим же helper с `--push <host-file> <guest-file>`. Оба скрипта подготовки draft находятся в scratch: `/home/poshl9k/.hermes/cache/scratch/lab44-draft.py` и `lab44-revise.py`. Они вызывают функции продуктовых `create_draft`, `update_draft`, `validate_draft` с SQLAlchemy Session; никаких сырых SQLite UPDATE. Apply — `AgentClient.call('apply_version', {'version_id': 4, 'safe_mode': False})` по root-owned Unix socket. Доступность панели по HTTPS проверена, вход в браузер под admin не выполнялся; UI подтверждён данными panel view, реально выданным bundle и тестами, но не интерактивным браузерным сеансом.

## Discovery и сборка

```
virsh -c qemu:///system list --all
# vsr-clean-16e76bf running; vsr-clean-192a1d0 shut off
virsh -c qemu:///system snapshot-list vsr-clean-16e76bf
# clean-16e76bf-firstboot disk-snapshot
virsh -c qemu:///system snapshot-current vsr-clean-16e76bf --name
# clean-16e76bf-firstboot
virsh -c qemu:///system domiflist vsr-clean-16e76bf
# br0 52:54:00:cc:00:01; vsr-verify-lan 52:54:00:cc:00:02
virsh -c qemu:///system qemu-agent-command vsr-clean-16e76bf '{"execute":"guest-ping"}'
# {"return":{}}
# guest: vs-router-agent/web/caddy active; wheel 0.1.0; UI present;
# management enp2s0/192.168.10.1/24, WAN enp1s0/10.10.10.146/24;
# marker 2 confirmed; pinned /usr/local/lib/vs-router/sing-box 1.14.2;
# UID 29092/29093 and vs-router-tproxy-postboot already provisioned, ip_forward=1.
uv build backend --wheel
sha256sum backend/dist/vs_router_backend-0.1.0-py3-none-any.whl
# b3afa3b264168182eeab79f32a80d921ff471ddcb56805ee6e40af0a1eb7ef98
# host: from backend/dist, python3 -m http.server 18994 --bind 192.168.10.254
# guest:
curl -fsS -o /root/vs_router_backend-0.1.0-py3-none-any.whl http://192.168.10.254:18994/vs_router_backend-0.1.0-py3-none-any.whl
sha256sum /root/vs_router_backend-0.1.0-py3-none-any.whl
# b3afa3b264168182eeab79f32a80d921ff471ddcb56805ee6e40af0a1eb7ef98
python3 -m pip install --break-system-packages --no-deps --force-reinstall /root/vs_router_backend-0.1.0-py3-none-any.whl
systemctl restart vs-router-agent vs-router-web
# active / active; caddy active
python3 -c 'import inspect,vs_router.validators as v;print(inspect.getsourcefile(v),"tproxy.not_available" in inspect.getsource(v))'
# /usr/local/lib/python3.13/dist-packages/vs_router/validators.py False
```

Рестарт web сбрасывает in-memory sessions. Новых Python dependencies wheel не требовал. Полный packaging `install.sh` НЕ перезапускался: нужные UID, Unbound/AppArmor, postboot, sing-box binary и forwarding уже были provisioned на этой чистой VM. Valid enabled config дополнительно принят штатным `validate_draft`: `{'valid': True, 'errors': [], 'warnings': []}`.

## Клиент и outbound

```
qemu-img create -f qcow2 -F qcow2 -b /home/poshl9k/VMs/vsr-clean-192a1d0.qcow2 /home/poshl9k/VMs/vsr-lab44-client.qcow2
chgrp kvm /home/poshl9k/VMs/vsr-lab44-client.qcow2
chmod 664 /home/poshl9k/VMs/vsr-lab44-client.qcow2
virsh -c qemu:///system define /home/poshl9k/.hermes/cache/scratch/lab44-client.xml
virsh -c qemu:///system start vsr-lab44-client
virsh -c qemu:///system qemu-agent-command vsr-lab44-client '{"execute":"guest-ping"}'
# {"return":{}}
# client guest: stop/disable vs-router-web/agent/bootrestore/caddy;
ip link set enp0s3 up
ip addr replace 192.168.10.50/24 dev enp0s3
ip route replace default via 192.168.10.1 dev enp0s3
ip route get 10.10.10.103
# 10.10.10.103 via 192.168.10.1 dev enp0s3 src 192.168.10.50
```

Client XML: `pc-i440fx-10.2`, одна NIC `vsr-verify-lan` (`52:54:00:cc:00:50`), virtio disk/guest agent. На host скачан pinned archive `sing-box-1.14.2-linux-amd64.tar.gz` из GitHub release v1.14.2; `sha256sum -c` с пином `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` → `OK`; `sing-box version` → `1.14.2`, revision `af6e64c3b69e6132ebaee0e1a3d24e93903f6709`. Серверный конфиг в scratch `lab44-proxy.json`: inbound Shadowsocks `10.10.10.103:18876`, `chacha20-ietf-poly1305`, пароль равен фиксированной не-секретной заглушке продуктового генератора, outbound direct; `sing-box check -c ...` → exit 0. Запущен `sing-box run -c ...`, debug log в `lab44-proxy.log`. Два HTTP сервера из `lab44-origin/`:

```
python3 -m http.server 18874 --bind 10.10.10.103   # proxy.txt
python3 -m http.server 18875 --bind 10.10.10.103   # direct.txt
ss -ltnp '( sport = :18874 or sport = :18875 or sport = :18876 )'
# LISTEN 10.10.10.103:18874 python3; :18875 python3; :18876 sing-box
```

## Draft и apply

`lab44-draft.py`: копирует confirmed v2 через `create_draft(body=None,db=db)` → `update_draft(body=data,db=db)`; устанавливает `dns.interfaces=['enp2s0']`, ACL localhost+LAN, upstream `10.10.10.1`; `proxies.enabled=true`, один Shadowsocks outbound `lab44_ss` к `10.10.10.103:18876`; TProxy `enabled=true`, ingress `enp2s0`, `final=direct`; firewall pass только для TCP от клиента к origin-портам 18874/18875. `validate(data,old)` → valid; `validate_management` и `validate_site_bindings` → без ошибок; `build_artifacts` → `singbox`, `tproxy_guards`, `tproxy_interception`, `tproxy_unbound_ordinary`, `tproxy_unbound_selected`. Функцию `validate_draft` при прямом Python-вызове надо вызывать с `body=None`: её FastAPI-default `Body(...)` сам по себе не JSON. Первый вызов без этого аргумента ложно выдал `model_type`; с `body=None`: valid.

Первый draft v3 имел rule с `ip_cidr=['10.10.10.103/32']` И `ports=['18874']`. Хотя apply v3 дал `confirmed` и оба HTTP 200, generated sing-box route оказался `logical OR` между IP и port; прокси получил И :18874, И :18875. Это не доказательство nonmatch, результат отклонён. Без правок продуктового кода создан новый draft v4 из confirmed v3, оставлен только matcher `ports=['18874']`, `protocol=any` (один конкретный целевой TCP endpoint, другой порт того же host не совпадает). `lab44-revise.py` делает тот же штатный create/update/validate/management path:

```
python3 /root/lab44-revise.py
# VALIDATE {'valid': True, 'errors': [], 'warnings': []} DRAFT 4
# RULE {'name':'lab44_selected', 'ip_cidr':(), 'ports':('18874',),
#       'action':'route', 'outbound':'lab44_ss', ...}
python3 -c 'from vs_router.agent.daemon import UnixSocketTransport; from vs_router.agent.rpc import AgentClient; print(AgentClient(UnixSocketTransport("/run/vs-router/agent.sock")).call("apply_version",{"version_id":4,"safe_mode":False}))'
# {'version_id': 4, 'status': 'confirmed', 'phases': {...,
#  'tproxy_guards':'applied','tproxy_unbound_selected':'applied',
#  'tproxy_unbound_ordinary':'applied','singbox':'applied',
#  'tproxy_interception':'applied','tproxy_policy_route':'applied',
#  'unbound_process':'applied','singbox_process':'applied'},
#  'error':None,'reason':None,'reason_service':None}
python3 -c 'import json; v=json.load(open("/etc/vs-router/applied/singbox.json"));print(v["route"])'
# {'rules':[{'port':[18874],'action':'route','outbound':'lab44_ss'}],
#  'final':'direct','auto_detect_interface':True}
```

Никакой lab bypass/sitecustomize не применялся. `nft list chain inet vs_router_tproxy_interception prerouting` после запроса: `tproxy_tcp counter packets 10 bytes 719`; `tproxy_guard forward` containment packets 0; `vs-router-agent/web/caddy/singbox/unbound-selected/unbound-ordinary` все active. Контрольная точка перед окончательной парой запросов: лог outbound 16 строк, оба origin-лога по 3 строки (включая прежние пробы v3).

## Пакеты: финальная пара, v4

```
# guest vsr-lab44-client (только enp0s3; curl --noproxy '*' исключает env proxy):
curl --noproxy '*' -fsS --connect-timeout 4 --max-time 12 http://10.10.10.103:18874/proxy.txt
# LAB44-TARGET-THROUGH-PROXY; SELECTED_RC=0
curl --noproxy '*' -fsS --connect-timeout 4 --max-time 12 http://10.10.10.103:18875/direct.txt
# LAB44-DIRECT-NONMATCH; NONMATCH_RC=0
```

Outbound `lab44-proxy.log`, строки ПОСЛЕ контрольной точки: `inbound/shadowsocks[lab44-in]: inbound connection from 10.10.10.146:34482`, `inbound connection to 10.10.10.103:18874`, `outbound/direct[direct]: outbound connection to 10.10.10.103:18874`. Новой строки про :18875 после контрольной точки НЕТ. Origin-логи в ту же секунду: `proxy.txt` → source `10.10.10.103` (локальный выход host proxy); `direct.txt` → source `10.10.10.146` (WAN router, NAT). Это различает пути независимо от двух HTTP 200. `tproxy_tcp` counter >0 подтверждает перехват; клиент не имеет WAN NIC, host-local curl за него не выдавался.

Дифференциальная проба: остановлен ТОЛЬКО host proxy listener :18876 (никаких nft удалений/исключений); с того же клиента selected → `HTTP=000 bytes=0`, `curl RC=56 Recv failure: Connection reset by peer`; direct → `LAB44-DIRECT-NONMATCH`, `RC=0`. После повторного запуска listener selected → `LAB44-TARGET-THROUGH-PROXY`, `RECOVERY_RC=0`; marker v4 остался confirmed. Это доказывает зависимость выбранного трафика от outbound, а не прямой WAN-leak. Такой отказ не равен тесту автоматического fail-closed при падении router sing-box — последний отдельно проверялся в lab-40.

## Панель / ограничение

`ConfigurationRow` через `view(row)` для v4 вернул `{'id':4,'status':'confirmed'}`; сохранённая `tproxy.enabled=True`, rule outbound `lab44_ss`; host marker v4 `status=confirmed` и перечисленные фазы. Текущий frontend собран `npm run build`, `dist` передан по host-only `192.168.10.254:18995`, SHA-256 tar на обеих сторонах `f72d8e0a3d8bb924f88b54b1353c35f6fb2185425f9b4a5ccf83a69ec59bafa1`, UI dir полностью очищен и разархивирован с `chmod -R a+rX`, web перезапущен. HTTPS `https://192.168.10.1/` → HTTP 200; выданный index байт-в-байт равен `dist/index.html`, выданный `/assets/index-Fih65I6V.js` равен локальной сборке, SHA-256 `9a20b31e96b1e3b292325e748ac3968b9973ce15c321c16ed1a3247eee7b5b98`; в нём есть `Применено: включено`, нет `tproxy.not_available`. `npx vitest run src/test/routing.test.tsx` → 15/15 PASS, включая confirmed-enabled label и save enabled draft. HTTPS hash сверялся с отключённой CA-проверкой (`ssl._create_unverified_context`); браузер под admin не открывался: фактическое отображение конкретной строки в живой авторизованной сессии отдельно не доказано. Рестарт web требует повторного login.

Отдельно выявлен баг семантики: несколько matcher-полей в одном TProxy rule превращаются в sing-box `logical OR`, не AND. Поэтому v3 не удовлетворял критерию nonmatch; финальное доказательство опирается только на однопольное правило v4. Исправление этого бага не входило в опыт и не делалось.

## Очистка / rollback

Команды и проверка после опыта (исполнены; см. итог ниже):

```
virsh -c qemu:///system destroy vsr-lab44-client
virsh -c qemu:///system undefine vsr-lab44-client
rm /home/poshl9k/VMs/vsr-lab44-client.qcow2
virsh -c qemu:///system snapshot-revert vsr-clean-16e76bf clean-16e76bf-firstboot
# если snapshot выключает гостя: virsh -c qemu:///system start vsr-clean-16e76bf
# остановить фоновые host HTTP :18874/:18875, host sing-box :18876,
# file servers :18994/:18995; не уничтожать уже существующую сеть vsr-verify-lan.
```

| Критерий | Итог |
|---|---|
| Gate открыт в установленном wheel; enabled draft прошёл продуктовый validate | PASS |
| Apply v4 confirmed, TProxy guard/readiness/capture/policy phases applied | PASS |
| Отдельный LAN-клиент → захват → Shadowsocks outbound → origin, лог outbound + token | PASS |
| Не совпавший endpoint :18875 → direct, нет записи outbound; origin видит WAN IP router | PASS |
| Выключенный outbound: выбранный поток не течёт direct, nonmatch работает; восстановление | PASS |
| Состояние конфигурации/UI без ложного gate: view + реально выданный bundle + UI tests | PASS по данным/asset; браузерный login не выполнялся |
| Составное правило IP+port как AND | FAIL: фактически OR; использовано однопольное правило |
| Очистка disposable-ресурсов и snapshot | PARTIAL: ресурсы удалены и snapshot восстановлен; snapshot старше предтестовой конфигурации v2 (см. ниже) |

Итог: healthy interception → outbound **доказан** для выбранного TCP endpoint (:18874); контроль прямого nonmatch (:18875) и зависимость от доступности outbound доказаны отдельными пакетными запросами. Не обобщать на UDP, домены, составные matchers или browser login.

Post-clean verification (реальный вывод): `virsh destroy/undefine vsr-lab44-client` → домен удалён; overlay отсутствует; `snapshot-revert vsr-clean-16e76bf clean-16e76bf-firstboot` → reverted, гость был выключен; `virsh start` → running; первый `guest-ping` сразу после старта не отвечал, после 18 секунд → `{"return":{}}`. `systemctl is-active vs-router-agent vs-router-web caddy` → active/active/active, LAN HTTPS → 200. `nft list tables` → только `inet vs_router`, `inet vs_router_ssh_lock`; TProxy-owned таблиц нет. `ss -ltnp` по :18874/:18875/:18876/:18994/:18995 → нет listeners. `virsh list --all` → только running `vsr-clean-16e76bf` и shut off `vsr-clean-192a1d0`. Клиентский домен/overlay удалён; существующая сеть `vsr-verify-lan` не менялась/не удалялась.

ВАЖНО: snapshot `clean-16e76bf-firstboot` сделан ДО первоначальной конфигурации v2. После rollback в DB `ConfigurationRow` → `[]`, `/run/vs-router/marker.json` отсутствует, а installed wheel снова содержит `tproxy.not_available` (`True`). `/var/lib/vs-router-bootstrap/succeeded` присутствует, web/agent/Caddy активны. Поэтому очистка действительно вернула гостя к САМОМУ snapshot, но НЕ к предтестовому состоянию с confirmed v2. Это потеря созданных после snapshot конфигураций; их восстановление не заявляется. Для дальнейшей работы понадобится заново создать draft/применить конфигурацию или восстановить отдельную копию DB, если она существует. Этот факт ограничивает PASS строки cleanup: extra resources удалены и rollback сработал; предтестовая конфигурация v2 НЕ восстановлена.

`git status --short` → `?? docs/lab-44-tproxy-happy-path.md`; `git diff --check` → exit 0. Ничего не закоммичено и не отправлено.
