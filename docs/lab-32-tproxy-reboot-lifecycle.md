# Lab-32: реальный reboot — systemd-lifecycle TProxy и восстановление защиты

Дата: 7 октября 2026. Одноразовая Debian 13 VM `vsr-tproxy-lab`
(kernel `6.12.107+deb13-amd64`, nftables, python3.13, systemd). Рабочий домен
`vsr-live-403ab3a` не затрагивался. Публичный gate `tproxy.not_available`
**не открывался**: включённый снапшот получен только офлайн через штатный
lab-механизм `model_copy` (как в lab-24/27/29/30/31).

Эта задача закрывает остаток lab-30 «reboot — только эмуляция пере-применения»:
artefacts впервые восстановлены на **настоящей** перезагрузке гостя.
Откатная точка: `virsh snapshot-create-as vsr-tproxy-lab
pre-reboot-2026-10-07 --disk-only --atomic` (создан перед экспериментом;
ранее существующий `pre-singbox-2026` не тронут).

## Зачем

`agent/singbox_service.py` генерирует systemd-юнит закреплённого бинарника
(ADR-0012) и умеет start/stop/readiness (`sing-box check -c`); каркас apply/boot
(`agent/tproxy_apply.py`, `agent/boot_restore.py`) поднимает guards **до** тракта.
Настоящей перезагрузки стенда до сих пор не выполнялось, поэтому было
неизвестно, переживают ли reboot сам systemd-юнит движка, загрузка guards,
policy route, capture-таблицы и default-deny, и сохраняется ли порядок
«сначала защита, потом тракт».

## Что построено

Все артефакты — из **настоящих** генераторов через интегрированный контур
(`generate_nftables`, `tproxy_apply.guard_content`,
`generate_tproxy_interception`, `generate_singbox`, `tproxy_apply.build_artifacts`,
`marks.POLICY_ROUTES`). Юнит движка — буквальный вывод
`agent.singbox_service.unit_content()`. Один lab-scaffold (`LAB_INPUT_ACCEPT`,
accept в INPUT по `ct mark & 0x200`) — та же смоделированная авторизация, что и
в lab-30/31.

| Файл | SHA256 |
| --- | --- |
| `backend/tests/lab/tproxy_reboot_probe.py` | `4f75be0107772772e0deb657009475516113f0c4daf0cffa3992c9bfbfbf2e60` |
| `backend/tests/lab/generate_tproxy_reboot_case.py` | `fab756627c12b32c0730f6c1a189a4153dc80816170f75e6df01f93b34c67eab` |
| `backend/tests/lab/tproxy_reboot_boot.sh` | `63b51affd9bf80a96c99124597ea55ca426d5252af19ef19d282672281f2ef59` |
| `tproxy-guards.nft` (generator output) | `5498f177c75f682f6a999b92eb5886e1bf4f72d36e58b49dfe00099ce678b95c` |
| `tproxy-intercept.nft` (generator output) | `954d2a1dfdf6ba46ce640a02025f0f369cc22476c26c0b969d454370b6fc2dbc` |
| `ordinary-firewall.nft` (+lab scaffold) | `6ed7647eacbc5a4580fe455858ae7f1fd8f1249e7cff71d3c9278ece9c4075c8` |
| `default-deny.nft` | `0ea4edae0400271f208164e4e0344adc9c706dabc413d59ee940a80e530d0d61` |
| `singbox.json` (generator output) | `7c8d9520191cc7502b428eb0ea001f4b9c57187efbef3c3bd36a86b48ec4fc82` |
| pinned binary `/usr/local/lib/vs-router/sing-box` | `fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8` (ADR-0012, подтверждён `sing-box version` + sha256sum) |

### LAB-харнесс boot-восстановления (не продуктовая служба)

`vsr-tproxy-lab-boot.service` (oneshot, `RemainAfterExit`, `WantedBy=multi-user`)
запускает `lab-boot.sh`, который повторяет **порядок продукта**
(`tproxy_apply.PHASE_ORDER` + `READINESS_STEPS`):

```
phase 1  guards       ordinary firewall + containment/preauth/DNS guards  -> fail-closed
phase 2  readiness    systemd-юнит движка (pinned sing-box) + policy route
phase 3  interception capture/reset/input-guard таблицы, строго последними
```

Скрипт пишет журнал порядка в `/run/vsr-tproxy-boot-order.log`. Между фазой 1 и
фазой 3 стоит явная проверка: если capture-таблица уже существует — процесс
падает. Продуктовый `boot_restore.py` восстанавливает только guard-файл; этот
харнесс расширяет тот же порядок до движка и capture-таблиц, чтобы reboot был
наблюдаем. Это **lab-only** надстройка.

### Два реальных дефекта, вскрытых reboot-ом

1. **Сгенерированный юнит движка не стартует под своим sandbox.** Пин
   `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` рубит `AF_NETLINK`, нужный
   `sing-box v1.14.2` (`auto_detect_interface`). journal:

   ```
   FATAL start service: create netlink socket: address family not supported by protocol
   ```

   Юнит установлен байт-в-байт; чтобы движок стал ready, добавлен lab-drop-in
   (`vs-router-singbox.service.d/lab-netlink.conf`), снимающий ровно этот knob
   (`… AF_UNIX AF_NETLINK`). Это **lab-deviation**, а не продуктовая рекомендация.

2. **`auto_detect_interface` выбирает management-NIC.** На гостe единственный
   default-route на загрузке — management-uplink `enp1s0`, поэтому `direct`
   outbound bind'ится к нему и не доходит до lab-origin на `wan0`
   (`journal: updated default interface enp1s0`, затем `dial tcp 198.18.0.2:19090:
   i/o timeout`). Для data-path-проверки проба временно направляет ROOT default
   на lab-WAN (`wan0`) и перезапускает движок — движок по netlink-монитору
   переключается на `wan0` (`updated default interface wan0`). Прежний default
   восстанавливается в cleanup. Это **lab-topology artifact**, не продуктовая
   претензия.

## Реальный reboot (успешный сценарий)

Порядок выполнения:

```
virsh -c qemu:///system reboot vsr-tproxy-lab      # ACPI reboot, 22:11:02 MSK
# guest-agent (virtio-serial) переживает reboot: ping снова отвечает через ~15 c
uptime -> "up 0 min"                                # подтверждение настоящей перезагрузки
```

После загрузки harness отработал сам (enabled-юнит). Журнал порядка
`/run/vsr-tproxy-boot-order.log` (свежий, 19:11:14 UTC — время загрузки):

```
2026-10-07T19:11:14+00:00 PHASE_START pid=679
2026-10-07T19:11:14+00:00 GUARDS_UP interception_absent=yes
2026-10-07T19:11:14+00:00 READINESS_UP engine_active=yes policy_route=yes
2026-10-07T19:11:14+00:00 INTERCEPTION_UP capture_loaded=yes
2026-10-07T19:11:14+00:00 PHASE_DONE
```

Наблюдалось после reboot (автоматически, без ручных действий):

- `vs-router-singbox.service` — `active`; `vsr-tproxy-lab-boot.service` — `active`.
- Движок ready: `ss -lntu` → `127.0.0.1:51272` (tcp) и `127.0.0.1:51271` (udp);
  journal движка: `inbound/tproxy[tproxy-tcp]: tcp server started`.
- Все 9 таблиц на месте: `vs_router`, `…_tproxy_guard`, `…_preauth`,
  `…_dns_ingress`, `…_dns_listener`, `…_dns_output`, `…_ct_reset`,
  `…_tproxy_interception`, `…_tproxy_input`.
- Guards подняты **до** тракта: журнал `GUARDS_UP interception_absent=yes`
  раньше `INTERCEPTION_UP`; между фазами capture-таблицы нет.
- policy route: `ip rule` → `100: from all fwmark 0x100 lookup 100`;
  `ip route show table 100` → `local default dev lo scope host`.

Data-path проверка после reboot (`tproxy_reboot_probe.py normal`; клиенты/origin —
в короткоживущих netns, роутер — persistent root-ns состояние):

```
{"scenario": "state_after_boot",    "status": "PASS", "detail": "tables ok, unit=active"}
{"scenario": "allowed_tcp_selected","status": "PASS", "detail": "proxied, origin_peer=10.212.2.1"}
{"scenario": "denied_tcp_selected", "status": "PASS", "detail": "blocked at preauth, origin empty"}
{"scenario": "default_deny_held",   "status": "PASS", "detail": "ordinary denied blocked by FORWARD default-deny"}
{"summary": {"mode": "normal", "pass": 4, "failed": []}}
```

Движок в journal: `inbound connection from 10.212.1.2 → to 198.18.0.2:19090`,
`outbound/direct[direct]: outbound connection to 198.18.0.2:19090`; capture-счётчик
`tproxy_tcp` растёт. Разрешённый selected-flow реально пошёл через прокси
(origin видит src роутера), запрещённый режется preauth, unselected —
FORWARD default-deny.

## Отказной сценарий reboot-а (движок битый)

Движок сломан: `mv /etc/vs-router/applied/singbox.json singbox.json.bak`, затем
реальная перезагрузка. Журнал порядка:

```
2026-10-07T19:12:09+00:00 PHASE_START pid=703
2026-10-07T19:12:10+00:00 GUARDS_UP interception_absent=yes
2026-10-07T19:12:18+00:00 FATAL readiness failed: engine not active/listening -> interception withheld (fail-closed)
```

Наблюдалось: `vsr-tproxy-lab-boot.service` — `failed`; `vs-router-singbox.service`
— `failed`; **guards/firewall/default-deny присутствуют**, capture-таблиц нет
(`…_ct_reset/_interception/_input` отсутствуют), policy route отсутствует.
Тракт остался fail-closed.

Проверка (`tproxy_reboot_probe.py failclosed`):

```
{"scenario": "state_after_boot",     "status": "PASS", "detail": "tables ok, unit=failed"}
{"scenario": "allowed_tcp_selected", "status": "PASS", "detail": "allowed flow dropped, containment hit, origin empty"}
{"scenario": "denied_tcp_selected",  "status": "PASS", "detail": "blocked at preauth, origin empty"}
{"scenario": "default_deny_held",    "status": "PASS", "detail": "ordinary denied blocked by FORWARD default-deny"}
{"summary": {"mode": "failclosed", "pass": 4, "failed": []}}
```

То есть при мёртвом движке разрешённый selected-flow **не** доходит до origin
(его ловит независимый containment `-10`), запрещённый режется preauth,
default-deny держится; capture не появился. Утечки нет.

## Cleanup (фактическое состояние гостя)

`vsr-tproxy-lab` возвращён в обычное состояние (удалены: обе службы и drop-in,
`/etc/vs-router`, `/usr/local/lib/vs-router`, все lab-таблицы nft, `ip rule`/`route
table 100`, временные netns и veth). Итог:

```
nft tables:                     (пусто)
ip rule:                        0/32766/32767 default
route table100:                 FIB table does not exist
netns:                          (пусто)
links lan0/lan1/wan0:           none
default route:                  via 192.168.122.1 dev enp1s0 (DHCP)
systemctl list-unit-files 'vs*': 0 unit files
/applied, /lib:                 отсутствуют
```

Откатная точка `pre-reboot-2026-10-07` оставлена (не удалялась). `vsr-live-403ab3a`
не затрагивался.

## Что это доказывает

На настоящей перезагрузке одноразовой VM:

- **systemd-lifecycle движка переживает reboot**: enabled-юнит pinned-бинарника
  автоматически стартует, становится `active`/ready (listeners на месте) без
  ручного вмешательства.
- **Защита восстанавливается раньше тракта**: harness поднимает guards
  (`GUARDS_UP interception_absent=yes`) до readiness и до capture — порядок
  продукта соблюдён и подтверждён журналом.
- **persistent-состояние возвращается**: nft-таблицы (guards + capture +
  default-deny) и policy route сами встают после reboot.
- **тракт после reboot корректен**: разрешённый selected-flow proxied
  (origin_peer = роутер), запрещённый и unselected — не доходят до origin;
  default-deny цел; перехват/`ct mark`/`tproxy` на месте, счётчик capture растёт.
- **отказной reboot fail-closed**: при битом движке capture не поднимается,
  guards/default-deny держат тракт, утечки нет.
- **cleanup реально чист**: гость вернулся в обычное состояние.

## Чего это НЕ доказывает (честные пределы)

- Это **lab-харнесс порядка, а не продуктовая служба.** `boot_restore.py`
  восстанавливает только guard-файл; порядок «guards→движок→interception» на
  загрузке реализован **lab-скриптом**, а не продуктом. Продуктовая boot-служба
  (и её реальный systemd-order) не проверялась.
- **Два дефекта вскрыты, но не исправлены в продукте.** 1) сгенерированный юнит
  падает под своим sandbox из-за `AF_NETLINK` — обойдено lab-drop-in'ом;
  2) `auto_detect_interface` выбирает management-NIC — обойдено lab-свапом
  default-route. Оба обхода — lab-only; выводы о «готовности» юнита делать нельзя.
- **INPUT accept — lab scaffold** (`LAB_INPUT_ACCEPT`), не генератор; доставка
  перехваченного потока к listener'у остаётся недоказанным продуктовым
  требованием (как в lab-24/27/29/30/31).
- **Харнесс ставит capture вручную, не через продуктовый apply.** Атомарный
  apply/rollback/commit, marker/дедлайн safe-mode, восстановление
  `recover_interrupted_apply` на reboot не проверялись.
- **Работает закрытый gate**: `tproxy.not_available` не открыт — это не enablement
  и не продуктовый boot.
- Не проверялись: `vsr-live`, production systemd-зависимости (After/Requires
  между реальными юнитами), Unbound/UID-lifecycle (DNS-таблицы подняты, но
  резолверы не запускались), IPv6, bridge/offload, ECMP/произвольный policy
  routing, мультипоточность/масштаб, неподделываемость mark против
  root-writer'а (ADR-0013).
- **Data-path прогон использует короткоживущие client/origin netns** (роутер —
  persistent root-ns состояние); сами клиентские namespace reboot не переживают.
- **`AF_NETLINK`-drop-in и смена default-route — lab-deviations**: их влияние на
  безопасность не оценивалось.

## Как воспроизвести

```
# host: артефакты из настоящих генераторов (gate закрыт)
cd backend && env -u PYTHONPATH PYTHONPATH=src .venv/bin/python \
  tests/lab/generate_tproxy_reboot_case.py /tmp/lab32-artifacts
# host: откатная точка
virsh -c qemu:///system snapshot-create-as vsr-tproxy-lab pre-reboot-<date> --disk-only --atomic
# доставка на VM (HTTP-сервер 192.168.122.1:8099 + vm-push.sh/vm-exec.sh), затем:
bash /root/vsr-lab/setup_guest.sh           # бинарь+юнит+drop-in+артефакты, enable
virsh -c qemu:///system reboot vsr-tproxy-lab
# после загрузки (guest-agent):
python3 /root/vsr-lab/lab32_reboot_probe.py normal      # -> pass 4/0
# отказной сценарий: mv singbox.json singbox.json.bak; virsh reboot; probe failclosed -> pass 4/0
bash /root/vsr-lab/cleanup_guest.sh
```

(Имена файлов в репозитории: `tproxy_reboot_probe.py`,
`generate_tproxy_reboot_case.py`, `tproxy_reboot_boot.sh`, `tproxy_reboot_boot.service`,
`tproxy_reboot_singbox_netlink_lab.conf`, `tproxy_reboot_setup.sh`,
`tproxy_reboot_cleanup.sh`.)
