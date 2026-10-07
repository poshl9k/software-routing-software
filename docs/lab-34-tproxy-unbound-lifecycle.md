# lab-34: lifecycle двух Unbound-процессов (selected/ordinary) TProxy DNS-контура

**Статус: gated-каркас + подтверждённый lifecycle на одноразовой VM. Публичный
gate `tproxy.not_available` остаётся закрытым.** ADR-0014 фиксирует DNS-контур как
два resolver-процесса (selected/ordinary) с разными listener и UID. До этой задачи
агент управлял только артефактами-конфигами, но не самими процессами. Теперь
добавлен типизированный адаптер `agent/unbound_service.py`, подключённый к фазам
`readiness`/`teardown` каркаса apply и к boot-restore. Ветка достижима только из
офлайн-снапшота `model_copy`, как и весь TProxy-каркас.

**VM:** одноразовая `vsr-tproxy-lab` (Debian 13, ядро 6.12, Unbound 1.26.1,
AppArmor активен). `vsr-live-403ab3a` не трогалась. Прогон: все контроли `PASS`,
`FAILS=0`, teardown подтверждён.

## Файлы

| Файл | Роль |
| --- | --- |
| `backend/src/vs_router/agent/unbound_service.py` | **новый**: детерминированный unit-текст для двух процессов, distinct UID, фиксированный argv `unbound-checkconf`/`systemctl`, fail-closed readiness, best-effort stop. |
| `backend/src/vs_router/generators/tproxy_dns.py` | + `TPROXY_ORDINARY_UID = 29093`, `ordinary_uid_for()` — единый источник UID рядом с selected. |
| `backend/src/vs_router/generators/unbound.py` | split-конфиги эмитят `username: ""` (systemd `User=` владеет UID); `generate_unbound()` golden **не изменён**. |
| `backend/src/vs_router/agent/tproxy_apply.py` | + шаг readiness `unbound_process`; `READINESS_STEPS = (policy_route, unbound_process, singbox_process)`, reverse в `TEARDOWN_STEPS`; `describe()` пишет `ordinary_uid`. |
| `backend/src/vs_router/agent/apply.py` | `_tproxy_readiness_steps` запускает `UnboundService` до перехвата; `_teardown_tproxy_steps` останавливает оба резолвера. |
| `backend/src/vs_router/agent/boot_restore.py` | `restore_tproxy_resolvers()` — поднимает оба резолвера после guards и до тракта; `recover_interrupted_apply` останавливает их при прерванном apply. |
| `backend/tests/test_agent_unbound_service.py` | **новый**: 18 тестов (unit-текст/UID/argv без инъекции, readiness блокирует перехват, порядок фаз, teardown, инертность при `enabled=False`). |

Штатная команда из `backend/`: `uv run --no-sync pytest -q` → **802 passed**
(было 784; +18 новых, 0 падений). Golden не менялись.

## Схема юнитов / UID / readiness

| | selected | ordinary |
| --- | --- | --- |
| unit | `vs-router-unbound-selected.service` | `vs-router-unbound-ordinary.service` |
| config | `/etc/vs-router/applied/tproxy-unbound-selected.conf` | `/etc/vs-router/applied/tproxy-unbound-ordinary.conf` |
| UID (`User=`) | `tproxy_dns.TPROXY_SELECTED_UID` = **29092** | `tproxy_dns.TPROXY_ORDINARY_UID` = **29093** |
| listener | `10.212.1.1` (ingress) | `10.212.3.1` |
| unmatched | → loopback-стаб `127.0.0.1@15353` | → внешний WAN-upstream |
| `ExecStart` | `/usr/sbin/unbound -d -c <config>` | то же, другой config |

Идентичные `[Service]`-ограничения у обоих юнитов (минимальные права):
`Type=simple`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`,
`RestrictNamespaces=true`, `LockPersonality=true`, `MemoryDenyWriteExecute=true`,
`Restart=on-failure`; ровно одна capability —
`AmbientCapabilities=CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (bind `:53`
непривилегированным UID). Пути/UID/argv — модульные константы; данные RPC в
`argv` не попадают, шелл не используется. Секретов в юните нет.

**Readiness (fail-closed):** `UnboundService.start()` сначала проверяет
`unbound-checkconf <config>` для **обоих** конфигов, затем пишет юниты,
`systemctl enable --now` обоих и ждёт `systemctl is-active --quiet` обоих;
любой провал → `ApplyError` (`agent.unbound_config_invalid` /
`agent.reload_failed`), при котором ни один юнит не включается. Шаг
`unbound_process` выполняется после `tproxy_policy_route` и строго до
`tproxy_interception`, так что оба резолвера готовы до открытия тракта.

## Находки, вскрытые на VM (важно для реального deploy)

1. **AppArmor профиль Debian блокирует путь конфига.** `/etc/apparmor.d/usr.sbin.unbound`
   ограничивает `/usr/sbin/unbound` чтением `/etc/unbound/**` и `/var/lib/unbound/**`;
   чтение сгенерированного `tproxy-unbound-*.conf` в `/etc/vs-router/applied/`
   даёт `Permission denied` даже под root. Сам юнит это не закрывает — нужен
   локальный оверрайд `/etc/apparmor.d/local/usr.sbin.unbound` с
   `/etc/vs-router/applied/** r,` и `apparmor_parser -r`. Это **открытая
   deploy-задача** (упаковка оверрайда), не реализованная в этом каркасе.
2. **`username` в конфиге конфликтует с выделенным UID.** Unbound всегда
   пытается drop под `username`, у которого compiled-in default `"unbound"`;
   как непривилегированный процесс это фатально (`unable to set group id of
   unbound: Operation not permitted`). Split-конфиги теперь эмитят
   `username: ""` (документированное отключение drop), а UID задаёт systemd
   `User=`. Обычный продуктовый `generate_unbound()` сохраняет
   `username: "unbound"` — golden не тронут. Существующие VM-пробы
   (lab-14…lab-23) уже делали эту замену вручную; теперь она часть генератора
   split.
3. **Общий pidfile `/run/unbound.pid`.** Оба процесса логируют нефатальный
   `cannot open pidfile /run/unbound.pid: Permission denied` (при `-d` pidfile не
   нужен). Выделенного `RuntimeDirectory`/`pidfile` пока нет — отмечено, не
   блокирует контур.

## Результаты VM (16 контролей, все `PASS`)

| Контроль | Наблюдение |
| --- | --- |
| `unbound-checkconf` обоих | `no errors` для selected и ordinary (exit 0) — та же команда, что readiness. |
| Оба юнита active | `systemctl is-active` = `active` для обоих. |
| Разные реальные UID | `/proc/<pid>/status` selected = 29092, ordinary = 29093. |
| Свои listener | `ss -lunp`: selected `10.212.1.1:53`, ordinary `10.212.3.1:53`. |
| Локальная запись | `router.test` → `192.0.2.77` у selected. |
| Unmatched selected → loopback-стаб | свежее имя → `203.0.113.8`; стаб видел запрос, WAN-origin — **нет**. |
| Unmatched ordinary → WAN | свежее имя → `203.0.113.7` от `198.18.0.3`; стаб запроса не видел. |
| Explicit forward selected | `host.forward.vsrprobe.org` → `203.0.113.7` от `198.18.0.2`. |
| Teardown | после stop/cleanup оба юнита `inactive`, listener'ов нет, UID-пользователи и dummy-интерфейс удалены, AppArmor-оверрайд снят. |

## Что это доказывает

- Адаптер `unbound_service` детерминированно ставит **два** systemd-юнита с
  разными реальными числовыми UID, минимальными правами и одним
  `CAP_NET_BIND_SERVICE`; процесс реально работает под 29092/29093 на своём
  listener'е.
- Readiness-команда адаптера (`unbound-checkconf`) проходит на обоих
  сгенерированных конфигах, а процесс стартует и обслуживает DNS.
- Разделение источника держится на уровне процессов: unmatched selected уходит
  на loopback-стаб и **не** во внешний WAN, ordinary идёт обычным путём;
  локальные записи и explicit forwards сохраняют приоритет.
- Остановка/teardown оставляет хост чистым (нет процессов, listener'ов,
  пользователей, оверрайдов).
- Каркас apply/boot инертен при `enabled=False`: ни `systemctl`, ни
  `unbound-checkconf` не вызываются, фаза `unbound_process` не появляется
  (unit-тесты на `FakeFS`/`FakeExecutor`).

## Что это **НЕ** доказывает

- **Не** публичное включение: gate `tproxy.not_available` закрыт, ветка
  достижима только офлайн. VM-проба ставила юниты/конфиги напрямую, а не через
  реальный apply-цикл агента (нет загрузчика nft/Unbound-артефактов и
  peer-UID RPC на VM).
- **Не** sing-box: loopback-стаб и WAN-origin — синтетические Python-серверы;
  реальный DNS-политик sing-box и перехват не проверялись.
- **Не** reboot с продуктовым подтверждением: `restore_tproxy_resolvers()`
  проверен только unit-тестами (no-op при отсутствии конфигов) и
  офлайн-порядком; реального reboot с поднятием резолверов и тракта не было.
- **Не** закрыт AppArmor-разрыв и pidfile: оверрайд нужен в упаковке; общий
  pidfile даёт нефатальные ошибки.
- **Не** строгая fail-closed-гарантия ADR-0006 и не атрибуция по QNAME (см.
  lab-28): контур — только plain `:53`, IPv4; кэш selected выключен, но
  параллельные in-flight-запросы/отрицательный кэш не гарантированы.
- **Не** проверены restart/crash-recovery resolver'ов и деградация движка.

## Как воспроизвести

```
# host: собрать бандл (конфиги из plan_tproxy_dns, юниты из unbound_service)
cd backend && uv run --no-sync python \
  /home/poshl9k/.hermes/cache/scratch/vm-lab/lab34/mklab34.py \
  /home/poshl9k/.hermes/cache/scratch/vm-lab/lab34
cd /home/poshl9k/.hermes/cache/scratch/vm-lab && tar czf lab34.tgz -C lab34 .
bash vm-push.sh lab34.tgz /root/vsr-probe \
  "rm -rf lab34 && mkdir -p lab34 && tar xzf lab34.tgz -C lab34 && bash lab34/runchecks.sh"
```
