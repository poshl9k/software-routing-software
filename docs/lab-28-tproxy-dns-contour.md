# DNS-контур TProxy: два Unbound + guards, собранные интегрированным планом

**VM:** одноразовая `vsr-tproxy-lab` (Debian 13, ядро 6.12, Unbound 1.26.x,
пакеты `unbound`/`ip`/`nft`/`setpriv`/`ss`). `vsr-live-403ab3a` не трогалась.
**Прогон:** `guest exit: 0`, все контроли `PASS`.
**Статус:** offline-план + gated-каркас apply; публичный gate
`tproxy.not_available` **закрыт**. Это не разрешение на включение.

## Что проверялось

Проба запускает **два настоящих Unbound** с конфигами, которые сгенерировал не
скрипт-заготовка, а **интегрированный путь**: `generators.tproxy_dns.plan_tproxy_dns`
→ `agent.tproxy_apply.build_artifacts` (тот же текст, что фаза `guards` →
`readiness` каркаса apply). Сгенерированные ingress/listener/OUTPUT-guard'ы
применяются `nft -f` внутри изолированного router-namespace; клиенты — в
соседних namespace; fake loopback DNS-стаб `127.0.0.1:15353` и два fake WAN
origin'а `198.18.0.2`/`198.18.0.3` синтезируют ответы. Никаких изменений
root-network гостя и хоста: всё в временных namespace, конфиги и процессы
удаляются в `finally`.

**Fixture** (host-only, offline): `backend/tests/lab/generate_tproxy_dns_split_cases.py`
— `source: plan_tproxy_dns+tproxy_apply`, `selected_uid: 29092`,
`apply_files: [tproxy_guards, tproxy_unbound_selected, tproxy_unbound_ordinary,
singbox, tproxy_interception]`. Его же проверяет host-тест
`backend/tests/test_tproxy_dns_split_lab.py::test_dns_split_fixture_comes_from_the_integrated_contour`.
**Probe:** `backend/tests/lab/tproxy_dns_split_probe.py` (VM-only, root).

## Схема контура

```
selected client --:53--> [ingress prerouting -110] прямой :53 вне LAN drop
        |
        v
  Unbound "selected"  UID 29092  bind: 10.212.1.1  cache off
        |  local-data / explicit forward -- приоритет сохранён
        |  unmatched
        v
  loopback DNS-стаб 127.0.0.1:15353 ---- (sing-box DNS, НЕ реализован)
        ^
  [listener input -10]  selected-IP доступен только с выбранных ingress
  [output  output -20]  skuid 29092: ответы клиентам + стаб + explicit forwards, иначе drop
        |
        x  глобальный WAN-upstream (для selected — никогда не исключение)

  Unbound "ordinary"  UID 29093  bind: 10.212.3.1  обычный путь/кэш
```

## Результаты контролей (UDP и TCP)

| Контроль | Наблюдение |
| --- | --- |
| Два процесса, разные listener и UID | У выбранного и обычного Unbound проверены `/proc/<pid>/status` (real/effective/saved UID 29092/29093) и нулевые `CapEff`/`CapAmb`. |
| Локальная запись | `router.test.` → `192.0.2.77` у **обоих** resolver; стаб и оба WAN-origin не видели запрос. |
| Unmatched у selected → loopback стаб | Свежее имя дало `203.0.113.8`; стаб зарегистрировал запрос, WAN-origin — нет; счётчик OUTPUT `tproxy_dns_stub` вырос. |
| Ordinary идёт обычным путём | То же имя у ordinary → `203.0.113.7` от `198.18.0.3`; стаб запроса не видел. |
| Приоритет explicit forward обоих | `*.forward.vsrprobe.org.` у selected и ordinary → `198.18.0.2` (`203.0.113.7`); OUTPUT `tproxy_dns_explicit_forward` вырос только у selected. |
| Прямой DNS выбранных к WAN (ingress guard) | selected → `198.18.0.2:53` : timeout + рост counter `tproxy_dns_direct`; запрос не дошёл до upstream. |
| Cross-listener (listener guard) | selected → `10.212.3.1` и ordinary → `10.212.1.1` : drop (`tproxy_dns_selected_wrong_listener` / `tproxy_dns_unselected_wrong_listener`). |
| OUTPUT по UID, тот же внешний tuple | Под UID 29092 запрос к `198.18.0.3:53` отброшен (`tproxy_dns_output_denied` вырос), origin не получил; под UID 29093 — корректный ответ. |
| Отключение кэша selected | Повтор unmatched у selected снова ушёл на стаб; повтор у ordinary обслужен из кэша без нового запроса к origin. |
| Остановка стаба (fail-closed) | Ранее разрешённое имя у selected **не** отдано (cache off); свежее имя UDP/TCP — timeout; ни один WAN-origin не получил запрос. При этом обычный Unbound по другому свежему имени продолжил получать `203.0.113.7`, а локальная запись и explicit forward selected работали. |
| Восстановление стаба | Новое имя UDP, затем TCP — снова `203.0.113.8` от стаба, без перезапуска Unbound. |

## Что это доказывает

- Сгенерированные **интегрированным планом** (`plan_tproxy_dns` через
  `tproxy_apply.build_artifacts`) конфиги selected/ordinary и три guard-таблицы
  корректны как `unbound-checkconf`/`nft -c` и работоспособны как пакетный
  контур: адреса listener, UID и имена таблиц согласованы между конфигами и
  guards.
- Разделение источника DNS по ingress/listener и по UID на OUTPUT действительно
  разделяет selected и ordinary; локальные записи и явные forwards сохраняют
  приоритет у обоих; unmatched selected уходит на loopback-стаб, а не во
  внешний WAN.
- При потере стаба selected получает **отказ (timeout), а не утечку** во
  внешний DNS, при живых положительных контролях ordinary/локальной
  записи/forward.
- Host-тесты `backend/tests/` (в т.ч. `test_tproxy_dns_integration.py`,
  `test_tproxy_apply_integration.py`, `test_tproxy_dns_plan.py`,
  `test_tproxy_dns_split_lab.py`) закрепляют инертность каркаса при
  `enabled=False`, порядок `guards → readiness → interception`, byte-for-byte
  состав guards из плана, fail-closed семантику и teardown.

## Что это **НЕ** доказывает

- **Не** sing-box: loopback-стаб и WAN-origin'ы — синтетические Python-серверы;
  реальный proxy/DNS-policy sing-box, UDP/TCP-перехват и маршрутизация
  unmatched-запросов через прокси не проверялись.
- **Не** продуктовые службы: нет systemd-юнитов, прав на bind `:53`,
  изоляции, безопасного lifecycle (старт/рестарт/деградация/восстановление) и
  атомарного apply/boot/rollback для самих resolver-процессов. `selected_uid`
  — параметр плана; в схеме нет поля UID, поэтому взят единый зарезервированный
  `TPROXY_SELECTED_UID = 29092` (см. `tproxy_dns.py`), а не создаётся
  пользователь/процесс.
- **Не** строгая fail-closed-гарантия ADR-0006: отключение кэша покрыто на
  последовательных UDP/TCP-повторах, но не гарантирует блокировку
  одновременных in-flight-запросов, отрицательного/aggressive-NSEC кэша и
  очередей; нет автоматического обнаружения потери движка и перевода DNS в
  host-owned режим.
- **Не** атрибуция по QNAME: исключение explicit forward привязано к адресу, не
  к имени; OUTPUT не видит QNAME.
- **Вне области:** IPv6 (split отвергает IPv6-listener/upstream, OUTPUT-guard
  IPv4-only), DoH/DoT/шифрованные upstream, фрагменты, privileged-обход.
- Публичный gate `tproxy.not_available` **остаётся закрытым**; ничего из
  проверенного не является разрешением на включение TProxy.

## Как воспроизвести

```
# host (offline fixture из интегрированного плана)
cd backend && env -u PYTHONPATH .venv/bin/python \
  tests/lab/generate_tproxy_dns_split_cases.py /tmp/contour-case.json
# гость (VM-only, root)
bash .../vm-push.sh /tmp/contour-case.json /root/vsr-probe \
  "for f in tproxy_dns_baseline_probe.py tproxy_dns_split_probe.py; \
   do curl -fsS -O http://192.168.122.1:8099/\$f; done && \
   python3 tproxy_dns_split_probe.py contour-case.json"
```
