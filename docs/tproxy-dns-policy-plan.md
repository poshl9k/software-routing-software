# План политики DNS-контура TProxy

**Статус:** анализ + заготовка (offline). **НЕ доказательство.** Публичный
gate `tproxy.not_available` закрыт. Ничего не подключено к bundle/apply/boot/API.

## Что добавлено

`backend/src/vs_router/generators/tproxy_dns.py` — планировщик `plan_tproxy_dns(version,
selected_uid) -> TProxyDnsPlan`. Это **композиция поверх существующих offline-генераторов**,
а не новый рендер:

- `selected_unbound` / `ordinary_unbound` — из `generate_tproxy_unbound_split`;
- `listener_addresses` (selected/ordinary) — из `tproxy_unbound_listener_addresses`;
- `nft_guards` — три упорядоченные таблицы из `generate_tproxy_dns_ingress_guard`,
  `generate_tproxy_dns_listener_guard`, `generate_tproxy_dns_output_guard`.

Каждая таблица несёт `role`, `table`, `hook`, `chain`, `priority` и сырой текст
(`content`), byte-for-byte равный выводу соответствующего генератора. Hook/priority
берутся из общего реестра `generators/marks.py`, чтобы план и реестр владения не
разъезжались.

Порядок контура — единый контракт: `ingress` (prerouting -110) → `listener`
(input -10) → `output` (output -20). При `tproxy.enabled=False` план — «всё
отключено»: `selected_unbound`/`ordinary_unbound` = None, `listener_addresses` = {},
а `nft_guards` содержат только `destroy table` своих таблиц. При `enabled=True`
без валидного UID — `ValueError tproxy.dns_output_invalid_uid`.

## Схема контура

```
selected client --DNS--> [ingress: prerouting -110] drop direct :53
        |
        v
  Unbound "selected"  (bind: selected ingress addrs, cache off, root -> 127.0.0.1@15353)
        |  unmatched
        v
  loopback DNS stub :15353  (sing-box DNS -- НЕ реализован)
        ^
        |  [listener: input -10] iifname<iifname> ip daddr<selected> th dport 53
  [output: output -20] skuid selected: client replies + stub + explicit forwards, else drop
        |
        x  global WAN upstream (никогда не исключение для selected)
```

`ordinary` Unbound обслуживает остальные интерфейсы своим конфигом/кэшем. Локальные
записи (`local-data`) и явные `forward-zone` сохраняются в обоих конфигах.

## Открытые риски (что НЕ доказано)

- **Настоящий sing-box DNS** отсутствует: loopback stub `127.0.0.1@15353` не
  реализован как процесс; маршрутизация unmatched-запросов не проверена.
- **Права/службы**: нет реальных Unbound-процессов, их UID, systemd-юнитов и
  изоляции; `selected_uid` — лишь параметр плана.
- **Отказоустойчивый lifecycle**: старт/рестарт/деградация движка и восстановление
  не реализованы; `cache-max-ttl: 0` проверен только на последовательных повторах.
- **DoH/DoT** и шифрованные upstream вне области: контур описывает только plain :53.
- **IPv6**: split отвергает IPv6-listener'ы и upstream'ы; OUTPUT-guard IPv4-only.
- **Параллельные запросы**: отключение кэша не гарантирует недоступность имени при
  отказе движка для одновременных in-flight запросов.
- **Граница attrибуции**: исключение explicit forward привязано к адресу, не к QNAME;
  после передачи в Unbound источник запроса по socket UID не восстанавливается.
- **Публичный gate**: `tproxy.enabled=True` по-прежнему отвергается валидатором; план
  достижим только из offline `model_copy`-снимка. Это не разрешение на включение.

Подробный пакетный контекст — `docs/tproxy-dns-source-boundary.md` и `docs/lab-14..23`.
