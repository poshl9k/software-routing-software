# Владение mark / table / hook / port для TProxy (анализ и заготовка)

**Статус: анализ + заготовка реестра, НЕ доказательство. Публичный gate
`tproxy.not_available` остаётся закрыт.** Этот документ фиксирует, какие
целочисленные пространства реально существуют в коде, вводит
проект-контракт владения (`backend/src/vs_router/generators/marks.py`) и
перечисляет, что ещё не сделано. Подтверждения на реальном пакетном тракте
здесь нет.

## Зачем

Блокер #2 (см. `docs/lab-09-tproxy-mark-collision.md`): `meta mark`
используется как «proof» успешного TProxy, но привилегированный сторонний
writer nftables/marks может выставить бит после reset и пропустить
established TCP через INPUT. Нет единого реестра владения
marks/hooks/tables/ports и гарантии отсутствия коллизий. План
(`docs/sing-box-tproxy-plan.md:63`) требует «выделить mark/table/ports и
сверить конфликты» и «дизайн владения marks/hooks».

Реестр — это *контракт имен/резервирования*, а **не** средство безопасности.
Он не заменяет независимую INPUT-авторизацию и не решает prototype-проблему
подделки marks.

## Что реально найдено в коде

### Marks / fwmark / policy routing

В **продуктовых генераторах** (`backend/src/vs_router/`) нет ни `meta mark`,
ни `fwmark`, ни `ip rule`. Централизовать в продакшене пока нечего — реестр
остаётся провизией. Конкретные значения существуют только в VM-lab пробах:

| Значение | Назначение | Где |
| --- | --- | --- |
| `0x100` | routing mark TProxy (bit 8) | `backend/tests/lab/tproxy_tcp_probe.py:162,184`; `tproxy_preauth_probe.py:157`; `tproxy_udp_uid_probe.py:38` |
| `0x200` | proof-бит (bit 9) | `backend/tests/lab/tproxy_tcp_probe.py:184,194,205` |
| `0x300` | interception+proof вместе | `backend/tests/lab/tproxy_tcp_probe.py:184` |
| `0xfffffdff` | сброс proof-бита | `backend/tests/lab/tproxy_tcp_probe.py:189` |
| `0x123` | lab fwmark policy route | `docs/lab-05-singbox-tproxy.md:9` |

Policy route (лабораторные): `ip rule add priority 100 fwmark 0x100 lookup
100` — `tproxy_tcp_probe.py:325`, `tproxy_preauth_probe.py:169,301`,
`tproxy_udp_uid_probe.py:200`. `docs/lab-05` использует `fwmark 0x123 →
table 100`. Ни одно из этих правил в продукте не применяется.

### nftables-таблицы

Продукт: `inet vs_router` (`nftables.py:99`). Offline-эксперименты (не
подключены к bundle/apply/boot): `inet vs_router_tproxy_guard`
(`:177`), `inet vs_router_tproxy_preauth` (`:310`),
`inet vs_router_tproxy_dns_ingress` (`:202`),
`inet vs_router_tproxy_dns_listener` (`:234`),
`inet vs_router_tproxy_dns_output` (`:261`). Time-only лабораторные таблицы
(`vsr_tcp_intercept`, `vsr_tcp_proof_reset`, `vsr_tcp_input_proof`,
`vsr_tcp_mark_collision`, `ip vsr_tproxy_lab`) живут только в пробах.

### Hook priorities

Продукт: input/forward `priority filter`, prerouting `dstnat`, postrouting
`srcnat` (`nftables.py:103,148,153`). Offline TProxy: guard forward `-10`
(`:189`), preauth prerouting `-90` (`:330`), dns_ingress prerouting `-110`
(`:218`), dns_listener input `-10` (`:243`), dns_output output `-20` (`:271`).

### Порты

| Порт | Назначение | Где |
| --- | --- | --- |
| `51271/udp` | sing-box TProxy UDP inbound `127.0.0.1` | `generators/singbox.py:26` |
| `51272/tcp` | sing-box TProxy TCP inbound `127.0.0.1` | `generators/singbox.py:28` |
| `15353` | loopback DNS stub selected Unbound | `generators/unbound.py:86` |

## Дизайн (заготовка)

Раскладка 32-битного mark (биты эксклюзивны по владельцу):

```
bits 0..7   (0x000000FF)  резерв router / не-TProxy владельцев (конкретного значения нет)
bit  8      (0x00000100)  TProxy routing mark (0x100)
bit  9      (0x00000200)  TProxy proof-бит (0x200) — ПОДДЕЛЫВАЕМ
bits 10..11               запас TProxy (внутри 0x00000F00)
```

Почему proof нельзя считать неподделываемым: `meta mark` в INPUT доступен
любому writer, который сработал раньше в пакетном пути. Маска и reset-хук
ограничивают коллизии (свой бит + чужой namespace не пересекаются), но не
делают бит неоспоримым свидетельством. Поэтому proof — только «hint».

Почему маска ограничивает коллизии: `assert_no_collisions(mark, owner)`
падает, если бит `mark` попадает в маску другого владельца (чужой namespace)
или выставляет в собственной маске значение, отличное от
зарегистрированного. TProxy-претензия на низкий байт (например lab `0x123`)
отвергается, потому что он задевает `PRODUCT_RESERVED_BITS`.

## Чего не хватает (остаётся сделать)

1. **Reserved mark namespace как норма продукта.** Даже зарезервированные
   биты не мешают конкурирующему привилегированному writer'у. Нужны явный
   reserved-диапазон, документированный контракт для сторонних writers и
   проверка уже используемых marks на хосте.
2. **Единственный владелец hooks.** Сейчас экспериментальные таблицы
   используют приоритеты `-110..-10`; нет гарантии, что будущий TProxy и
   сторонний nftables-writer не пересекутся по hook priority. Нужен единый
   владелец порядка hooks.
3. **Независимая INPUT-авторизация с packet-path proof на VM.** Реестр её не
   заменяет. Требуется подтверждение на реальном пакетном тракте: proof при
   конкурирующем writer'е, уже буферизованные байты, OUTPUT sing-box, DNS,
   IPv6, arbitrary policy routing/ECMP и atomic apply/rollback/boot.
4. **Продуктовая интеграция.** Реестр пока аддитивный и к генерации не
   подключён: `generate_nftables`/`generate_singbox` и golden не изменены.
   Значения marks/ports сейчас только зарезервированы как провизия.

## Тесты

`backend/tests/test_marks_registry.py` (18 тестов) проверяет
непротиворечивость реестра, непересечение TProxy- и продуктового
пространств, отказ валидации на чужом mark и соответствие констант реальным
значениям в `singbox.py`, `unbound.py`, `nftables.py` и lab-пробах.
