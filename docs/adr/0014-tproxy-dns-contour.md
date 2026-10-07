# ADR-0014: DNS-контур для sing-box TProxy — два Unbound-процесса и DNS-политика sing-box за loopback-stub

**Статус:** принят
**Дата:** 2026-10-07
**Участники:** владелец продукта и Hermes Agent

## Контекст

ADR-0006 требует: при непреднамеренном отказе включённого TProxy не
допускать прямой утечки не исключённого трафика выбранных источников, а
выключение администратором — возвращать обычную маршрутизацию. Для DNS это
означает, что запрос выбранного клиента, не совпавший с локальными записями и
явными forwards, должен при готовом движке разрешаться **через политику
sing-box** (прокси), а при отказе движка — **не** уходить во внешний WAN-DNS.
DNS самого роутера при этом не перехватывается.

Аудит действующих генераторов (`docs/tproxy-dns-source-boundary.md`) показал
контрпример к прямому использованию общего Unbound:

- `backend/src/vs_router/generators/unbound.py:6–29` строит **один** конфиг по
  `configuration.dns`: общие `interface`, `access-control`, `local-data` и
  `forward-zone`; при заданном `dns.upstreams` появляется глобальный
  `forward-zone` с `name: "."`. Генератор не читает `configuration.tproxy` и не
  различает источник запроса.
- Значит, запросы выбранного и невыбранного клиентов к одному listener попадают
  в **один конфиг и кэш**. После передачи запроса Unbound его OUTPUT — это
  трафик процесса роутера, а не исходного клиента; **по socket UID или upstream
  DNS ID источник уже не восстановить после кэша** (lab-14, lab-16).
- `backend/src/vs_router/generators/nftables.py:180–234` (тогда —
  preauthorization/containment) не создаёт отдельной авторизации DNS-выхода
  Unbound: source-scoped FORWARD-drop блокирует транзит, но клиентский запрос к
  локальному resolver идёт в INPUT, после чего Unbound делает **собственный**
  OUTPUT к WAN (lab-16). Это доказывает недостаточность одного FORWARD guard,
  но не утечку при включённом TProxy.

Пакетный контекст подтверждён серией одноразовых VM-проб lab-14…lab-23
(Unbound 1.26.1, изолированные namespace, fake loopback stub и синтетический
WAN origin): split конфигов проходит `unbound-checkconf` (lab-18); два реальных
Unbound с разными listener и независимыми кэшами дают разные ответы на одно
неподходящее имя (lab-20); набор ingress/listener/OUTPUT-guard'ов и разделение
по numeric UID проверены пакетами (lab-17, lab-19, lab-21); потеря stub и
отключение кэша selected проверены отдельно (lab-22, lab-23). Это **не**
продуктовые службы и **не** настоящий DNS sing-box.

Заготовка плана контура — `backend/src/vs_router/generators/tproxy_dns.py`
(`plan_tproxy_dns`), документ `docs/tproxy-dns-policy-plan.md`. Публичный gate
`tproxy.not_available` закрыт; всё достижимо только из offline-снимка
`model_copy`.

## Решение

**Вариант A — внешний двухпроцессный контур:**

1. **Два процесса Unbound.**
   - **selected** — собственный IPv4 listener на адресах `tproxy.ingress_interfaces`;
     доступен только выбранным ingress. Повторяет локальные `local-data` и явные
     доменные `forward-zone`; **unmatched**-запросы уходят на loopback DNS-стаб
     `127.0.0.1@15353`, который обслуживает **DNS-политика sing-box** (резолв
     через прокси). Прямой выход во внешний WAN-DNS у selected **не является
     исключением никогда**.
   - **ordinary** — текущее поведение общего resolver; обслуживает остальные
     интерфейсы своим конфигом и кэшем. Локальные записи и явные forwards
     сохраняются и в selected, и в ordinary.

   Реализация сплита — `generate_tproxy_unbound_split` / `_render_unbound` с
   `root_forward="127.0.0.1@15353"` (`generators/unbound.py`).

2. **nft-guards** — три упорядоченные таблицы, единый контракт порядка
   `ingress → listener → output` (`GUARD_ORDER` в `tproxy_dns.py`):
   - **ingress** (`inet vs_router_tproxy_dns_ingress`, prerouting priority
     `-110`): прямой IPv4 TCP/UDP `:53` от выбранных ingress к **нелокальному**
     адресату — drop; локальный адрес роутера возвращается без блокировки.
   - **listener** (`inet vs_router_tproxy_dns_listener`, input priority `-10`,
     раньше обычного INPUT): selected-Unbound IP доступен только с выбранных
     ingress; запрос с иного ingress к selected listener и вход не с `lo` к
     stub `127.0.0.1:15353` — drop.
   - **output** (`inet vs_router_tproxy_dns_output`, output priority `-20`,
     по `meta skuid` selected-Unbound): разрешены ответы клиентам (source IP
     выбранного интерфейса, `oifname` того же интерфейса, sport `53`), запросы к
     loopback-стабу и запросы к адресам **явных** forwards; всё прочее — drop.

3. **Кэш selected выключен намеренно:** `cache-max-ttl: 0`,
   `cache-max-negative-ttl: 0`, `serve-expired: no`. Это не даёт ответу
   selected пережить готовность движка. Цена — отключение кэша затрагивает и
   явные forwards; локальные `local-data` кэшу не подчиняются. Ordinary и
   действующий `generate_unbound()` не меняются.

4. **Fail-closed.** При падении sing-box/стаба выбранный клиент получает
   **timeout, а не утечку**: unmatched-запросы уходят на stub, в WAN не выходят
   (lab-22, lab-23). DNS самого роутера не перехватывается.

Порядок hook/priority и имена таблиц берутся из общего реестра
`generators/marks.py` (ADR-0013), чтобы план и контракт владельца не
разъезжались; `TProxyDnsPlan` компонует существующие offline-генераторы
(byte-for-byte), не рендеря ничего нового.

## Рассмотренные варианты

- **Вариант A — DNS-политика sing-box вне общего Unbound, за loopback-stub
  (принят):** признак выбранного источника различается **до** общего
  кэша — через отдельный процесс, отдельный listener, ограничение входа по
  `iifname` и OUTPUT по UID. Локальные записи и явные forwards сохраняют
  приоритет у обоих процессов; unmatched уходит в политику sing-box, а не во
  внешний WAN.
- **Вариант B — DNS-политика внутри sing-box на общем Unbound (отвергнут):**
  один resolver не различает выбранный и невыбранный источники, и после общего
  кэша/forward исходный клиент не восстанавливается по socket UID или upstream
  ID (lab-14, lab-16). Нельзя сохранить **приоритет** локальных записей и
  явных forwards относительно политики sing-box, не расщепив процесс. Fail-closed
  слабее: ответ из общего кэша способен пережить отказ движка (lab-22), а
  отзыв одного OUTPUT-правила не отзывает уже выданный ответ. Общий Unbound
  остаётся единственным действующим сервисом, поэтому вариант B не даёт
  изоляции источника без того же split.
- **Открыть публичный gate ради контура:** не рассматривается как решение;
  контур описан как план, gate `tproxy.not_available` остаётся закрытым.

## Последствия

- **Два процесса + UID + guards** — обязательный состав контура: два
  Unbound-конфига (selected/ordinary), разные numeric UID (в пробах `29092`/
  `29093`), три guard-таблицы с зафиксированным hook/priority и loopback-стаб
  `127.0.0.1:15353`. Права на bind `:53` и на OUTPUT привязаны к UID и уровню
  привилегий.
- **Права/службы/lifecycle ещё НЕ реализованы.** В дереве нет реальных
  Unbound-процессов, их UID, systemd-юнитов, изоляции и безопасного
  apply/boot/rollback; `selected_uid` — лишь параметр плана. Настоящий DNS
  sing-box (loopback-стаб как процесс) отсутствует. Всё это открытые условия;
  факт принятия ADR их не закрывает.
- **Вне гарантий (честная граница, не снятая):** DoH/DoT и шифрованные
  upstream — контур описывает только plain `:53`; **IPv6** — split отвергает
  IPv6-listener/upstream, OUTPUT-guard IPv4-only; **параллельные запросы** —
  отключение кэша покрывает последовательные UDP/TCP-повторы, но не
  гарантирует блокировку одновременных in-flight-запросов (объединение запросов
  Unbound, отрицательные ответы, DNSSEC/aggressive NSEC, буферы/очереди остаются);
  привязка исключения explicit forward — к **адресу**, не к QNAME, и OUTPUT не
  видит QNAME.
- **Отказоустойчивый lifecycle не доказан:** автоматическое обнаружение сбоя
  stub/Unbound, перевод в host-owned блокировку, recovery без рестарта
  resolver, атомарный apply/rollback — открыты. Строгая трактовка ADR-0006 для
  DNS-ответов, уже находящихся в кэше/очереди, требует отдельного решения.
- **Связь с другими решениями.** Семантика intent/отказа — ADR-0006; единый
  владелец mark/table/hook — ADR-0013; закреплённый бинарник —
  ADR-0012. Ничто в этом ADR **не** открывает публичный gate
  `tproxy.not_available`: это оформление контура DNS, а не подтверждение
  готовности перехвата, и не разрешение на включение.
