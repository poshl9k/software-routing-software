# ADR-0029: Словарь выхода и субъекта маршрутизации

- Status: принят
- Date: 2026-10-21
- Deciders: пользователь, Hermes

## Context

Маршрутизация описана в конфигурации **двумя** несвязанными моделями:

- легаси `TProxy` (`schema.py:520`): источник — `ingress_interfaces` (только
  интерфейсы из `configuration.interfaces[]` с зоной не `wan`/не `None`), выход
  правила — `action: direct|block|route` плюс `outbound` (тег из
  `proxies.outbounds` ∪ `proxies.groups`, и только при `proxies.enabled`);
- продуктовая `routing_rules` (`schema.py:711`): субъект — `server` или
  `device(subscriber, peer)`, выход — `Exit{kind: direct|outbound|tunnel}`.

Живой контур на панели маршрутизирует через `routing_rules` (ADR-0018/0019,
ADR-0028), у `routing_rules` **нет UI вообще**: `grep routing_rules frontend/src`
пусто. Экран «Выборочная маршрутизация» редактирует легаси `TProxy`, который
на панели включить нельзя: `tproxy.ingress_interface` требует интерфейс из
`configuration.interfaces[]` с зоной не `wan`, а панель имеет только WAN-интерфейс.
Проверено на живых моделях (`Configuration` + `validate_configuration`):
`tproxy.enabled=true` на хосте с одним `wan`-интерфейсом →
`tproxy.ingress_interface`; источником захвата не может быть интерфейс
туннеля, если он не объявлен в `interfaces[]` с не-`wan` зоной.

Отсюда «человеку ничего не понятно»: экран описывает чужую сущность.

AWG Manager (`hoaxisr/awg-manager`, доки `awgm.hoaxisr.ru/guide/singbox/router/`)
держит один словарь: субъект (устройство в политике / весь LAN / сам роутер) →
назначение → выход (outbound-протокол / composite-группа / «Интерфейс» =
`direct` с `bind_interface` / WG-endpoint / `reject`). Наш продуктивный
`Exit` беднее: нет выхода через интерфейс, нет группы, нет явной блокировки;
`group` не принимается вовсе (`validators.py:370` берёт только
`proxies.outbounds`), серверный туннель выходом быть не может
(`routing.tunnel_client_required`).

## Decision

1. **Продуктовая модель — единственный словарь для нового UI.** Мастер и
   «Расширенные настройки» строятся на `routing_rules`. Легаси `TProxy`
   сохраняется как контур роутерного профиля; вывод его из эксплуатации —
   отдельная задача, здесь не решается.

2. **Выход (`Exit`) расширяется до шести видов.** Замороженная форма JSON:

   ```json
   { "kind": "direct" }
   { "kind": "interface", "interface": "eth0" }
   { "kind": "outbound",  "tag": "vless_fr" }
   { "kind": "group",     "tag": "auto" }
   { "kind": "tunnel",    "name": "client_vpn" }
   { "kind": "block" }
   ```

   Поля: `kind`; `tag` — только для `outbound`/`group`; `name` — только для
   `tunnel`; `interface` — только для `interface`. Ровно одно из них обязательно,
   остальные отсутствуют.

   - `interface` — прямой выход, привязанный к сетевому интерфейсу хоста:
     генератор sing-box рендерит `{"type": "direct", "bind_interface": …}`.
     Механизм не новый: тот же приём уже применяется для выхода-туннеля
     (`generators/singbox.py:193`) и принят закреплённым `sing-box 1.14.2`
     (`backend/tests/test_routing_rules.py:322`).
   - `group` — группа выходов `selector`/`urltest`; принимается и группа, и её
     участники, даже когда `proxies.enabled` выключен (как сейчас для
     `outbound`).
   - `block` — отказ правила (`action: reject`), а не молчаливый прямой
     маршрут: ADR-0019 требует, чтобы недоступный/запрещённый выход не
     выпускал трафик наружу.

3. **Субъект (`RoutingSubject`) расширяется до трёх видов:**

   ```json
   { "kind": "server" }
   { "kind": "device", "subscriber": "anna", "peer": "iphone" }
   { "kind": "interface", "interface": "lan0" }
   ```

   `device` — как сейчас. `interface` — «весь трафик, пришедший на этот
   интерфейс»: реализуется как `source_ip_cidr` по адресам интерфейса
   (`configuration.interfaces[].addresses`, IPv4) либо, для интерфейса
   туннеля, по адресам его пиров. Это ровно семантика «весь LAN»/«весь
   туннель» из AWG Manager, выраженная в модели sing-box, а не в nftables.

4. **Вход через прокси-порт (LAN SOCKS5/HTTP) в объём ADR не входит.** Это
   отдельный инбаунд sing-box плюс правило firewall: на панели с
   default-deny молчаливо открытый прокси — это открытый прокси. Требуются
   аутентификация, явный адрес слушания и отдельное решение по firewall.
   Словарь `Exit`/`RoutingSubject` расширяется так, чтобы этот вид субъекта
   (`kind: "proxy"`) добавился позже без ломки формы.

5. **Отказоустойчивость не меняется.** Правило с недоступным выходом
   отказывает, а не откатывается на прямой интернет; устройство абонента без
   подходящего правила получает `reject` (ADR-0019). Новый вид выхода
   `interface` этому не противоречит: отсутствие интерфейса — ошибка
   конфигурации, отвергаемая валидатором, а не повод выпустить трафик.

## Новые коды отказа

- `routing.exit_interface_reference` — интерфейса выхода нет в
  `configuration.interfaces[]`.
- `routing.exit_group_reference` — тега группы выхода нет в `proxies.groups`.
- `routing.exit_fields_unexpected` — поле, не относящееся к `kind`.
- `routing.exit_field_required` — обязательное поле `kind` не задано.
- `routing.subject_interface_reference` — интерфейса субъекта нет в
  `configuration.interfaces[]` и это не интерфейс туннеля.
- `routing.subject_fields_unexpected` — поле, не относящееся к `kind`.

## Consequences

- UI может предложить один список «куда» и один список «кому» вместо
  разнородных `action`/`outbound`/`kind`.
- `proxies.enabled` перестаёт быть условием «можно вообще выбрать выход»:
  выход ссылается на объявленный тег, а рендерится ли выход — решает
  генератор.
- `routing_rules` получает UI впервые; до этого модель правилась только
  вручную через JSON.
- Легаси `TProxy` и продуктовые `routing_rules` продолжают сосуществовать:
  в конфигурации это две разные секции, и генератор sing-box ставит
  продуктовые правила перед легаси (`generators/singbox.py`, порядок
  `preparation + product_rules + legacy`). Сведение двух моделей — отдельная
  задача, здесь не решается.
