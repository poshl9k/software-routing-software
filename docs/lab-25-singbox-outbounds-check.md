# lab-25: sing-box outbounds/groups из контракта `proxies` (offline check на VM)

**Статус: генератор + `sing-box check` на одноразовой VM. Публичный gate
`tproxy.not_available` остаётся закрыт, фетч подписок/apply/UI не реализованы.**
Отчёт об оффлайн-проверке, а не о готовности перехвата и не о боевой
маршрутизации.

## Что сделано

Генератор `backend/src/vs_router/generators/singbox.py::generate_singbox`
аддитивно расширен: секция контракта `proxies` (outbounds/subscriptions/groups,
по умолчанию выключена) теперь превращается в детерминированные sing-box
`outbounds` и `outbounds`-группы. Инбаунды TProxy и маршрутные правила TProxy не
изменены; для пустой/выключенной секции `proxies` выход **побитово прежний**
(golden и `tests/test_tproxy.py` не тронуты).

Разворачивается **только при `proxies.enabled == true`**:

- локальные `direct`/`block` из контракта рендерятся как есть (без серверных
  полей);
- типы `shadowsocks`, `vmess`, `vless`, `trojan`, `hysteria2`, `tuic` — с
  `server`/`server_port` и блоком `tls` (`server_name`/`insecure` по полям
  контракта);
- группы `selector`/`urltest` (`interval` из `interval_minutes`, `url`);
- `route.final` выбирается детерминированно: первая `selector`-группа (по tag),
  иначе первая `urltest`-группа, иначе `direct`.

### Детерминизм и ссылки

- `outbounds` сортируются по `tag`, группы — по `tag`; порядок внутри
  `group.outbounds` сохраняется как заданная приоритетность (это семантика
  селектора, а не «сортировка»).
- Ссылки групп валидируются существующим `validators.validate_proxies`
  (`proxy.group_reference`, `proxy.group_recursive`, `proxy.group_empty`).
- Добавлен `proxy.tag_reserved`: контракт не может занять implicit-tag `direct`
  (иначе route-цель неоднозначна).
- Ни один сгенерированный `outbound` не ссылается на несуществующий tag;
  `route.final` всегда указывает на отрендеренный tag.

### Секреты

Генератор **не расшифровывает** `EncryptedSecret` (детерминизм, отсутствие I/O,
ключ ему недоступен). Секрет-несущие поля sing-box получают фиксированные
не-секретные заглушки (`PLACEHOLDER_UUID` — nil-UUID, `PLACEHOLDER_PASSWORD` —
`redacted`). Ciphertext и plaintext в preview не попадают — проверено тестом и
ниже. Реальная инъекция секрета относится к будущему apply-пути (не реализовано)
и должна идти через `secrets.decrypt_secret`. `admin_listen` не рендерится
(административный endpoint не реализован); валидатор по-прежнему запрещает
не-loopback bind.

## Проверка на VM

VM: `vsr-tproxy-lab` (одноразовая; `vsr-live-403ab3a` не трогалась).
Бинарник: `/var/cache/vsr-singbox-probe` — `sing-box version 1.14.2`, go1.26.8,
linux/amd64. Доставка: `vm-push.sh` (LAN 192.168.122.1:8099 → `/root/vsr-probe`).

Конфиг сгенерирован оффлайн через `model_copy`/валидный contract с
`proxies.enabled=true`; gate TProxy **не** открывался
(`tproxy.enabled` остался `false`). Все 6 прокси-типов, local
`direct`/`block`, группы `urltest`+`selector`, `route.final="select"`.

```
--- non-empty proxies ---
EXIT_0
--- legacy empty ---
EXIT_0
```

`sing-box check -c` вернул **exit 0** и для контракта с непустыми
outbound'ами/группами, и для legacy-конфига (пустые proxies) — предупреждений
об устаревших local-типах `direct`/`block` не напечатано.

SHA256 загруженных файлов (guest `sha256sum`):
- `singbox-outbounds-probe.json` — `99d3230a3358ab6bfe1de10d2a79d986978ceaf9c6a9dd7ce61d1fe52c867b8f`
- `singbox-legacy-probe.json`  — `0132fa355ec5f562598c29a438260bc0273fd4f1050322ef981f0642c8a7c5f1`

Команда на VM: `/var/cache/vsr-singbox-probe check -c <file>`.

## Тесты

`backend/tests/test_singbox_outbounds.py` — 15 тестов: генерация из контракта,
порядок и разрешение ссылок, сохранение приоритета группы, детерминизм при
перестановке контракта, отсутствие секретов/заглушки, `proxy.reserved_tag`,
выключенная/пустая секция → прежний вывод, неизменность TProxy-правил и
инбаундов.

`backend/` — `uv run --no-sync pytest -q` → **531 passed**.

## Не реализовано / границы

- Фетч подписок, downloader, rule-set'ы, планировщик, UI, agent-команды.
- Реальная инъекция расшифрованного секрета в конфиг (apply-путь) — заглушки
  только для preview/check.
- `shadowsocks.method` не смоделирован в контракте — используется фиксированный
  `chacha20-ietf-poly1305`.
- `add`/`remove`/`update` outbound'ов, выбор выхода на уровне правила TProxy
  (у `TProxyRule` только `direct`/`block`) и проверка packet-path — вне scope.
- `sing-box check` подтверждает только синтаксис/схему конфига, **не**
  устанавливает sing-box, не открывает перехват и не доказывает совместимость
  протоколов/форкового AWG-outbound.
