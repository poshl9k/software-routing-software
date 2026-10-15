# ADR-0016: Параметры AmneziaWG 3 в модели туннеля и импорте клиента

**Статус:** принят
**Дата:** 2026-10-15
**Участники:** владелец продукта и Hermes Agent

## Контекст

Официальное приложение Amnezia (AmneziaWG 3.1) выдаёт клиентский `.conf`, который
содержит не только классические параметры обфускации (Jc/Jmin/Jmax/S1/S2/H1–H4), но и
дополнения AWG 3:

- padding'и `S3`/`S4`, сигнатурные пакеты `I1`–`I5` (`<r 2><b 0x…>`);
- диапазоны `min-max` вместо одиночных значений (`RekeyAfterTime`, `RekeyTimeout`,
  `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, `ContentPaddingAddition`,
  `PersistentKeepalive`);
- `HeaderProtectionKey` (низкоэнтропийная защита заголовков) и флаги
  `RandomTrailers`/`DisableCookies`;
- `PresharedKey` в `[Peer]`.

Это подтверждено документацией `amneziawg-go` (разделы «AWG 3+») и `amneziawg-tools`
(`src/config.c` принимает эти ключи в `awg setconf`). Наш собственный рантайм —
`amneziawg-go`/`amneziawg-tools` **v3.1.20260812** (`docs/lab-02-amneziawg.md`,
`router_project_plan.md`) — поэтому такие конфиги на хосте применимы; ограничение было
только в панели: схема, генератор и парсер импорта знали лишь классический набор, а
значения были строго целыми; `PresharedKey` при импорте отвергался, чтобы не потерять
секрет.

До этого решения `CONTEXT.md` фиксировал набор обфускации как «Jc, S1, S2, H1–H4».

## Решение

1. **Модель (`schema.py`).** `Tunnel.obfuscation` — `dict[str, int | str]`; значение —
   uint32 или строка-диапазон `min-max`, а `I1`–`I5` — сигнатурная строка. Допустимые
   ключи и формат проверяются валидатором (`tunnel.awg_key`, `tunnel.awg_parameter`).
   `keepalive` — `int | str` (секунды или `min-max`, `tunnel.keepalive`).
   Новые поля: `preshared_key` (секрет, клиент), `header_protection_key` (секрет),
   `random_trailers`, `disable_cookies` (bool). `AWG_CORE` (обязательные Jc/S1/S2/H1–H4)
   для `protocol=="awg"` сохранён.
2. **Секреты.** `preshared_key` и `header_protection_key` хранятся шифрованными
   (`EncryptedSecret`, env-ключ) и добавляются в список `encrypt_inputs`
   (`api/configuration.py`); в API-ответах отдаются как `{redacted:true}`.
3. **Генератор (`generators/wireguard.py`).** Порядок эмиссии: Jc/Jmin/Jmax/S1..S4/H1..H4,
   I1–I5, ContentPaddingAddition, тайминги, затем HeaderProtectionKey,
   RandomTrailers/DisableCookies. Ключи, которых нет на туннеле, не эмитятся — конфиг без
   дополнений AWG 3 генерируется байт-в-байт как раньше (golden не меняются). Клиентский
   `[Peer]` дополнительно пишет `PresharedKey`.
4. **Импорт (`frontend/src/tunnelConf.ts`).** Парсер принимает S3/S4, I1–I5, диапазоны,
   `HeaderProtectionKey`, `RandomTrailers`/`DisableCookies` (`on/off/true/false/1/0`) и
   `PresharedKey`; значения обфускации хранятся как число или строка-диапазон.
5. **UI (`pages/ConnectionEditors.tsx`).** Поля обфускации — текстовые (значение или
   диапазон), добавлены `HeaderProtectionKey`, тумблеры `RandomTrailers`/`DisableCookies`,
   поле `PresharedKey` для клиента; строка распознавания при импорте показывает статус PSK.
6. **Keygen не меняется.** `POST /keygen/tunnel` по-прежнему генерирует классический
   набор, чтобы не менять поведение для уже созданных в панели туннелей.

## Вне объёма

- Генерация полного набора AWG 3 для **серверных** туннелей, создаваемых в панели
  (S3/S4/I1 и HeaderProtectionKey), и соответствующая серверная валидация.
- Живая проверка handshake с внешним AWG-3-сервером на Debian-VM (юнит/golden её не
  заменяют; см. `docs/lab-02-amneziawg.md`).

## Последствия

- Импортированный клиентский `.conf` от AmneziaWG 3 применяется на хосте через
  `awg setconf` без потери параметров и с сохранением PresharedKey.
- `obfuscation` больше не «только целые»: кодовые пути, полагавшиеся на `int`, обновлены
  (валидация UI, парсер, генератор); добавлены тесты `test_tunnel_proxy.py` и
  `tunnelConf.test.ts` (в т.ч. полный конфиг AWG 3).
- Старые снапшоты читаются без миграции: новые поля опциональны с дефолтами, документ
  версии хранится как JSON.

Связанные: ADR-0001 (AmneziaWG userspace), `docs/lab-02-amneziawg.md`.
