# Внедрение портала абонента (ADR-0032, ADR-0033)

План работ по ADR-0032 (отдельный публичный процесс) и ADR-0033 (учётка =
Абонент, системное применение операций). Объём — `docs/subscriber-portal-spec.md`.

## PRIORITY

| # | Фаза | Статус | Что сделано |
|---|------|--------|-------------|
| 1 | Контракт стыков (этот файл) | готово | схема БД портала, внутренний интерфейс, API-контракты |
| 2 | Ядро портала: БД + модели + миграции + auth (инвайт/логин/rate limit/аудит) | готово | `vs_portal/` (models, auth, internal, security, errors), `alembic-portal/0001` |
| 3 | Внутренний интерфейс панель↔портал + очереди операций устройств | готово | `vs_router/internal_app.py`, очередь `portal_device_ops`, ретраи, expire/renew |
| 4 | Админ-API портала в панели (тарифы, приглашения, подписки) | готово | `vs_router/api/portal_admin.py`, тест `test_portal_admin.py` |
| 5 | Публикация: Caddy второй hostname, systemd unit, install | готово | `portal_names()` (производный `portal.<custom>`), host-matched маршрут в `management`-сервере, 2 юнита, крюки install.sh |
| 6 | Фронтенд админа: тарифы/инвайты/подписки на странице «Абоненты» | готово | `Subscribers.tsx` переписан по ui-rules, 11 тестов, tsc+build зелёные |
| 7 | Фронтенд портала (отдельное приложение): логин, инвайт, устройства | готово | `frontend-portal/` — build + 6 тестов; 3 уязвимости npm-зависимостей на ревью |
| 8 | Приёмочные проверки MVP (спека, пункты 1–9) | частично | пункты 1–7, 9 покрыты тестами (portal auth/devices/internal/admin + UI); пункт 8 (админ-API недоступен с имени портала) доказан host-matched маршрутом + тестом генератора; живая VM-проверка не проводилась |

Известные падения НЕ из этой волны (воспроизведены на чистом HEAD в worktree):
`test_preset_catalog` ×2 (SHA/счётчики каталога, след коммита c23659f) и
`test_installer_hardening::test_installed_db_migrates_on_rerun` (alembic недоступен
в системном python). Плюс предсуществующие tsc-ошибки в `ConnectionEditors.tsx`.

## Схема БД портала (`vs-portal.db`, отдельный файл, отдельные миграции)

Ключ по имени абонента (`Subscriber.name` из конфигурации — ADR-0033). Пароли
argon2id (как `api/auth.py`). Все метки времени — UTC.

- `portal_accounts`: `subscriber_name` (PK), `password_hash`, `email` nullable,
  `status` ('active'|'disabled'), `created_at`.
- `portal_invites`: `token` (PK, urlsafe 32 байта), `subscriber_name`,
  `password_hash` nullable (вариант «активировать»), `expires_at`, `used_at`
  nullable, `created_at`. Одноразовый: `used_at` ставится при активации.
- `portal_tariffs`: `id` PK, `name` unique, `device_limit` int ≥ 1,
  `term_days` int ≥ 1, `price_amount` nullable (заложено, MVP не используется),
  `created_at`.
- `portal_subscriptions`: `subscriber_name` PK, `tariff_id` FK→tariffs,
  `expires_at`, `status` ('active'|'expired'|'renewed'→'active'), `updated_at`.
- `portal_devices`: `id` PK, `subscriber_name`, `name` (имя пира, уникально
  вместе с subscriber), `label`, `public_key`, `private_key` (зашифрован
  секретами панели, как `EncryptedSecret`), `preshared_key` (зашифрован),
  `allowed_ips` JSON, `status` ('active'|'inactive'|'removed'), `created_at`.
  Хранит материал ключей, чтобы продление вернуло те же ключи/адреса.
- `portal_device_ops`: `id` PK, `subscriber_name`, `op`
  ('create'|'delete'|'activate'|'deactivate'|'expire'), `device_id` nullable,
  `label` nullable, `status` ('pending'|'applied'|'failed'), `detail` nullable
  (код ошибки, человекочитаемое), `created_at`, `applied_at` nullable.
- `portal_audit`: `id` PK, `actor` (имя абонента или 'admin'), `action`,
  `detail` nullable, `at`.

Миграции: `backend/alembic-portal/` — собственная env.py, БД из
`VS_PORTAL_DATABASE_URL` (дефолт `sqlite:///vs-portal.db`). Панель открывает ту
же БД вторым движком (SQLite WAL) — два писателя допустимы для MVP, конкурентные
записи редки.

## Процессы и сокеты

- `vs-router-web.service` — существующая панель (админ-API + агентный RPC).
- **Новый** `vs-router-web-internal.service`: второй uvicorn того же пакета
  `vs_router`, приложение `vs_router.internal_app:app` — ТОЛЬКО внутренние
  маршруты `/internal/portal/*`, UDS `/run/vs-router/web/internal.sock`
  (mode 0660, группа `vs-router-portal`). Админ-маршруты на нём отсутствуют
  физически — не «проксирование с фильтром», а отдельный ASGI-апп.
- **Новый** `vs-router-portal.service`: uvicorn `vs_portal.app:app`,
  UDS `/run/vs-router/portal/portal.sock`, БД
  `sqlite:////var/lib/vs-router/portal/vs-portal.db`, статика
  `/var/lib/vs-router/portal/ui`. Пользователь `vs-router-portal`. Нет доступа к
  агентному RPC, нет путей к админ-сокету.
- Секрет стыка: `/etc/vs-router/portal-internal.secret`, owner
  `vs-router-web`, group `vs-router-portal`, mode 0640; оба процесса читают,
  запросы без верного `X-VS-Portal-Secret` → 403.

## Внутренний интерфейс (портал → панель, узкий)

Все ответы JSON; ошибки — `{"error": {"code": ...}}`, те же коды, что в панели
где применимо. Аутентификация — секрет-заголовок; путь только `/internal/portal/*`.

- `GET /internal/portal/subscribers/{name}/state` →
  `{"subscription": {...}, "devices": [{name, label, status, allowed_ips,
  last_handshake, applied: bool}], "tunnel": {name, obfuscation?, dns_mode,
  exit}}` — из применённой конфигурации + runtime.
- `POST /internal/portal/subscribers/{name}/device-op` — тело
  `{op, device_id?, label?, keys?}`; панель строит черновик из применённой
  версии, применяет сам (системное применение ADR-0033, без подтверждения
  админом — non-safe подтверждает сразу; safe-mode первый apply отказ), в ответ
  `{status, device?}`; при занятом цикле `409 {"error":{"code":"apply.busy"}}`
  — операция остаётся pending в `portal_device_ops`, портал ретраит.
- `POST /internal/portal/subscribers/{name}/expire` — снимает пиры абонента с
  применённой конфигурации (auto-блокировка истечения), ключи остаются в
  `portal_devices`.
- `POST /internal/portal/subscribers/{name}/renew` — возвращает те же пиры
  (материал из `portal_devices`).

## API портала (публичный процесс; cookie `vs_portal_session`, Secure/HttpOnly/SameSite=Lax)

- `POST /api/portal/invite/activate` `{token, password(≥8), email?}` →
  одноразовый токен сгорает, создаёт/активирует аккаунт.
- `POST /api/portal/login` `{username, password}` → rate limit по имени+IP
  (паттерн `api/auth.py`), аудит.
- `POST /api/portal/logout`; `GET /api/portal/me` → аккаунт + подписка +
  плашки («истекает через N дней», «на этом тарифе разрешено N устройств…»).
- `GET /api/portal/devices` — через внутренний интерфейс.
- `POST /api/portal/devices` `{label}`; `DELETE /api/portal/devices/{name}`;
  `POST /api/portal/devices/{name}/activate|deactivate` — все пишут операцию в
  `portal_device_ops`, ответ со статусом ('applied' | 'pending').
- `GET /api/portal/devices/{name}/export?format=conf|qr|amnezia` — генераторы
  панели переиспользуются (ADR-0022), материал ключей из `portal_devices`.

## Админ-API в панели (сессия админа, пишет в БД портала вторым движком)

`/api/portal-admin/*`: CRUD тарифов; `POST .../subscribers/{name}/invite`
(галка «активировать» → в ответе готовый пароль, UI маркирует риск перехвата);
отзыв непринятого приглашения; сброс пароля = новая инвайт-ссылка;
`PATCH .../subscription` (смена тарифа, продление); понижение тарифа ниже
текущего числа устройств разрешено, создание новых блокируется порталом.

## Публикация

`management.py` получает `portal_names()` по модели двух имён ADR-0025:
резерв `portal.<ip>.nip.io` + `portal.<custom>`. Caddy `management`-сервер:
второй маршрут по этим hostname → `unix//run/vs-router/portal/portal.sock`,
`automate`/`subjects` включают имена портала. NFT-правило `management_acme`
уже покрывает :80 — не дублировать.

## Владение файлами в волне A

- **backend-portal**: `backend/src/vs_portal/**`,
  `backend/src/vs_router/internal_app.py`, `backend/src/vs_router/api/portal_admin.py`,
  `backend/alembic-portal/**`, `backend/tests/test_portal*.py`,
  `backend/src/vs_router/app.py` (только монтирование нового роутера).
- **backend-publication**: `backend/src/vs_router/management.py` (только
  portal_names и его тесты), `backend/src/vs_router/generators/caddy.py`,
  `backend/packaging/vs-router-portal*.service`, `install*.sh`-крюки,
  `backend/tests/test_portal_publication*.py`.
- **frontend-admin**: `frontend/src/pages/Subscribers.tsx`, типы/компоненты.
- **frontend-portal**: новый `frontend-portal/**`.
