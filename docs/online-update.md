# Онлайн-обновление: канал выпусков (ADR-0010)

Чек-лист внедрения канала обновлений «по проводу». Формат выпуска задан
ADR-0010: манифест `release.json` + tar-артефакт зафиксированного коммита,
сверка `source_sha256` и `REVISION == commit`. Ветки и `latest` запрещены
(ADR-0005). Хост выпусков — ассеты GitHub Release (бесплатно; лимит 2 ГиБ на
файл, общего лимита и лимита трафика нет).

## Оставшийся объём

- [x] **Хост выпусков:** GitHub Release assets на тег `vs-router-<commit>`.
      Обоснование: бесплатный, версионируемый, неизменяемый URL ассета;
      `release.json` кладём рядом с архивом.
- [x] **`backend/packaging/make-release.sh`** — собрать `vs-router-<commit>.tar.gz`
      (дерево коммита + `REVISION` внутри) и `release.json`
      (`commit/semver/source_url/source_sha256/min_os`); опционально
      `--upload` через `gh release create`.
- [x] **`update.sh` без `git fetch`:** `--release <40hex>` / `--manifest <url>`
      → скачать манифест → проверить `sha256` и `REVISION` → распаковать в
      `/opt/vs-router.new` (прежнее дерево сохраняется в `/opt/vs-router.prev`)
      → пересборка/wheel/`alembic`/деплой UI+units/рестарт.
      Обоснование: на self-contained ISO (ADR-0008) в `/opt/vs-router` нет
      `.git`, поэтому git-путь неработоспособен.
- [x] **Строгие проверки:** https-only загрузка, sha256 артефакта
      (fail-closed), `REVISION` из архива == коммит манифеста, проверка
      раскладки дерева до подмены; падение миграции/рестарта — фатально.
- [x] **Панель + RPC:** `GET /api/update` (read-only, admin, no-store) сравнивает
      установленный выпуск (`/api/release`) с манифестом; `POST /api/update`
      (admin) запускает обновление через whitelisted RPC агента
      (`update_status` / `apply_update`). Применение не блокирует RPC-цикл:
      агент стартует detached-юнит `vs-router-update` с
      `backend/packaging/update-run.sh`, который пишет итог в
      `/run/vs-router/update-state.json`; статус показывает «выполняется» и
      последний результат. Запрошенный коммит сверяется с манифестом (нельзя
      поставить произвольный код). URL манифеста — host-owned
      `/etc/vs-router/update.json` (`{"manifest_url": "https://..."}`) или
      `VS_ROUTER_UPDATE_MANIFEST_URL`.
- [ ] **Подпись артефакта** (minisign/cosign) — будущее усиление поверх sha256.
- [ ] **Автооткат выпуска:** `update.sh` сохраняет прежнее дерево
      (`/opt/vs-router.prev`), но автоматического возврата при неудачном
      рестарте нет; решать с панелью.

## Настройка хоста

```bash
# /etc/vs-router/update.json  (host-owned; панель и агент читают только его)
echo '{"manifest_url": "https://github.com/<owner>/<repo>/releases/latest/download/release.json"}' \
    > /etc/vs-router/update.json
```

Без этого файла (и без `VS_ROUTER_UPDATE_MANIFEST_URL`) панель показывает
«URL манифеста не задан», а `POST /api/update` отвечает `update.not_configured`.
Панельная «применить» требует, чтобы `commit` манифеста совпал с запрошенным,
и стартует detached-юнит `vs-router-update` (`backend/packaging/update-run.sh`);
прогресс и результат видны в `/run/vs-router/update-state.json`.

## Как выпустить

```bash
# локально: собрать артефакт и манифест в ./release
VS_ROUTER_RELEASE_BASE_URL="https://github.com/<owner>/<repo>/releases/download/vs-router-<commit>" \
    backend/packaging/make-release.sh <40-hex-commit>

# загрузить в GitHub Release (ассеты получают неизменяемые URL)
backend/packaging/make-release.sh <40-hex-commit> --upload
```

## Как обновиться на сервере

```bash
# по манифесту конкретного выпуска (пиннинг по коммиту)
sudo backend/packaging/update.sh \
  --manifest https://github.com/<owner>/<repo>/releases/download/vs-router-<commit>/release.json

# либо: пиннинг по коммиту + базовый URL манифеста через env
sudo VS_ROUTER_UPDATE_MANIFEST_URL=https://github.com/<owner>/<repo>/releases/latest/download/release.json \
  backend/packaging/update.sh --release <40-hex-commit>
```

`--release` сверяет `commit` манифеста с запрошенным — «latest/download» в URL
выбирает последний *выпуск*, а не ветку, и коммит всё равно проверяется.
