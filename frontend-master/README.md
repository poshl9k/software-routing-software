# frontend-master — админский интерфейс мастер-портала (`vs_master`, ADR-0035)

Мини-приложение по образцу `frontend-portal/`: тот же theme.ts (токены `--vs-*`),
те же сборка/тесты. Этап 1, статус в `docs/master-portal-plan.md`.

## Запуск и гейт

```sh
npm install        # npm ci после коммита lockfile
npm run dev        # Vite на 127.0.0.1, /api → 127.0.0.1:8000 (мастер)
npm run typecheck && npx vitest run && npm run build
```

Сборка в `dist/`; для деплоя в каталог мастера — `VS_MASTER_STATIC_DIR=<dir> npm run build`.

## Правила

Те же, что для `frontend/` (`docs/ui-rules.md`): один примитив на задачу,
плоские поля, цвет только из токенов темы, тесты ведут себя как оператор.
Экраны: вход/первый запуск, ноды, абоненты, тарифы (строятся на
`/api/master-admin/*` и `/api/admin/*`).
