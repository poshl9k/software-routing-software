# vs-router frontend

React + TypeScript + MUI, Vite, React Router. Русские строки; основа структуры и токенов — `mockups/*.html` и `mockups/css/vs-router.css`. `design reference.png` не используется.

```sh
cd frontend
npm install
npm run dev
npm run typecheck
npm test
```

Node 22.12+ (в среде Node 26). Dev proxy: `/api` → `http://127.0.0.1:8000`, исходные Host/Origin сохраняются для same-origin проверки backend. Сессия использует Secure cookie: для полного входа нужен доверенный HTTPS reverse proxy к Vite либо браузер, разрешающий Secure cookies на localhost. При HTTPS proxy он должен согласованно передавать backend схему/Host. Все запросы клиента используют `credentials: include`.

Production-команда `npm run build` предусмотрена, но по условию задачи не запускалась. Артефакт — `dist/`. Uvicorn/FastAPI должен отдавать assets из `dist/assets` и `dist/index.html` как SPA fallback для UI-маршрутов, исключая `/api/*`. В существующем backend такой mount отсутствует; backend не изменён.

## Экраны и интеграция

- `/`: обзор, статусная полоса, WAN, DHCP, интерфейсы, туннели, Caddy, события.
- `/network`: интерфейсы/зоны, fail-closed, упорядоченные WAN-адреса, маршруты и диагностика.
- `/firewall`: вкладки зон (включая router), first match, port forward, outbound NAT и алиасы.
- `/dhcp`, `/dns`, `/tunnels`, `/proxy`: таблицы и карточки по макетам; поиск демонстрационных аренд.
- `/apply`: POST apply/confirm/rollback, окно 60–600 с, фазы из ответа, diff версий. Блокировка повторной команды и нового применения во время известного незавершённого цикла. После ошибки команда считается неопределённой; факт отката не симулируется.
- `/onboarding`: setup создаёт учётку, login устанавливает сессию, `/api/draft` сохраняет LAN. Безопасная настройка хранится локально как предпочтение запроса apply, поскольку серверного API настроек нет. Первая конфигурация требует применения без safe mode: у агента ещё нет stable snapshot.
- `/login`: вход существующей учёткой; `/events`: демонстрационный журнал.

`GET /api/versions` возвращает конфигурации; показывается последняя версия, включая черновик, с явным указанием источника. Пустой список или ошибка дают заметно помеченный демонстрационный набор; пустые списки внутри реальной версии не подменяются примерами. Редактирование таблиц не реализовано.

**TODO-API:** HTTP-маршрута статуса применения в backend нет. RPC `status` возвращает маркер `{version_id, applied_at, deadline, status, phases}`, но браузер не имеет доступа к unix socket. Несуществующий GET `/api/apply` не вызывается. Тип `ApplyMarker` и преобразование Unix deadline подготовлены; до появления маршрута виден последний ответ команды только в текущей вкладке. POST apply не возвращает deadline: countdown использует начало запроса + выбранное окно и явно помечен приблизительным; агент остаётся единственным источником истины. После перезагрузки состояние неизвестно; backend обеспечивает запрет нового цикла. БД draft/confirmed не трактуется как маркер.

Runtime-состояния интерфейсов/Интернета, аренды, счётчики firewall, handshake/трафик, Caddy health и журналы, маршруты, диагностика — типизированные TODO-API. Они не выдаются за живую телеметрию. Всё отображается React-компонентами. Секреты конфигурации типизированы как непрозрачные значения и не выводятся.

Vitest проверяет ключевые экраны, API payload/cookies/errors, onboarding, apply→confirm и таймер. Сетевой интеграционный прогон с агентом и визуальный скриншот не выполнялись.

## Проверки в среде задачи

- Node `v26.9.0`, npm `11.19.1` доступны.
- `npm install` заблокирован DNS/сетью: `EAI_AGAIN registry.npmjs.org`; lockfile не сформирован.
- `npm test` и `npm run typecheck` не стартовали: зависимости (vitest/tsc) не установлены.
- Доступным из локального кэша TypeScript 6.0.3 проверен синтаксис всех 18 TS/TSX-файлов: ошибок нет. Это не полный typecheck React/MUI приложения.
- Отдельная строгая проверка `types.ts`, `api.ts`, `fixtures.ts`, `preferences.ts` прошла.
- Дополнительная проверка API-клиента через Node assert с fetch mock прошла: cookies, apply/confirm/rollback payload, структурированные ошибки, 204, offline, некорректный JSON.
- Production build, скриншот и коммит не выполнялись. Backend не изменён.

## Созданные файлы

```text
frontend/
  .gitignore
  README.md
  package.json
  vite.config.ts
  tsconfig.json
  index.html
  src/
    main.tsx
    App.tsx
    api.ts
    types.ts
    state.tsx
    preferences.ts
    fixtures.ts
    theme.ts
    styles.css
    ui.tsx
    pages/
      Dashboard.tsx
      Network.tsx
      Firewall.tsx
      Services.tsx
      ApplyScreen.tsx
      Onboarding.tsx
    test/
      setup.ts
      api.test.ts
      screens.test.tsx
```
