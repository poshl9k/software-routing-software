# UX/UI refactor checklist

Scope decision (grilled): phase **(a)** now — consolidate primitives, unify the
draft-editor pattern, kill dead code, single token source, inline-SVG icons, no
new dependencies. Phase **(b)** (TanStack Query for server state) — later,
pointwise, after review. MUI + React Context stay for now.

Contract: all `frontend` tests stay green (`npm test`), `npm run typecheck`,
`npm run build`. User-visible label text and role/name queries are preserved
except where a change was explicitly agreed (TODO-API copy, `demo` rename).

## Foundation — `src/components/`
- [x] `format.ts` — `fmtDateTime` moved out of `ui.tsx`
- [x] `validators.ts` — every `*Valid` + `lines`/`split`/`normalize` in one place; distinct `nameValid` (rule/alias) vs `ifaceNameValid` (interface)
- [x] `Icon.tsx` — inline-SVG set (14 glyphs), replaces unicode/emoji
- [x] `Badge.tsx` — MUI Chip, tone→token mapping
- [x] `EmptyState.tsx`, `InfoNote.tsx` (replaces `Todo`, drops `TODO-API ·` prefix)
- [x] `PageHeader.tsx` — the `h1.page-title` contract
- [x] `Card.tsx`, `DataTable.tsx` (empty-state aware), `Tabs.tsx` (`PageTabs`)
- [x] `Field.tsx`, `Select.tsx` (`Select`/`SelectField`/`InterfaceSelect`), `Toggle.tsx`
- [x] `ErrorNotice.tsx`, `EditorShell.tsx` (+ `EditorFooter`, `EditorFieldset`)
- [x] `hooks/useDraftEditor.ts` — one draft lifecycle for all 7 editors

## Foundation stream — page structure and status
- [x] `PageSection` — section heading and content beneath the single `PageHeader` h1
- [x] `StatTile` — compact metric with an explicit value or unknown state
- [x] `InlineStatus` — inline state or feedback with text, not colour alone
- [x] `StatusHero` — prominent page state, including unknown without implying healthy
- [x] `ApplyStatusRail` — prop-only apply lifecycle display; caller owns status and timestamps; countdown `aria-live` changes only with phase
- [x] `ServiceStatusHeader` — shared service heading and honest state
- [x] `WizardProgress` — accessible wizard step progress; the decimal marker is a CSS counter, because a native list marker of the next step is painted outside its own box and lands in the gap of the previous one (the row read as «Кому2. Что»)
- [x] `LoadingSkeleton` — loading placeholder without fabricated data
- [x] `ExpertDisclosure` — keyboard-accessible optional controls with expanded state
- [x] `ConfirmDialog` — MUI confirmation for new destructive or other risk actions

## Pages migrated to the shared library
- [x] `Network.tsx` — `.form-grid` fix not here (Routing), raw selects replaced
- [x] `Firewall.tsx` — raw selects replaced, `Collection`-style footer unified
- [x] `ServiceEditors.tsx` (DHCP/DNS) — `useDraftEditor` + `EditorShell`
- [x] `ConnectionEditors.tsx` (Tunnels/Sites/DDNS) — `Collection` on primitives
- [x] `Routing.tsx` — fixes undefined `.form-grid`
- [x] `SSH.tsx` — `useDraftEditor`
- [x] `Services.tsx`, `Dashboard.tsx`, `ApplyScreen.tsx`, `Maintenance.tsx`
- [x] `Onboarding.tsx` (Onboarding + Login)
- [x] `App.tsx` — `Layout`, nav icons, `demo`→`noConfiguration`
- [x] `state.tsx` — `demo`→`noConfiguration` rename

## Cleanup
- [x] `styles.css` — layout only; colours come from `theme.ts` tokens via `GlobalStyles` CSS vars
- [x] remove legacy CSS aliases (`--sidebar-bg`, `--workspace-bg`, `--card-border`, `--accent-blue`, `--status-*`, `--text-secondary-legacy`) and unused `.avatar`
- [x] delete `ui.tsx` and `editor.tsx` after migration
- [x] TODO-API user copy → product language; dev gaps stay as code comments

## Review follow-ups (applied)
- [x] `Field` floats its label when a placeholder is present (label/placeholder overlap)
- [x] `EditorShell.edit` accepts a render function, so the edit branch is only evaluated in edit mode
- [x] `SelectField.required` opt-in — no false "empty value" error for the universal enum select
- [x] `Select.ariaLabel` — unique accessible name for the repeated Network row selects (verified on the native `<select>`)
- [x] removed dead `uncertain` destructure in `state.tsx`

## Second pass — editor chrome
- [x] `Form.tsx` — `FormGrid`/`FormWide`/`FormActions`; every editor form (Tunnels/Sites/DDNS, DHCP, DNS, Routing, SSH, Apply, Onboarding) lays out in one adaptive grid, so fields no longer sit as ragged `inline-flex` rows
- [x] `DeleteButton.tsx` — one icon-only trash action (tooltip + `aria-label`) for card headers and row ends, replacing every ad-hoc red text button
- [x] `EditorFooter` everywhere (incl. SSH); the edit toggle always sits right-aligned in `.toolbar-actions`
- [x] table editors (`Network`, `Firewall`, DHCP pools/reservations, DNS records/forwards): the column header is the only visible label — the per-cell name moved to `aria-label` (`getByLabelText` still matches); controls fill the cell (`min-width` floor, numeric cells narrower), `vertical-align: top`
- [x] `Field`/`Select`/`InterfaceSelect` reserve one helper line so rows keep equal height; `SelectField`/`InterfaceSelect` gained `ariaLabel` + an optional `label`
- [x] `.fields` (Onboarding/Apply) stretches its controls to full width
- [x] `Field` API extended (`autoComplete`, `readOnly`, `required`, `inputProps`, `className`, `sx`, optional `onChange`) so the last raw MUI `TextField`s were migrated: Onboarding/Login, Maintenance (backup passwords, ping/traceroute, update), ApplyScreen (confirmation window), Services (lease search), the tunnel SecretField and the read-only identity fields — a page no longer hand-rolls a text input
- [x] `Checkbox` stays only where it is semantically right: multi-select groups (Routing ingress, SSH interfaces). Standalone booleans use `Toggle`; two dense inline options in Maintenance keep `Checkbox` (a `Switch` would outweigh the compressed row)
- [x] `Icon.name` narrowed from `string` to `IconName` (a typo is now a type error instead of a silently blank glyph); `navigation` is typed
- [x] `api.release()` (unused client method) removed; `Firewall` row deletes now carry a per-row `aria-label` instead of a shared «Удалить»
- [x] `ValueTabs` added to `Tabs.tsx` and `Network`/`Firewall` migrated: no page imports MUI `Tabs`/`Tab` any more (`PageTabs` = index strip, `ValueTabs` = route/state key)
- [x] `docs/ui-rules.md` — the canonical UI rule set for future agents (rules + pre-flight checklist), referenced from `AGENTS.md`

## Verify
- [x] `npx tsc --noEmit` — clean
- [x] `npx tsc --noEmit --noUnusedLocals --noUnusedParameters` — clean
- [x] `npx vitest run` — 67/67 green (2 selectors updated: `Экспорт пира`, `статус агента не прочитан`)
- [x] `npm run build` — ok (manualChunks: app ~317 kB / 97 kB gzip, mui ~303 kB; no 500 kB warning)

## Result
- `ui.tsx` and `editor.tsx` deleted; all consumers use `src/components/`.
- Every native `<TextField select>` hand-rolled in pages replaced by one `Select`.
- 7 editor pages share `useDraftEditor` + `EditorShell`.
- Fake diagnostic fixtures (DNS/Proxy/Network) removed — real gaps now show `EmptyState`/`InfoNote`.
- ADR: `docs/adr/0011-ui-component-system-and-state.md`.

## Phase (b) — server state (TanStack Query)
- [x] `@tanstack/react-query` added; per-provider-tree `QueryClient` created inside `RouterProvider` (fresh cache per app mount and per test); query-key factory in `src/query.ts`
- [x] DHCP leases (`Services.tsx`) — pilot: `enabled` on the leases tab, `refetch` for «Обновить», a submitted `term` drives the search key (no per-keystroke fetch)
- [x] rule counters (`Maintenance.tsx`): `enabled: admin`, `refetch` for «Обновить»
- [x] `diff` (`ApplyScreen.tsx`): `enabled` when a confirmed version and a draft exist
- [x] host interfaces + live addresses (`Network.tsx`, `Onboarding.tsx`): shared cache key; addresses gated off in edit mode; onboarding enables the inventory only after the account step (preserves the login→inventory call order test)
- [x] TProxy preview (`Routing.tsx`): on-demand `enabled: false` + `refetch()`; `removeQueries` when entering edit / saving; error surfaced from the query
- [x] apply status: **not** a Query (the RPC may perform an already-due rollback). Duplicated topbar/screen reads collapsed into one imperative `hooks/useApplyStatus.ts` (`enabled` parks it on the Apply screen; `refreshToken` forces the screen's manual re-read; `clearErrorOnRefresh`)
- [ ] Zustand (or context selectors) only if over-render is measured
- [x] Code-split the MUI bundle (`manualChunks`) to clear the 500 kB warning — split into react / mui / query vendor chunks (app ~317 kB, mui ~303 kB, react ~51 kB, query ~33 kB)
- [ ] i18n extraction (documented gap)

## Keenetic-parity pass — step 1: firewall rules list

Reference material: `docs/ui-refs/keenetic/` (screenshots + UX logic of the Keenetic web
configurator), synthesis in `00-KEENETIC-UX-LOGIC.md`.

- [x] `Firewall.tsx` zone tabs — the rule list stopped being one concatenated text column:
  explicit `№, Имя, Действие, Протокол, Откуда, Куда, Порт, Состояние, Действия`, so order
  of evaluation is a number and each attribute is scannable (Keenetic: priority + separate
  columns)
- [x] the implicit default deny stays visible as a trailing row (`Запретить (по умолчанию)`)
  instead of being implied
- [x] empty zone shows `EmptyState` «Нет правил.» + the implicit-deny sentence; the add
  action stays a single button in the card (Keenetic empty-state pattern)
- [x] per-row `DeleteButton` with a per-row label (`Удалить правило <имя>`); deletion was
  previously reachable only through the composer
- [x] `.table-wide` (styles.css) — the wide read-only rules table scrolls horizontally
  instead of letting `wordBreak: break-word` from `theme.ts` split headers per character at
  ~900 px. Verified by rendering the page (stub API + vite dev + CDP screenshots), not by
  tests; see `docs/ui-rules.md` §3 for the clarified rule
- [x] deliberate deviation: at ≲1040 px the actions column needs horizontal scrolling.
  A sticky actions column was rejected for now (needs a surface-coloured sticky cell and
  hover states); revisit if the narrow-window case matters
- [ ] not done in this step: drag-to-reorder rows, multi-select + bulk delete/move/copy
  between zones, per-row enable toggle (needs an `aria-label`-only toggle primitive),
  icon-only row edit (needs a pencil glyph in `Icon.tsx`)

## Keenetic-parity pass — step 2: overview (`/`)

- [x] «Службы · текущее состояние» stopped being a `.stats` soup of `DHCP: <chip>` lines —
  now a `DataTable` (`Служба` / `Состояние`) with the existing `RuntimeServiceInline`
  (Keenetic: a service is a row with its state in its own column)
- [x] every overview table passes a concrete `empty` (`Интерфейсы WAN не настроены.`,
  `Подсети DHCP не настроены.`, `Туннели не настроены.`, `Сайты не настроены.`) instead of
  the generic `Нет записей` (Keenetic names what is missing)
- [x] the journal card said the same thing twice (`InfoNote` + `EmptyState`) — collapsed to
  one honest message; `/events` keeps its `PageHeader` in standalone mode
- [x] `StatusHero` for the connection gained an `action` link to `/network`; the honest
  unknown state («Телеметрия не подключена») is untouched — we have no telemetry to show
- [x] narrow-window table compression on the overview is fixed by two changes, both
  measured rather than guessed: (1) `RuntimeServiceInline` gained `showAsOf` and the tunnel
  row passes `false` — the `as of` timestamp was what made the `Статус` column demand 345 px
  (table preferred width fell 661 → 419 px); (2) `.dash-grid` collapses to one column below
  1320 px (`styles.css`), because two cards need ≥ ~1300 px of viewport before each card is
  wider than its widest table. Earlier `.dash-grid table { min-width }` was tried and
  reverted — it clipped neighbouring columns. Verified at 1280 / 1400 / 1600 px: no table
  narrower than its preferred width, no per-character header splits

## Keenetic-parity pass — step 3: DHCP (`/dhcp`)

Reference: `03-home-network-dhcp.md` (Keenetic keeps permanent-IP devices, subnets and leases
as separate lists, and answers a failed list read inside the list).

- [x] «Подсети и диапазоны» got a concrete empty state («Подсети DHCP не настроены.») instead
  of the generic `Нет записей`
- [x] the lease list state now lives in exactly one place — the table cell. Removed the
  `InfoNote «Получено аренд: N»` receipt, the separate `Badge «Kea ctrl-agent недоступен»`
  and the `ErrorNotice` above the table; the cell distinguishes loading / 502-503 /
  other read error / genuinely empty
- [x] `fmtRemaining` added to `components/format.ts` — `expires_in` is a number of seconds and
  the column used to print it raw (`2740`); now «45 мин», «23 ч 23 мин», «менее минуты»,
  «истекла». Column renamed to «Истекает через»
- [x] an applied lease search is visible («Показаны результаты по запросу «term»») with a
  `Сбросить` action restoring the full list
- [x] deliberate deviation from ui-rules §4: a failed *read* of the lease list is shown as an
  `EmptyState` inside the table rather than through `ErrorNotice` — `ErrorNotice` is for
  risque actions; Keenetic answers a failed list read in the list area. Verified on the stub
  for all four states

## Keenetic-parity pass — step 4: DNS (`/dns`)

Reference: `04-dns.md` (Keenetic separates the server/profile level from the routing level and
never hides whether DNS is encrypted).

- [x] both DNS tables got concrete empty states («Локальных имён нет.»,
  «Доменов с отдельным DNS нет.») instead of the generic `Нет записей`
- [x] the encrypted-vs-plain distinction is now visible: one local `formatUpstream` renders
  `DNS (UDP) · <address>:<port>` / `DoT · <tls_name> (<address>:<port>)` /
  `DoH · <doh_server>` in both the forwards table and the «Режим и доступ» list. Before,
  `u.address || u.doh_server` printed a bare `1.1.1.1` or a Google URL with no hint that
  one is plaintext UDP — the panel could not answer "is my DNS encrypted?"
- [x] the query-log `InfoNote` moved out of the «Режим и доступ» card into its own
  «Журнал запросов DNS» card with one honest message (one message, in the place it belongs)
- [x] `frontend/src/test/dns-readonly.test.tsx` added: empty texts, UDP/DoT/DoH labels in both
  lists, DoT without a TLS name, and the query-log message existing only in its own card

## Keenetic-parity pass — step 5: tunnels (`/tunnels`)

Reference: `06-apps-vpn-tunnels.md` (Keenetic shows a VPN server's client list, names an empty
list instead of printing zero, and keeps the peer QR tied to the peer).

- [x] the read-only tunnel card stopped printing `Интерфейс: …` / `Клиентов: …` as bare
  paragraphs and uses the panel's `kv` list (same shape as «Режим и доступ» in DNS)
- [x] a server with no peers says `нет клиентов` instead of `Клиентов: 0`
- [x] the server peers tab shows `Пиров нет.` when empty; the single add-peer button stays as
  the only add action
- [x] per-peer QR dialog left untouched — it already matches the reference (QR belongs to a
  client peer, not to the server tile)
- [ ] open gap: no peer statistics (last handshake, endpoint as seen by the peer, traffic
  volume) — the agent does not expose it yet, and inventing it is forbidden. The reference
  expects a separate stats table next to the status once that data exists
- [ ] open naming inconsistency (pre-existing, one decision): the domain glossary in
  `CONTEXT.md` calls the server-side entry **Пир**, while the editor tab is labelled
  «Клиенты», the fact row «Клиентов», the button «+ Добавить пира» and the new empty state
  «Пиров нет.». Pick one term and rename the rest; recommended is the glossary term (Пир)

## Keenetic-parity pass — step 6: routing (`/routing`)

Reference: `06-apps-vpn-tunnels.md` (policies vs routes), `04-dns.md` (the reusable
«list → rule on the list» shape), `00-KEENETIC-UX-LOGIC.md` §5/§9/§12.

- [x] all six read-only tables on the page now name what is missing instead of printing the
  generic `Нет записей`: «Пользовательских правил нет — выбранный трафик идёт к конечному
  действию.», «Наборы правил не объявлены.», «Прокси-выходов нет.», «DNS-серверов нет.»,
  «DNS-правил нет.», and «Исключений нет.» in the bypass editor
- [x] the empty rules table is deliberately **not** a bare "nothing configured": the built-in
  stages (sniff/DNS/local addresses/UDP) always apply and unmatched traffic goes to the final
  action, so the message says exactly that
- [x] the `configure` rules table got no empty state on purpose — it always renders the four
  system rows S1–S4, so the branch would be dead code
- [x] the page's structure is untouched: two views, guided rule wizard, up/down ordering,
  broken-reference warnings (`ссылка сломана`), engine/final-action cards
- [ ] open: no live-packet proof for this page — the screenshots come from the stub API, not
  from a router (lab verification stays a separate, authorized step)

## Keenetic-parity pass — result

Six sections aligned to the Keenetic reference in `docs/ui-refs/keenetic/`: `/firewall`,
`/` (overview), `/dhcp`, `/dns`, `/tunnels`, `/routing`. Common changes, in order of how often
they repeated:

1. **Empty states stopped being generic.** Every read-only list names what is absent
   (Keenetic pattern, §5 of the synthesis). This was the single most repeated defect — the
   default `Нет записей` hid whether a list was empty or unread.
2. **One state, one message.** Duplicated notices collapsed into a single honest message in the
   place the user looks: the journal card, the DHCP lease list (receipt + badge + error notice
   → one cell), the DNS query-log note moved into its own card.
3. **Explicit columns where a row was concatenated** (`/firewall`: one text blob → nine
   columns, with the implicit default deny shown as a row).
4. **Honest status instead of a number or a colour.** `Клиентов: 0` → «нет клиентов»;
   `expires_in` seconds → «45 мин»; DNS upstreams now show whether they are plaintext, DoT or
   DoH; tunnel cards use the panel's `kv` list instead of paragraphs.
5. **Layout floors instead of squeezed words.** `.table-wide` for the wide read-only rules
   table and a one-column `.dash-grid` below 1320 px, both measured rather than guessed.

Verified for every step: the frontend gate (`tsc --noUnusedLocals`, `vitest`, `build`) run by
hand on the working tree, plus rendered screenshots of the populated and empty states (20 files
in `docs/ui-refs/keenetic/screenshots/vs-router-after/`). No live-router proof was produced —
the panel was exercised against a stub API only.

Open decisions left for the user:
- tunnel entry terminology: «Клиенты» vs the `CONTEXT.md` glossary term «Пир»;
- peer statistics (last handshake, traffic) need an agent RPC before the UI can show them.

## Keenetic-parity pass — step 7: proxy (`/proxy`: inbound sites + DDNS)

- [x] the shared read-only table in `Collection` got concrete empty states per kind:
  «Сайтов нет. Добавьте сайт.» / «Доменов DDNS нет. Добавьте домен.» — the add action lives in
  the card header, so a generic `Нет записей` gave no hint that the list is simply empty
- [x] inbound sites gained a `.sub` note about what the «Статус» column actually knows
  (`Состояние сертификата на устройстве панель пока не читает…`), mirroring the DDNS note that
  already existed. The per-row value stays honest; no certificate phase is invented
- [ ] open: the panel still does not read the live certificate state or the last DDNS update
  result — an agent RPC is needed before either column can carry real data

## Keenetic-parity pass — step 8: diagnostics (`/diagnostics`) — component-system migration

`Diagnostics.tsx` was the only page that bypassed the panel's component system: the import audit
prescribed by `docs/ui-rules.md` §1 returned 14 forbidden imports
(`Box, FormControl, InputLabel, MenuItem, Paper, Select, Stack, Table, TableBody, TableCell,
TableContainer, TableHead, TableRow, TextField`).

- [x] the hand-rolled connections table became `DataTable` (same 8 columns, same cell content),
  wrapped in `.table-wide` for its width
- [x] raw `TextField` → `Field`; raw `Select`+`FormControl`+`InputLabel`+`MenuItem` →
  `SelectField`/`Select` with the same labels and options; `Stack`/`Box` wrappers →
  the existing `.diag-controls` / `.form-grid` classes
- [x] the import audit now returns `[]` for this page (only `Button`/`Typography` remain)
- [x] `maskLog` (the log redaction guard: passwords, URLs, IPs, hostnames) was **not touched** —
  verified by reading the diff and by rendering a log line containing `token=abcdef`, which still
  renders as `[скрыто]`
- [ ] note: `Routing.tsx` is the one remaining page with a non-listed MUI import
  (`Radio`/`RadioGroup`, for the TProxy rule action choice). There is no primitive for a radio
  group; either add one or record the exception explicitly

## Keenetic-parity pass — terminology + `/network` residuals

- [x] the server-side tunnel entry now uses the `CONTEXT.md` glossary term everywhere: editor tab
  «Клиенты» → «Пиры», read-only fact «Клиентов» → «Пиров», empty value «нет клиентов» →
  «нет пиров»; tests updated
- [x] `/network` interface table column `Черновик` → `Конфигурация` (the cells hold
  «Черновик»/«Применено»/«Статус неизвестен», i.e. configuration state, so the old header named
  a lifecycle value instead of the fact)
- [x] the per-interface WAN addresses table got `У этого интерфейса нет адресов.`

Audited read-only and left alone (already compliant with the reference, so editing them would be
churn):
- `/ssh` — the empty case already says «Сначала назначьте интерфейс сетевой зоне», the WAN
  confirmation dialog separates the risk action, and the default-off state is stated;
- `/maintenance` — counters/release/ping/traceroute use primitives and honest unknowns; the only
  residual is that ping/traceroute show nothing before the first run (a hint would be nice, not a defect);
- `/onboarding` — `WizardProgress` with four steps and explicit first-apply warnings, matching the
  reference's wizard shape;
- `/events` — shares the journal card fixed in step 2, so it is already a single honest message.

## Series 2 (steps 10–17): every list-item editor becomes its own window

The first series fixed what the pages *said*; the second fixed how they *behaved* when you edit.
`docs/ui-rules.md` §9 now states the rule («one object = one form», «an editor of a list item opens
in its own window», identity shown once read-only, creation actions in one place), and every
surface was brought under it. Work list, evidence and the standing audit commands live in
`docs/ui-conformance.md`.

Converted from an inline form in the page flow into a modal window over the list, with a grouped
form (`PageSection` sections) and `EditorFooter` inside the dialog: interface (`/network`), tunnel
and sites/DDNS (`ConnectionEditors.tsx`), firewall rule (`Firewall.tsx`), DHCP reservation, subnet
list and DNS (`ServiceEditors.tsx`), routing sets/DNS/wizard/bypass (`Routing.tsx`), proxy
outbounds/subscriptions/groups (`RoutingProxy.tsx`). The state that carried one-object tabs
(`detailTab`, the tunnels `tab` indices, the firewall composer card) is gone with them.

Two defects were caught by looking at the screenshots rather than at the diff: the firewall rule
dialog duplicated the row's delete action, and the TProxy bypass section left a delete icon
floating in the page flow.

## Routing master — approved HTML references

- [x] `ChoiceCards`: two-column choices, read-only identity rows, four-column
  catalogue tiles; keyboard accessible, selected state and disabled reasons.
- [x] `FlowChain`: wrapping `Badge` chips with `Icon` arrows, static description.
- [x] `RoutingSurface` / `SummaryPanel`: scoped routing layout and inset summary.
- [x] `EditorFooter`: optional `saveLabel` and `action`, defaults unchanged.
- [x] `Icon`: device, arrow and seven category icons; literal `IconName` union.
- [x] Numbered step cards, real service DNS presets, OR wording, six exit cards,
  preview/system rows, expert engine block, existing modal item editor.
- [x] Save uses `useDraftEditor`; success resolves the saved context version,
  invokes the existing `useApplyCommands` global command, opens `/apply` for
  confirmation/status. Save-only never invokes apply.
- Deliberate reference corrections: destinations cannot be empty; presets are
  concrete domains, not geosite links; unmatched devices fail closed and the
  remaining traffic follows configured final/group selection, not always direct.
  System rows are shown first for reference, but their conditions explicitly
  place them AFTER the applicable user rules. No fabricated TProxy stages.
- Catalogue tiles scroll inside a bounded four-column surface rather than
  pushing manual fields below dozens of rows. Small screens use two columns.