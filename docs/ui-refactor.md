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

## Verify
- [x] `npx tsc --noEmit` — clean
- [x] `npx tsc --noEmit --noUnusedLocals --noUnusedParameters` — clean
- [x] `npx vitest run` — 67/67 green (2 selectors updated: `Экспорт пира`, `статус агента не прочитан`)
- [x] `npm run build` — ok (bundle 670 kB / 207 kB gzip; chunk-size warning noted for phase b)

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
- [ ] Code-split the MUI bundle (`manualChunks`) to clear the 500 kB warning
- [ ] i18n extraction (documented gap)