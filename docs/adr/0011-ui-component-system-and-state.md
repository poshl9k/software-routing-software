# 0011. Frontend component system and state strategy

- Status: accepted
- Date: 2026-10-06

## Context

The frontend had grown to ~7k LOC with two flat grab-bag modules (`ui.tsx`,
`editor.tsx`) and no shared editor primitive. Consequences found in the audit:

- Ten hand-rolled native `<TextField select>` with manual `SelectProps.native` +
  `slotProps.inputLabel.shrink` — the exact label-over-value bug class fixed
  once before.
- Seven copies of the same draft lifecycle (local `editing`/`saving`/`error`,
  `saveDraft`, the `Черновик vN сохранён` notice, `EditorFooter`, `fieldset`).
- Four copies of `nameValid`, two of `domainValid`, and a `Routing` layout class
  (`.form-grid`) that was never defined in the stylesheet.
- Colour tokens duplicated between `theme.ts` and `styles.css`, so the two could
  drift.
- Unicode glyphs in the sidebar and emoji in the dashboard used as icons.
- Hard-coded "diagnostic" rows presented as real data in the DNS, Proxy and
  Network screens, against the no-fabricated-data rule.

The state layer is a single React context of ~25 fields. Server state (leases,
rule counters, diff, apply marker, host interfaces) is fetched ad hoc per page
with local loading/error state and no cache.

## Decision

1. **One component library** in `src/components/` (plus `src/hooks/`), and the
   removal of `ui.tsx`/`editor.tsx`. Every dropdown is the single `Select`;
   validators live once in `validators.ts`; icons are an inline-SVG set with no
   new dependency.
2. **One draft lifecycle** — `useDraftEditor` + `EditorShell` — shared by all
   editor pages, with the page supplying only `empty`, `valid` and a `commit`
   mapper.
3. **One colour source** — `theme.ts` owns the tokens and publishes them to the
   layout stylesheet as `--vs-*` custom properties via MUI `GlobalStyles`;
   `styles.css` carries layout only.
4. **Keep MUI + React Context for now.** Adopt **TanStack Query** in phase (b),
   pointwise, for the pure server-state reads (DHCP leases, rule counters, diff,
   host interfaces/addresses, TProxy preview). Two exceptions: the version list
   stays in context, and **apply status is not a Query** — its RPC may perform an
   already-due rollback, so it is read imperatively through one shared
   `useApplyStatus` hook rather than cached/deduped/background-refetched.
   Consider Zustand or context selectors only if over-rendering is measured.
5. **One editor "chrome"** (follow-up pass after the primitives landed). Every
   editor form is laid out by `FormGrid` (`FormWide` spans a row, `FormActions`
   is a field-level button row); every removal is the same icon-only
   `DeleteButton` (trash glyph, tooltip, `aria-label`) placed in the card header
   or at the row end; the edit toggle sits right-aligned in `.toolbar-actions`
   and every editor ends in `EditorFooter`. Inside a table a control fills its
   cell (`min-width` floor, `vertical-align: top`) and the column header is the
   only visible label — the per-control name moves to `aria-label`, so
   `getByLabelText` in the tests still matches. `Field`/`Select` reserve one
   helper line so rows keep equal height instead of jumping when a message
   appears. `Field` is the only text input a page uses: its API covers
   `autoComplete`, `readOnly`, `required`, native `inputProps` (min/max/pattern),
   `className`/`sx` and an optional `onChange` (read-only values). `Toggle`
   (switch) is the standalone boolean; `Checkbox` remains for multi-select
   groups and dense inline options. Tab strips are also a primitive: `PageTabs`
   (index) and `ValueTabs` (route/state key) so no page imports MUI `Tabs`.
   The full rule set for future changes lives in `docs/ui-rules.md`.

## Consequences

- Duplicated primitives and the editor pattern are gone; a new page reuses
  `Select`/`Field`/`Card`/`DataTable`/`useDraftEditor` instead of copying them.
- The label-over-value and undefined-class bugs cannot silently return through
  a new hand-rolled select or a stray class name.
- Removing the fabricated diagnostic rows means those screens honestly show
  "not wired yet" rather than fake data.
- Deferring a state manager keeps the change reviewable and avoids rewriting
  every test around a new data layer for an unproven performance gain. The cost
  is that server-state caching stays manual until phase (b). The single ~670 kB
  MUI chunk that once tripped the 500 kB warning is now split by `manualChunks`
  into react / mui / query vendor chunks (app ~317 kB, mui ~303 kB, react ~51 kB,
  query ~33 kB).
