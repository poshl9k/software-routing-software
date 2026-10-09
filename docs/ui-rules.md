# UI rules

Rules for anyone (human or agent) changing the frontend. They encode the
decisions in `AGENTS.md`, `CONTEXT.md` and `docs/adr/0011-ui-component-system-and-state.md`.
When a rule and your instinct disagree, the rule wins — or change the ADR first.

Every rule is written as **what to do → why → how to check**. The design goal is
one ровный, предсказуемый интерфейс: one primitive per job, one place for each
action, no duplicated labels, no ad-hoc styling.

## 0. Before you touch anything

- **Gate.** Run and keep green: `cd frontend && npx tsc --noEmit --noUnusedLocals --noUnusedParameters && npx vitest run && npm run build`.
  → A red gate means you are not done, regardless of how it looks.
- **No new dependencies** (component lib, styling, icons, state) without an
  explicit decision. MUI + React Context + TanStack Query is the current stack.
- **Language: Russian UI.** New user-visible strings are Russian; keep code and
  comments in English. i18n extraction is a known gap — do not invent a second
  string system.
- **Read the primitive you are about to use** (`frontend/src/components/`). Do
  not guess a prop name; the components are the contract.

## 1. One component per job — never hand-roll

| Need | Use | Do not |
| --- | --- | --- |
| Text / number / password input | `Field` | raw MUI `TextField`; `slotProps.htmlInput` by hand |
| Dropdown | `Select`, `SelectField`, `InterfaceSelect` | `<TextField select>` + `SelectProps={{native:true}}` + `inputLabel.shrink` |
| Standalone boolean | `Toggle` | a hand-built `FormControlLabel`+`Switch` |
| Multi-select group, dense inline option | `Checkbox` + `FormControlLabel` | `Toggle` in a checkbox list (a switch is wrong there) |
| Status chip | `Badge tone="blue|green|amber|red|purple"` | coloured `<span>` |
| Read-only table | `DataTable` | hand-rolled `<table>` |
| Card with a header action | `Card` (+ `action={…}`) | a bare `<div class="card">` |
| «нет данных» / hint / error | `EmptyState` / `InfoNote` / `ErrorNotice` | ad-hoc paragraphs |
| Icon | `Icon name={IconName}` | emoji or unicode glyphs (`✔`, `→`, `✕`) |
| Page title / tabs | `PageHeader`; `PageTabs` (index-driven) or `ValueTabs` (route/state key) | raw `<h1>` / MUI `Tabs` |
| Section heading and content | `PageSection` | ad-hoc section heading and wrapper |
| Compact metric | `StatTile` | a custom metric card |
| Inline state or feedback | `InlineStatus` | status conveyed by colour alone |
| Prominent page state | `StatusHero` | a bespoke status banner |
| Apply lifecycle summary | `ApplyStatusRail` | a second apply-status reader or calculated history |
| Service heading and state | `ServiceStatusHeader` | separate, inconsistent service status chrome |
| Wizard step progress | `WizardProgress` | hand-built step indicators |
| Loading placeholder | `LoadingSkeleton` | fabricated data while loading |
| Optional expert controls | `ExpertDisclosure` | an inaccessible custom disclosure |
| Risk action confirmation | `ConfirmDialog` | new `window.confirm` calls |
| Form layout | `FormGrid` (`FormWide`, `FormActions`) | flex divs, per-field widths |
| Remove an item | `DeleteButton` | a red text button "Удалить" |
| Editor draft lifecycle | `useDraftEditor` + `EditorShell`/`EditorFooter` | another local `editing/saving/error` copy |

→ **Why:** the primitives already fix the recurring bug classes (label overlap,
non-native selects, uneven rows, unlabelled controls). A copy re-introduces them.
→ **Check:** `search_files` for `from "@mui/material"` in `src/pages/` — the only
allowed imports there are `Alert`, `Button`, `Checkbox`, `Dialog*`,
`FormControlLabel`, `Switch`, `Typography`. Anything else is a smell.

## 2. Forms and editors

- Put the form body in **`FormGrid`**; span with **`FormWide`**; group
  field-level buttons with **`FormActions`**. → Fields stop being ragged
  `inline-flex` rows of different widths.
- **`label` in cards, `ariaLabel` in table cells — never both.** A visible label
  that repeats the column header is duplication; a control with neither is
  inaccessible.
- Pass `required`, `autoComplete`, `inputProps`, `maxLength`, `readOnly` to
  `Field` instead of raw props. `readOnly` fields must omit `onChange` (the type
  enforces it); a non-read-only field must have one.
- Use `hint` for persistent guidance and `valid={false}` for an error state;
  **never** pass `error`/`helperText` to a `Field`. The helper line is reserved
  so rows keep equal height — do not remove that.
- Every editor ends in **`EditorFooter`** («Отмена / Сохранить» right-aligned).
- The **edit toggle lives at the top-right** (`.toolbar-actions`), never in the
  middle of a form.
- Keep the `useDraftEditor` contract (`empty`, `valid`, `commit`). Do not invent
  a second draft lifecycle per page.

## 3. Tables

- Read-only → `DataTable`. Editable → **the column header is the only visible
  label**; the per-control name goes to `aria-label`.
- Control fills its cell; widths come from the CSS floors
  (`.MuiTableCell-root .MuiFormControl-root`). **Do not set per-cell widths.**
- Leave `vertical-align: top` (theme) and the helper-line reserve alone — they
  are what keeps rows even.
- Remove with `DeleteButton` at the row end, with a **per-row** label
  (`Удалить правило ${r.name || \`#${r.index + 1}\`}`) — never a shared "Удалить".
- Adding columns is a redesign, not a tweak: check the widest case visually
  before committing (the delete column must never be pushed off-screen).

## 4. Actions and buttons

- **One action, one place.** Create/save → `EditorFooter`. Page-level →
  `Card action` or `.toolbar-actions`. Per-row → the row's own control.
- Text buttons for one-off actions; icon buttons (`DeleteButton`) for repeated
  row operations.
- Destructive and other risk actions need a confirmation and a surfaced error
  (`ErrorNotice`). New risk actions use the MUI `ConfirmDialog` primitive instead
  of `window.confirm`; existing calls may be migrated when those flows change.
- Never place two controls for the same logical action with different wording.

## 5. Accessibility

- Every control has an accessible name: `label` **or** `aria-label`.
  → **Check:** no `<Field>`/`<Select>`/`<SelectField>`/`<InterfaceSelect>` in
  `src/pages/` without one; they must all have `label=`, `ariaLabel=`, or be a
  numeric cell.
- Icon-only buttons carry `aria-label` **and** a `Tooltip` (`DeleteButton`).
- **Do not drop a visible label without adding `aria-label`** — the tests find
  fields by `getByLabelText`, which matches an accessible name either way, so a
  label → `aria-label` move stays green while a plain deletion breaks a11y.
- Use `readOnly` (not `disabled`) for values the operator must see but not edit —
  disabled fields drop out of the tab order and read as "unavailable".
- Keep MUI's keyboard/focus behaviour; do not add `tabIndex=-1` or remove focus
  outlines.
- `ExpertDisclosure` must open and close from the keyboard, expose its expanded
  state, and keep hidden controls out of the tab order.
- `PageHeader` owns the page's single `h1`; `PageSection` and other headings
  use lower levels in order.
- A countdown in `ApplyStatusRail` announces phase changes with `aria-live`,
  not every second of the countdown.

## 6. Styling and tokens

- **Colour comes from `theme.ts`** (published as `--vs-*` vars). `styles.css` is
  layout only. Never hardcode a hex in a page or component.
- No inline `style={{…}}` for colour or spacing — use the existing class or `sx`.
- Do not re-add the legacy CSS aliases (`--sidebar-bg`, `--workspace-bg`,
  `--card-border`, `--accent-blue`, `--status-*`) — they were removed on purpose.
- Titles match `PageHeader`; cards match `Card`; do not fork their class names.

## 7. State and data

- Server reads go through **TanStack Query** with a key from `src/query.ts`
  (`queryKeys.*`). Never hand-roll `fetch` + `useEffect` + local loading state.
- **Apply status is not a Query** — its RPC may perform an already-due rollback,
  so it is read imperatively via `useApplyStatus`. Do not "optimise" it into the
  cache.
- **Never fabricate data.** No demo fallback, no `LAB_MODE`, no plausible-looking
  sample rows presented as real. Empty state = prompt setup.
- Status must be honest: unknown or unread state is not healthy. Status
  primitives must show the supplied state without inferring success from missing
  data. `ApplyStatusRail` is prop-only: its caller supplies status and any time
  values; the rail never invents timestamps or fetches status itself.
- **No unauthenticated panel render.** Without a session the only reachable
  screen is `/login` (and `/onboarding` for first run); every panel route sits
  behind the `Protected` guard and redirects to `/login`. There is no read-only
  or demo shell for a visitor without a session — the shell must never mount
  before the session check resolves.
- Keep `schema.py`, `types.ts`, API payloads and migrations in sync when a field
  is added.

## 8. Tests and process

- All frontend tests stay green; you may adjust **positional/text selectors
  only** (label → `aria-label` moves are safe by construction).
- Do not regenerate `backend/tests/golden/` to silence a failure.
- Unit tests do not prove layout. For table/form changes, render the page
  (dev server + stub API) and look at it — the delete column, wrapping and row
  height are visual properties.
- When you add a primitive or a rule, update `docs/ui-refactor.md` and
  `ADR-0011` in the same change — plus `AGENTS.md` if the rule is load-bearing.
- Commit/push only when the task asks for it.

## Pre-flight checklist

- [ ] Gate green (`tsc --noUnusedLocals`, `vitest`, `build`, no 500 kB warning)
- [ ] Reused the library primitive for every control; no raw MUI inputs in pages
- [ ] `label` XOR `ariaLabel` on every control
- [ ] Removals are `DeleteButton` with a per-row label; edit toggle top-right
- [ ] Form body in `FormGrid`; editor ends in `EditorFooter`
- [ ] No hardcoded colour, no new CSS alias, no inline style for colour
- [ ] Server state via Query (`useApplyStatus` for apply status)
- [ ] Looked at the page, not just the test output
- [ ] Docs/ADR touched if you added a primitive or rule

## Symptoms you are off-design

- A field is wider/narrower than its neighbours or its label overlaps the value.
- The same word appears twice for one control (header + label).
- A red text "Удалить" button instead of the trash icon.
- An emoji or unicode glyph used as an icon.
- A hex colour or `style={{ color: … }}` in a page.
- A `useEffect` fetching something that `queryKeys` already covers.
- A control with no accessible name.
