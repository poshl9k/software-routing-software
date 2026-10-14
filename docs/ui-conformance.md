# UI conformance: Keenetic UX/UI rules across the whole panel

Standing work list for bringing **every** surface — existing and future — under the rule set in
`docs/ui-rules.md` §9 (Keenetic-derived) plus `docs/ui-refs/keenetic/00-KEENETIC-UX-LOGIC.md`.
Rules live in `ui-rules.md`; this file is the checklist of what still violates them and how to
check for the violation mechanically.

## How to audit any page (mechanical, before reading code)

```sh
cd frontend/src
# 1. a tab strip whose tabs edit ONE object (fields), not different lists/modes
grep -rn '<PageTabs\|<ValueTabs' pages/*.tsx
# 2. editors rendered in the page flow instead of a window
grep -rn 'selected && <Card\|editing.map(\|<Card title="Нов' pages/*.tsx
# 3. forbidden MUI imports in a page (bypasses the primitives)
python3 - <<'PY'
import re, glob
allowed={'Alert','Button','Checkbox','Dialog','DialogActions','DialogContent','DialogTitle','FormControlLabel','Switch','Typography'}
for f in sorted(glob.glob('pages/*.tsx')):
    s=open(f,encoding='utf-8').read()
    names=[n.strip() for m in re.finditer(r'import\s*\{([^}]*)\}\s*from\s*"@mui/material"',s,re.S) for n in m.group(1).split(',') if n.strip()]
    bad=[n for n in names if n not in allowed]
    if bad: print(f, 'EXTRA:', ', '.join(bad))
PY
# 4. the same value in two controls (editable + read-only twin)
grep -rn 'readOnly' pages/*.tsx | head
```

A page passes when: no item editor in the page flow, no one-object tab strip, one control per
value, add-actions do not scale with the list, every list has a concrete empty state, and status
is text + indicator (admin state vs link state, unknown as its own state).

## Work list

- [x] `/firewall` — rules list: explicit columns, default-deny row, empty state, row delete
      (`docs/ui-refactor.md`, step 1) — but the **rule composer is still an inline `Card`** → see below
- [x] `/` overview — services table, concrete empty states, one journal message
- [x] `/dhcp` — lease state in one place, `fmtRemaining`, visible applied filter
- [x] `/dns` — DNS type visible (UDP/DoT/DoH), query-log message in its own card
- [x] `/tunnels` — `kv` facts, «нет пиров», peers empty state
- [x] `/routing` — concrete empty states on six tables
- [x] `/proxy` — sites/DDNS empty states, certificate caveat
- [x] `/diagnostics` — migrated onto the primitives (import audit clean)
- [x] terminology — the tunnel entry follows the `CONTEXT.md` glossary («Пир»)
- [x] console menu — ASCII-English copy (the physical console has no Cyrillic font)
- [x] **(A)** `/network` interface editor → modal window with grouped sections
      (`Идентификация / Роль / Адресация / Тип и подключение / Дополнительно` + `ExpertDisclosure`);
      the duplicate read-only «Описание» twin is gone; the per-NIC `+ VLAN на …` buttons collapsed
      into one `+ Виртуальный интерфейс` dialog. Verified by screenshot: window over the list,
      `EditorFooter` inside it
- [x] **(B)** tunnel editor → modal window, one form (`Идентификация / Подключение / Ключи /
      Пиры / Дополнительно`); peers stay a list inside the form, QR/PSK unchanged. 224 lines of
      tab plumbing deleted. Verified by screenshot
- [x] **(C)** sites/DDNS editors → separate windows (`Collection`); sites get
      `Идентификация / Подключение / Сертификат`, DDNS gets `Идентификация / Подключение /
      Секрет`. Tunnel branch re-checked by screenshot after the shared-path edit — still a window
- [x] **(D)** firewall rule composer → window (`Правило: <имя>` with `Идентификация / Условие /
      Решение`). Verification caught a **duplicate delete**: the dialog carried its own
      `Удалить правило …` while the row already has one → removed from the dialog (§4: one place
      per action). Row delete kept, `editors.test.tsx` (which targets the table) still green
- [x] **(E)** DHCP/DNS editors → windows (`Устройство: printer` with `Идентификация / Адрес`;
      subnets list window `Подсети DHCP` with row `Изменить` → nested subnet window).
      Entry from `/dhcp` is the row action, not a form in the flow
- [x] **(F)** routing editors → windows: `Новый набор` (`Идентификация / Содержимое`),
      `DNS-сервер`/`DNS-правило` (one dialog, title picks the kind) and the guided rule wizard
      (`Новое правило`, «Шаг 1 из 3: условия» inside the dialog). F wrote no report — verified
      from the tree, my own gate and screenshots
- [x] **(H)** TProxy bypass («Исключения») → window `Исключение: <имя>` with
      `Идентификация` / `Условие`; the section behind it is now a plain list (`<имя>` + `Изменить`)
      with `EmptyState «Исключений нет.»` and no stray delete icon
- [x] **(G)** `RoutingProxy.tsx`: all three inline editors are windows — `Прокси-выход: <тег>`
      (`Идентификация / Подключение / Правила`, `id="outbound-editor-<i>"` preserved),
      `Подписка`, `Группа выходов`; no `rule-row` editors left in either file
- [x] `ProxiesView` no longer repeats a card-level «Изменить» on every row: the Действия cell is
      «—» and the section is entered from the toolbar «Редактировать» above it (§4: one place per
      action, and the label no longer pretends to act on a row)
- [x] fixtures are contract-valid now: `wg-office` → `wg_office` (tunnel `Name` forbids hyphens;
      `interface: "wg-office"` stays, `InterfaceName` allows them) and the peer
      `alina-laptop` → `alina_laptop`; the QR assertion in `maintenance-features.test.tsx` follows.
      Renaming beat relaxing the backend rule because `Name` is the schema contract
- [x] **apply button moved to the top, and it applies** — «Применить v<id>» + «Проверить изменения»
      now sit in a right-aligned sticky bar (`styles.css .page-actions`) under the top panel instead
      of the bottom of the menu, and the primary button applies the draft directly (with a
      `ConfirmDialog` naming the risk: no stable version / safe-mode countdown / safe mode off).
      `ApplyStatusRail` takes `action={null}` for «report nothing» v. `undefined` for «render the
      fallback», so the sidebar keeps the honest status text and no button
- [x] **gate hygiene — `screens.test.tsx` flake fixed at the root.** Cause was not a test race: a
      `200` diff response without `summary`/`changes` (a bare `{}`) made `DiffReview` throw
      `Cannot read properties of undefined`, and the unhandled error unmounted the screen of
      whichever test was running — hence «a different test each time». `DiffReview` now treats the
      payload as untrusted (unreadable → honest warning, missing `consequences` → empty), with two
      regression tests. 8 consecutive file runs and 2 full runs green after the fix, where the same
      file failed ~1 run in 3 before. The `afterEach`/`clearMocks`/fake-timer suspects were checked
      and ruled out earlier — do not re-check them
- [x] peer/tunnel name fields now carry a hint (`Латиница, цифры, «_»; до 31 символа`) instead of
      a bare «Некорректное значение». The strict rule is correct — the backend contract is
      `Name = ^[a-zA-Z][a-zA-Z0-9_]{0,30}$` (`schema.py:7`, used by `class Peer`), and
      `Firewall.tsx` / `RoutingProxy.tsx` already had such hints
- [ ] remaining decision: `frontend/src/fixtures.ts:56` ships a peer named `alina-laptop`, which
      that contract rejects (as does the QR test that mirrors it). Either rename the fixture
      (and the one assertion in `maintenance-features.test.tsx`) or relax the peer-name rule
      server-side — a product call, not a UI one
- [ ] page-level settings stay on the page and are **not** converted: `SSH.tsx` (access
      settings), `Maintenance.tsx` (backup, ping, release), `Diagnostics.tsx` (tabs = different
      lists), `Onboarding.tsx` (first-run wizard), `ApplyScreen.tsx`

## Rules of engagement for these slices

- Structure only: no change to validators, save mappers, API calls or the schema. A slice that
  needs a behaviour change stops and asks.
- Every slice: the frontend gate run by hand on the frozen tree (not the subagent's word),
  plus rendered screenshots of the list and of the open window (`vs-router-dev/references/
  frontend-visual-qa.md`).
- Deploy to the lab VM only after the gate is green on the frozen tree; the console/menu copy is
  ASCII-only by rule.
