# Repository guide

## Sources and implementation status

- `README.md`: project overview. `CONTEXT.md`: authoritative domain semantics.
  `docs/adr/`: accepted design decisions; these and CONTEXT take precedence over
  `router_project_plan.md`, which tracks work rather than defining semantics.
- Read ADRs by full filename: two files have number `0001` (Debian/userspace AWG,
  and removal of demo data/LAB_MODE). ADRs `0002`–`0005` cover first LAN access,
  first-apply safety, interface-scoped SSH, and verified installer releases.
- Accepted does **not** mean implemented. The plan's final installation-audit
  section explicitly lists pending safeguards. Current preseed still includes
  a known unattended password and NOPASSWD; bootstrap still uses floating source
  downloads. Do not describe the new LAN/SSH/release guarantees as shipped.
- Verify behavior in source and tests. Backend/frontend READMEs contain historical
  statements: apply is no longer a 501 stub, the agent exists, static UI serving
  exists, and production demo fallback has been removed. Test counts and old
  “MVP ready” claims are not current verification.
- Operational references: `docs/install.md`, `installer/README.md`,
  `docs/admin.md`, `docs/tunnel-proxy-apply.md`. `docs/lab-01` through `lab-04`
  reports record specific past VM checks, not blanket current guarantees.

## Project map

- `backend/src/vs_router/`: Python 3.11+ FastAPI application (`app.py`), Pydantic
  contract (`schema.py`), domain validation (`validators.py`), SQLAlchemy/SQLite
  snapshots (`db.py`), secret handling (`secrets.py`), HTTP routes (`api/`).
- `backend/src/vs_router/generators/`: deterministic configuration generation for
  networkd, nftables, Kea, Unbound, WG/AWG and Caddy; bundle serialization.
- `backend/src/vs_router/agent/`: whitelisted Unix-socket RPC, apply/confirm/
  rollback, service adapters, boot restoration, tunnel startup and DDNS.
- `backend/alembic/`: database migrations; `backend/tests/`: unit/API/agent tests
  and `golden/` generated-output fixtures. Dependencies: `pyproject.toml`, `uv.lock`.
- `frontend/src/`: React 19, TypeScript, MUI; `pages/`, shared `editor.tsx`/`ui.tsx`,
  `api.ts`, `types.ts`, `state.tsx`, theme/styles and Vitest tests under `test/`.
  Vite configuration and scripts live in `frontend/`; lockfile is committed.
- `backend/packaging/`: privileged install/bootstrap/update scripts and systemd
  units. `installer/`: Debian preseed and ISO builder. These change real systems.
- `mockups/`: static visual references, not runtime data or a shipped demo mode.

## Development and checks

Run from the indicated directory with dependencies already available. Dependency
setup, when authorized: `cd backend && uv sync --locked`; `cd frontend && npm ci`.
Frontend documentation specifies Node 22.12+.

| Directory | Command | Purpose |
| --- | --- | --- |
| `backend/` | `uv run --no-sync pytest -q` | Backend tests without dependency sync |
| `backend/` | `uv run --no-sync pytest -q tests/test_generators.py` | Focused generator tests |
| `backend/` | `uv run --no-sync alembic upgrade head` | Migrate the selected development DB |
| `backend/` | `uv run --no-sync uvicorn vs_router.app:app --host 127.0.0.1` | Local API |
| `frontend/` | `npm run dev` | Vite development server |
| `frontend/` | `npm test` | Vitest run |
| `frontend/` | `npm run typecheck` | TypeScript check |
| `frontend/` | `npm run build` | TypeScript build and Vite output in `dist/` |

Use a disposable development database (`VS_ROUTER_DATABASE_URL`; default is
`sqlite:///vs-router.db`). App startup does not create tables. Vite proxies `/api`
to port 8000 while preserving Host/Origin. Secure cookies require a suitable
HTTPS development setup; do not disable cookie security to make login work.

Unit/golden tests do not prove host networking works. Native checks (`nft -c -f`,
`unbound-checkconf`, `kea-dhcp4 -t`, `caddy validate`) and apply/reboot/rollback
scenarios belong on an explicitly authorized disposable Debian 13 VM. Do not run
packaging scripts, ISO installs or live network/service changes as routine tests.

## Safety invariants and work rules

- Keep the web process unprivileged. System changes go through the agent's typed
  RPC whitelist and peer-UID checks; never add arbitrary shell execution.
- Preserve whole-configuration snapshots, one draft and one active apply cycle.
  Safe mode uses a host-owned deadline/marker, probe and rollback to confirmed
  state; reboot must not confirm a pending version. Safe mode currently rejects
  first apply without a confirmed baseline; non-safe apply confirms immediately.
- Preserve fail-closed unassigned interfaces, default deny and first-match rule
  order. Keep AllowedIPs distinct from routes and tunnel roles immutable.
- Maintain Secure/HttpOnly/SameSite cookies, origin checks, admin authorization,
  login rate limiting, encrypted stored secrets and redacted API responses.
  Secret-bearing generated bundles must not appear in previews or logs.
- Treat explicit LAN assignment, retained management HTTPS, guarded first apply,
  SSH opt-in by interface and verified release pinning as required design targets
  under ADRs 0002–0005; consult the audit before changing those paths.
- Keep generators deterministic and free of I/O. Review golden changes against
  intended semantics; do not regenerate fixtures just to silence failures.
- Keep Python schemas, frontend types, API payloads and migrations aligned.
  Use shared UI components/helpers, visible `ErrorNotice` errors and handled
  async failures; existing native MUI selects use `SelectProps={{ native: true }}`.
  UI is currently Russian; i18n remains a documented design/implementation gap.
  Before any frontend change read `docs/ui-rules.md` — the canonical UI rule set
  (one primitive per job, one place per action, `label` XOR `aria-label`, tokens
  from `theme.ts`, and a pre-flight checklist). For any UI work, always load and
  apply the `all-design-stack` skill first.
- Never restore fabricated production fallback data, LAB_MODE or insecure cookie
  toggles. Empty configuration must prompt setup; sample fixtures are test-only.
  An unauthenticated visitor reaches only `/login` (`/onboarding` for first run):
  no read-only or demo panel shell is rendered without a session.
- Inspect `git status` before edits; preserve unrelated changes, including the
  existing CONTEXT/plan and ADR 0002–0005 work. Avoid incidental lockfile churn.
  Report actual checks and limitations, distinguishing source review, unit tests
  and live VM evidence. Do not install, deploy, commit or push without task scope
  authorizing it.
