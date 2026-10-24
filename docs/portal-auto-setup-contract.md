# Portal auto-setup: contract (shared interfaces)

All three slices (portal auto-install, TUI setup, Telegram bot) reference this doc.

## Portal DB schema (relevant

### `portal_settings` table (already deployed, alembic-portal migrations)

| key | value | notes |
| --- | --- | --- |
| `support_url` | Telegram link (`https://t.me/...`) | admin-editable |
| `bot_token` | Telegram Bot API token | new; for the bot |

Add migration `0002` to `backend/alembic-portal/` that inserts `bot_token` with a
comment explaining its purpose.

### Admin account

The portal uses the same `UserRow` model from `vs_router.db` for admin auth.
The portal's admin UI is reached through the panel web process (the same login
session). A first-time setup creates the first admin user via `/api/setup`
(the panel's own onboarding endpoint already exists in `auth.py`).

## Portal DB path (runtime)

`/var/lib/vs-router/portal/vs-portal.db` (env `VS_PORTAL_DATABASE_URL` in
`vs-router-portal.service` and `vs-router-web.service`).

## Files each slice owns

| Slice | Owns (may create/modify) | Must NOT touch |
| --- | --- | --- |
| A — auto-install | `backend/packaging/install.sh`, `backend/alembic-portal/0002_bot_token.py` | `console_menu.py`, any bot code |
| B — TUI setup | `backend/src/vs_router/agent/console_menu.py`, `backend/src/vs_router/agent/setup_wizard.py` (new) | `install.sh`, bot code |
| C — Telegram bot | `backend/src/vs_router/telegram_bot/` (new), `backend/packaging/vs-router-telegram.service` (new), `backend/packaging/install.sh` (append only) | `console_menu.py`, setup wizard |

## Verification gate

```bash
cd /home/poshl9k/GitHub/software-routing-software/backend
env -u PYTHONPATH /home/poshl9k/.hermes/bin/uv run --no-sync pytest -q
```