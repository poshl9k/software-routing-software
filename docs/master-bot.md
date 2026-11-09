# Master Telegram bot

The **master** uses its own bot and database. The node's local portal bot remains a separate service and must not share this bot token. Installation enables `vs-master-bot.service`; without settings it idles and does not poll Telegram.

`install-master.sh` uses a root-owned `/opt/vs-master/venv` and a separate `/etc/vs-router/master.env`; it does not reinstall the panel's Python package or modify/reload Caddy. On an existing master DB it requires the original key and creates a checked pre-migration SQLite backup. Review the existing Caddy configuration and adapt `caddy-master.example` (including the actual hostnames/IP) before publishing; the installed app is initially reachable only on `127.0.0.1:8440`.

Configure via an authenticated administrator request to `PUT /api/master-admin/settings/telegram` with `bot_token` and an HTTPS `public_url` (origin only). The token is encrypted in `master_settings`, never returned by `GET /api/master-admin/settings/telegram`. Use a private, secure channel to enter it; do not put it in shell history, issue reports, or chat. Restarting the service is not required: it reloads settings before polling. The installation key in `/etc/vs-router/master.env` must remain available for decryption and backups.

A private `/start` message from the Telegram user creates an account idempotently, **without a subscription**. The subscriber cannot create devices until an administrator grants an active subscription. `/start` and `/menu` show a persistent chat-level Telegram reply keyboard (Подписка, Личный кабинет, Устройства); tapping a label sends ordinary text that is checked against the private sender before invoking the existing action. Older inline **Меню** buttons open that chat keyboard with a new message. Device-specific actions, deletion confirmation and the cabinet URL remain inline on their own messages. Telegram clients may still hide a persistent keyboard manually. The bot's cabinet button issues a 10-minute single-use proof. Its raw token travels in the HTTPS link's URL fragment; the browser removes the fragment before submitting the proof to `POST /api/portal/login/magic`. The `frontend-master` cabinet shows subscription/device state and allows creation and configuration download only under an active subscription. This is tested with a simulated API, not a real Telegram/browser/node round trip.

**Stars charging is disabled.** There is no `sendInvoice` path. Every pre-checkout query is rejected; an unexpected successful-payment update is retained once in `master_payment_receipts` for manual review and never grants a subscription. Do not enter a live price or issue a live invoice until the tariff, integer XTR amount, term, device limit, refund/fulfilment policy, and an end-to-end sandbox provisioning test are approved.

## Device management (offline-tested candidate)

This slice extends the original ADR-0035 MVP bot non-goal with subscriber device
operations; it does **not** change the master/node ownership or bridge contract.
There is no local-portal HTTP login/session in the bot. `device_service.py` is the
shared domain used by the HTTP portal and bot; exports use the same guarded
renderer. Master `Device`/`DeviceOp` rows remain authoritative, and only the
existing worker/`BridgeClient` talks to the assigned node's internal bridge.

Open **Устройства** from `/menu` to see the chat-level submenu **Список устройств**,
**Добавить устройство**, **Главное меню**. The add button asks for a device name
using Telegram's reply interface: reply to that exact prompt within two minutes
(1–128 characters). Unrelated chat messages never create a device. Navigation,
expiry or a bot restart cancels the prompt; entitlement and the verified link are
rechecked when submitting the name. The existing `/new Имя` command remains an
alternative. A successful submission may initiate a real node apply, so opening
the submenu or prompt alone must not create anything. Device-specific controls
stay inline on list messages. The commands below also work in the master's
private bot chat (numeric IDs come from `/devices`):

| Command | Result |
| --- | --- |
| `/devices` | Own devices, master status, pending operation, applied flag and last-handshake timestamp from bridge state; five devices per page with navigation/actions |
| `/new Телефон` | Create with a 1–128-character label; existing tariff limit and automatic node selection apply |
| `/activate 12`, `/deactivate 12` | Enable/disable an owned device; preserve its identity and keys |
| `/delete 12` | Ask for explicit **Удалить навсегда** / **Отмена**, never delete on the initial command/button |
| `/conf 12` | Upload the wg-quick `.conf` using `sendDocument` |
| `/qr 12` | Upload the same configuration as a PNG using `sendPhoto` |
| `/amnezia 12` | For supported AWG state, upload an Amnezia `vpn://` URI in `device-12-amnezia.txt`; ordinary WG is rejected |

Every device entry point, including list, callbacks and deletion confirmation,
requires a positive private chat ID equal to the sender ID, an active master
account with **both** its Telegram identity and separately verified `/start` link
matching that chat, and the latest subscription with active status, future expiry
and an existing tariff. Group/mismatched senders cannot invoke operations.
An administrator-entered numeric Telegram ID without private `/start` is not a
verified link. Device lookup is restricted to that account; a forged foreign ID
never reaches the bridge or export renderer. The subscription status/menu and
cabinet-login flow remain available separately, without granting device access.

Deletion confirmations are random single-use proofs, bound to the chat, account,
exact verified-link timestamp and device ID. They expire after two minutes;
cancel, a replacement prompt, consumption or bot restart invalidates them. Only
one pending proof per chat is retained, with an overall bound of 1,000 unexpired
chats. Ownership/subscription/pending-operation checks run again on confirmation.
A repeated or forged callback cannot enqueue another deletion.

Mutation acceptance and a non-secret Telegram-update receipt are committed in
one master DB writer transaction. `master_settings` keys in the `tgdev:` namespace
contain only a hash of bot identity/chat/update ID and a `DeviceOp` ID; no token,
configuration or private key is stored there. Redelivery after a lost Telegram
reply, process restart or token rotation of the **same bot** cannot enqueue a
second operation: create/toggle receipts return the existing operation; an
already consumed deletion proof is rejected. Receipts currently have no
retention/purge policy: deleting them manually removes this replay protection.
A second, intentionally sent `/new` command is a new operation and still counts
against the tariff. Pending bridge operations remain in the existing durable
queue; bot replies distinguish queued from applied, and never claim successful
provisioning merely because Telegram accepted a reply.

Exports contain private keys and are a deliberate disclosure **to Telegram and
the verified subscriber**, not an end-to-end encrypted channel. They are sent
as in-memory multipart uploads with `protect_content=true`, with no secret in
ordinary messages, captions, callback data, audit details, URLs or temporary
files. Amnezia URIs are files, not clickable message links. Immediately before
upload, the bot rereads the exact account/link, live subscription and device
ownership after bridge I/O. It validates the Telegram response's message ID and
private recipient. A Telegram failure has no secret-text fallback and no device
mutation rollback; ambiguous upload success may cause a duplicate attachment on
retry. Protection against forwarding is not protection against screenshots,
downloads or Telegram's access. Prefer the HTTPS cabinet if that disclosure is
unacceptable. Changes after an authorized request/send is already in flight
cannot retract an accepted operation or attachment.

The bot runs synchronous DB/crypto/bridge work via `asyncio.to_thread`, with one
bounded I/O slot per bot instance; Telegram I/O remains asynchronous and no DB
writer lock spans it. One authorized polling consumer per bot token is still
required. A missing/down bridge fails closed for lists/exports; a queued mutation
must be checked with `/devices` after recovery. Large or unsupported QR/AWG
exports may be rejected; use `.conf` or the cabinet rather than a text fallback.
No new migration, service setting, Stars path or proactive-notification behavior
is introduced by device management.

Regression tests in `backend/tests/test_master_bot_devices.py` use a disposable
file-backed SQLite database, synthetic `httpx.MockTransport` Telegram multipart
requests, and an injected node bridge. They cover own list/create/toggles,
subscription/link/ownership denials, limit, confirmation expiry/cancel/replay,
restart/token-rotation receipts, pending operations, guarded exports,
post-bridge revocation, Telegram failures/invalid ACKs, and bounded off-loop I/O.
Observed TDD: initial **62 failed / 4 passed**, then **66 passed**; two additional
failing regressions for queued-time entitlement and token rotation were fixed.
Final focused candidate checks: **75 passed**. Broader `test_master*.py` run on
Windows: **219 passed, 1 deselected**, with an import-only `pwd` shim; the deselected
boot-restore test requires Unix `grp`/`os.chown`. These are offline source/API/DB
checks, not Linux host, real Telegram/client import, deployment or live-node
acceptance. Existing FastAPI/Python deprecation and Pydantic warnings remain.

## Subscription notifications (Stage-2 candidate)

Migration `0004_master` adds a transactional outbox (`master_subscription_notifications`), a subscription notification revision, and a verified private-chat link. Existing numeric Telegram IDs are **not** backfilled as links: each active subscriber must send a private `/start` to this master bot. Group chats and mismatched senders cannot link; disabled accounts cannot link or receive subscription details/magic links. The verified recipient is stored separately from the account identity, so changing an identity cannot silently transfer the link.

The real administrator `PUT /api/master-admin/subscribers/{id}/subscription` queues an activation/assignment notice in the **same transaction** as a changed, future-dated grant. An identical absolute-expiry PUT does not queue another event; `days` remains the existing additive renewal operation, so repeating it grants another extension and produces a new revision. The master worker queues expiry only on the `active` → `expired` transition, even when there are no devices or the nodes are unavailable. Notices describe the master entitlement, **not** confirmed node provisioning. No historical assignment backfill or advance-expiry reminders are included.

**Proactive delivery is off by default**, independently of the existing configured interactive bot. The runner drains at most 20 due events before each long poll only when started with `VS_MASTER_TELEGRAM_NOTIFICATIONS=1`; token and public HTTPS URL must also be configured as above. Do not enable this against a real bot until separately authorized. These changes neither configure a token nor change installation/service files. The billing prohibition above is unchanged.

Each send has a committed 60-second claim lease; no SQLite transaction/writer lock is held across the Telegram request. Failed attempts remain durable and retry after 30 seconds, doubling to a one-hour cap; bot restart does not reset the attempt/lease schedule. An abandoned lease becomes eligible again. Delivery is recorded only after a successful `sendMessage` response containing a private-chat message ID for the expected recipient. Immediately before attempting delivery the claim transaction rechecks active account, exact verified link/recipient, subscription revision and current expiry. Obsolete or unauthorized events are terminally suppressed (not delivered), rather than sending stale activation/expiry information. A change made after a send is already in flight cannot retract that message.

Delivery is **at least once, not exactly once**: if Telegram accepted the message but its response was lost, the process crashed before the local acknowledgement, or a lease expired during an ambiguous request, retry may send a duplicate. The Bot API request has no application-supplied idempotency key in this implementation. Local claim fencing prevents concurrent normal attempts and stale local acknowledgements; it cannot undo an already accepted Telegram send. Run one authorized polling consumer per token; the lease is not permission to start competing long pollers. There is no automatic outbox retention/purge policy in this slice.

Upgrade only the master DB using the usual `alembic-master` migration workflow before starting the updated worker/bot. Downgrade refuses once verified links, revised grants, or any outbox rows exist: stop the processes and use a reviewed backup/restore procedure instead of dropping delivery history or pending retries. The new migration was exercised against a disposable file-backed SQLite DB with prior `0003_master` rows, WAL, uniqueness/check/foreign-key rejects and metadata comparison. Tests use synthetic Telegram transport only; Windows runs use an import-only `pwd` shim and do not validate Linux host behavior.

Checks: backend/API/SQLite tests, browser UI tests with simulated responses, and native systemd unit parse on a disposable VPS staging path. On November 9, 2026, master release `57818dbf459de080610582ebf47dae758a161e14` was installed on test VPS `85.209.159.130` after an integrity-checked database/UI rollback backup. The installed wheel matched the release, master web/worker/bot and backup timer were active, the loopback/public health checks passed, and the anonymous browser reached the Telegram-login screen. Proactive notifications and Stars invoices remained off; the Caddy configuration checksum was unchanged. Linux master tests against that commit: 220 passed. **Real Telegram device commands, authenticated cabinet access and live master→node provisioning were not exercised**; the five existing service peers on rg3 were not changed by the master installation.
