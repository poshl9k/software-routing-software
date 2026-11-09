# Master Telegram bot

The **master** uses its own bot and database. The node's local portal bot remains a separate service and must not share this bot token. Installation enables `vs-master-bot.service`; without settings it idles and does not poll Telegram.

`install-master.sh` uses a root-owned `/opt/vs-master/venv` and a separate `/etc/vs-router/master.env`; it does not reinstall the panel's Python package or modify/reload Caddy. On an existing master DB it requires the original key and creates a checked pre-migration SQLite backup. Review the existing Caddy configuration and adapt `caddy-master.example` (including the actual hostnames/IP) before publishing; the installed app is initially reachable only on `127.0.0.1:8440`.

Configure via an authenticated administrator request to `PUT /api/master-admin/settings/telegram` with `bot_token` and an HTTPS `public_url` (origin only). The token is encrypted in `master_settings`, never returned by `GET /api/master-admin/settings/telegram`. Use a private, secure channel to enter it; do not put it in shell history, issue reports, or chat. Restarting the service is not required: it reloads settings before polling. The installation key in `/etc/vs-router/master.env` must remain available for decryption and backups.

A private `/start` message from the Telegram user creates an account idempotently, **without a subscription**. The subscriber cannot create devices until an administrator grants an active subscription. `/start` and `/menu` show a persistent chat-level Telegram reply keyboard (Подписка, Личный кабинет, Устройства); tapping a label sends ordinary text that is checked against the private sender before invoking the existing action. Older inline **Меню** buttons open that chat keyboard with a new message. Device-specific actions, deletion confirmation and the cabinet URL remain inline on their own messages. Telegram clients may still hide a persistent keyboard manually. The bot's cabinet button issues a 10-minute single-use proof. Its raw token travels in the HTTPS link's URL fragment; the browser removes the fragment before submitting the proof to `POST /api/portal/login/magic`. The `frontend-master` cabinet shows subscription/device state and allows creation and configuration download only under an active subscription. This is tested with a simulated API, not a real Telegram/browser/node round trip.

**General Stars billing is disabled.** The default still rejects every pre-checkout query and retains unexpected successful payments once in `master_payment_receipts`, without granting access. An offline-tested, explicitly gated **single real-price test purchase** is described below; this is not a billing launch or tariff selector.

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

## One-off Stars test purchase (offline-tested candidate)

Migration `0005_master` must be applied to the **master** database before running
this candidate bot/worker. Neither the migration nor this change enables payment.
No installer/service setting is changed. Normal subscriptions and registration
remain administrator-controlled.

This is an ordinary-production **real charge**, not a Telegram sandbox. Only when
both `VS_MASTER_STARS_TEST_ENABLED=1` and
`VS_MASTER_STARS_TEST_ACCOUNT_ID=<one canonical positive master Account ID>` are
set can that account's verified private sender request `/buy`. Missing, malformed,
list-valued or whitespace-padded account configuration fails closed. The account
must be active and have an active, future-dated **Super tariff ID 3, limit 50**.
The fixed one-time price is **1 XTR for +30 days**, preserving that tariff and
extending from `max(current time, current subscription expiry)`; no Base switch,
`provider_token`, `subscription_period`, automatic renewal or general sale is
included. Node readiness is checked from the existing master cache and decryptable
stored material, not by a live bridge call during checkout; pending device
operations block checkout. A node can still fail after that local check.
The invoice refers to `/terms` (one-off price, duration, no recurring payment,
possible delayed node reconciliation) and `/paysupport`. Both commands are
available in a private chat even without a linked account; the approved pilot's
payment/refund contact is `@poshl9k`. The operator handles disputes manually;
the bot does not promise an automatic refund and explains that Telegram support
does not resolve merchant payment disputes. Paying the invoice indicates
acceptance of the `/terms` terms; this test is limited to the explicitly
consenting allowlisted buyer.

A unique database-wide first slot permits one invoice attempt, not one per
update/process/account setting. Migration `0006_master` adds **one fixed retry
slot** without deleting or rewriting the first order. It can be used only after
the first invoice's ten-minute deadline, with a valid private ACK and no
approved checkout, payment receipt/event, account relink, subscription change
or pending device operation. An ambiguous send/ACK or checkout approval forbids
the retry; a second retry is never available. A late checkout on the expired
first invoice is rejected. The transaction records account, verified-link
timestamp, stable bot identity, exact subscription/tariff, price/term/limit, prior
expiry and a hashed opaque payload before Telegram I/O. The raw payload is never
stored/logged. The order is `sending` until a valid private-message ACK, then
`sent`. Send failure, lost ACK, crash or invoice expiry does **not** release the
slot or resend an invoice; operator reconciliation is required. Do not delete
orders or reset a slot to retry: an earlier invoice may still exist remotely.

Pre-checkout rechecks the exact order, sender, link, live subscription, tariff,
price, currency, ten-minute deadline and local fulfillment readiness. It persists
one approved checkout identity; a different checkout is rejected. Queue/DB work
has a two-second budget and answering has a three-second budget, below Telegram's
ten-second deadline. Saturated I/O rejects, rather than waiting behind a slow
bridge; a cancelled waiter retains its capacity until its DB thread finishes.
No database writer lock spans a Telegram request. A send/answer transport failure
is ambiguous and is not proof of a remote rejection. The bot retries the same
pre-checkout only within the provider's ten-second deadline; after that it
advances past the stale query so a subsequent successful-payment update cannot
be blocked by an unanswerable old query. An HTTP 400 for an already rejected
answer likewise cannot be treated as a new approval.

Successful payment commits the unique Telegram charge receipt, immutable event
observation, one master renewal, increased notification revision, fresh active
notification and one durable reconciliation ticket per device node **atomically**.
Previously queued obsolete notices are suppressed at claim time. Proactive notice
delivery remains controlled by its separate disabled-by-default flag. An approval
already committed while opted in remains fulfillable after restart, flag removal
or delayed payment delivery; removing the flag stops new invoices/checkouts, not
an already approved captured payment. Delayed fulfillment preserves a newer admin
extension and starts from now if the old grant has elapsed. Account disable,
relink, changed subscription/tariff, shortened grant, altered amount/payer/currency,
recurring payment or a second charge goes to review without a grant. An unapproved
or conflicting matched order is frozen in `review`, not reopened on replay.
Unknown charges remain unmatched without access: their receipt and unmatched
event are committed before the offset advances, and a warning signals manual
review. Malformed/conflicting updates never advance the poll offset; review
evidence is retained once. This intentionally halts subsequent polling progress
until a reviewed operator recovery. There is no automatic refund, charge dispute
handling, replay/offset repair UI, history purge
or test-slot reset endpoint; the operator must reconcile/refund through a separately
approved procedure. Do not treat this as a public paid service launch.

The worker's existing active-subscription pass does **not** infer an extension for
already-active devices. Therefore payment creates `DeviceOp(op='expire')` tickets,
linked by `master_stars_fulfillments`; the worker chooses `renew` while the grant
is active. It sends only this account's retained device mappings and preserves
identities/keys and user-disabled states. Missing/failed/pending/malformed node
ACKs leave the ticket and order fulfillment `pending` for restart-safe retry.
Only all acknowledged `renewed` tickets mark fulfillment `applied`; expiry or hard
failure before renewal completion requires `review`. A master ledger grant is not
proof of live service activation. After any future authorized real capture, verify
the charge, order/ledger, exact subscription, outbox revision, all node tickets and
actual existing peers separately before claiming end-to-end success.

The new tables are `master_stars_orders`, `master_stars_payment_events`, and
`master_stars_fulfillments`. Downgrade `0006_master` → `0005_master` refuses if
the retry order exists; downgrade `0005_master` → `0004_master` refuses any Stars
history. Stop processes and use a reviewed backup rather than dropping payment
evidence. Empty migration rollback preserves old unmatched receipts. Tests cover disposable
file-backed SQLite/WAL, prior-data upgrades and metadata/constraint parity, mocked
Telegram exact XTR invoice payloads, concurrent/restarted/reordered receipts,
rollback on ticket persistence failure and actual worker replay against fake
bridges (including both existing devices and multiple nodes). These prove local
DB/bot/worker behavior only, not Telegram capture, Linux host apply, production
refunds or live node activation. No live invoice was sent by these checks.

### Operator reconciliation (read-only)

`GET /api/master-admin/payments/reconciliation` requires an administrator session.
It returns ledger-wide **row counts**, not a deduplicated number of incidents
(orders, receipts, granted/review/unmatched events, receipts without an event,
pending renewals and review orders), plus order snapshots
in descending ID order with `limit` (1–100, default 50), optional `before_id` and
`next_before_id`. Each order includes a non-secret account ID, fixed price,
timestamps, grant/fulfillment states and per-node ticket status. A `sending`
invoice older than five minutes is flagged `invoice.ack_unknown`; a paid renewal
still pending after five minutes is `renewal.overdue`; review state is
`payment.review`. An expired unpaid `sent` order is history, not proof of a charge.
Amounts are integer XTR units, not the tariff's display price. The response omits
charge IDs, Telegram chat IDs, payload hashes, tokens and arbitrary node error
details; only the verified `renewed` ticket detail is exposed. All counts are
from one SQLite read snapshot, including when the list is paginated. The endpoint
does not refund, replay a provider update, retry a failed operation, contact a
node or change an entitlement. A flagged case requires an operator to inspect
the protected ledger and reconcile it before taking a separately approved action.

After the one-charge test, a copy of the paid master SQLite backup was restored
into an isolated root-only directory and checked for revision `0006_master`,
SQLite integrity and foreign keys, one receipt/granted event, the paid order,
matching subscription expiry and an acknowledged renewal ticket. This was an
offline recovery drill, **not** an overwrite of the live database. Never restore
a pre-payment backup on top of a paid ledger: it loses the durable receipt and
can grant or charge inconsistently. The master key must also be preserved
separately for an actual recovery.

Reproduce the platform-independent focused checks from `backend/` (use a fresh
scratch path for `--basetemp` on Windows):

```bash
uv run --no-sync pytest -q tests/test_master_stars*.py tests/test_master_migrations.py tests/test_master_magic.py tests/test_master_bot_devices.py
```

## Subscription notifications (Stage-2 candidate)

Migration `0004_master` adds a transactional outbox (`master_subscription_notifications`), a subscription notification revision, and a verified private-chat link. Existing numeric Telegram IDs are **not** backfilled as links: each active subscriber must send a private `/start` to this master bot. Group chats and mismatched senders cannot link; disabled accounts cannot link or receive subscription details/magic links. The verified recipient is stored separately from the account identity, so changing an identity cannot silently transfer the link.

The real administrator `PUT /api/master-admin/subscribers/{id}/subscription` queues an activation/assignment notice in the **same transaction** as a changed, future-dated grant. An identical absolute-expiry PUT does not queue another event; `days` remains the existing additive renewal operation, so repeating it grants another extension and produces a new revision. The master worker queues expiry only on the `active` → `expired` transition, even when there are no devices or the nodes are unavailable. Notices describe the master entitlement, **not** confirmed node provisioning. No historical assignment backfill or advance-expiry reminders are included.

**Proactive delivery is off by default**, independently of the existing configured interactive bot. The runner drains at most 20 due events before each long poll only when started with `VS_MASTER_TELEGRAM_NOTIFICATIONS=1`; token and public HTTPS URL must also be configured as above. Do not enable this against a real bot until separately authorized. These changes neither configure a token nor change installation/service files. General-sale billing remains disabled; the separately gated one-off test above is the only exception.

Each send has a committed 60-second claim lease; no SQLite transaction/writer lock is held across the Telegram request. Failed attempts remain durable and retry after 30 seconds, doubling to a one-hour cap; bot restart does not reset the attempt/lease schedule. An abandoned lease becomes eligible again. Delivery is recorded only after a successful `sendMessage` response containing a private-chat message ID for the expected recipient. Immediately before attempting delivery the claim transaction rechecks active account, exact verified link/recipient, subscription revision and current expiry. Obsolete or unauthorized events are terminally suppressed (not delivered), rather than sending stale activation/expiry information. A change made after a send is already in flight cannot retract that message.

Delivery is **at least once, not exactly once**: if Telegram accepted the message but its response was lost, the process crashed before the local acknowledgement, or a lease expired during an ambiguous request, retry may send a duplicate. The Bot API request has no application-supplied idempotency key in this implementation. Local claim fencing prevents concurrent normal attempts and stale local acknowledgements; it cannot undo an already accepted Telegram send. Run one authorized polling consumer per token; the lease is not permission to start competing long pollers. There is no automatic outbox retention/purge policy in this slice.

Upgrade only the master DB using the usual `alembic-master` migration workflow before starting the updated worker/bot. Downgrade refuses once verified links, revised grants, or any outbox rows exist: stop the processes and use a reviewed backup/restore procedure instead of dropping delivery history or pending retries. The new migration was exercised against a disposable file-backed SQLite DB with prior `0003_master` rows, WAL, uniqueness/check/foreign-key rejects and metadata comparison. Tests use synthetic Telegram transport only; Windows runs use an import-only `pwd` shim and do not validate Linux host behavior.

Checks: backend/API/SQLite tests, browser UI tests with simulated responses, and native systemd unit parse on a disposable VPS staging path. On November 9, 2026, master release `57818dbf459de080610582ebf47dae758a161e14` was installed on test VPS `85.209.159.130` after an integrity-checked database/UI rollback backup. The installed wheel matched the release, master web/worker/bot and backup timer were active, the loopback/public health checks passed, and the anonymous browser reached the Telegram-login screen. Proactive notifications and Stars invoices remained off; the Caddy configuration checksum was unchanged. Linux master tests against that commit: 220 passed. **Real Telegram device commands, authenticated cabinet access and live master→node provisioning were not exercised**; the five existing service peers on rg3 were not changed by the master installation.
