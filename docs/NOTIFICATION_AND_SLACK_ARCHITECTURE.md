# Notification / Event Backbone + Slack Architecture (Phase 4)

Status: current-state document, established 2026-09-20. This is the Phase 4
notification/event backbone for the Django UI foundation described in
`docs/DJANGO_UI_FOUNDATION.md` (Phase 3). It replaces the Phase 3 empty-state
placeholder in `core/services/notification_service.py` with real persistence
and delivery, and adds the Slack adapter that Phase 3 explicitly deferred.

## 1. Normalized event schema

One model, `web/core/models.py::Notification`, backs every notification. It
is deliberately generic so future producers can publish through it without a
schema change per event kind:

| Field | Type | Notes |
|---|---|---|
| `id` | auto PK | stable event/notification ID |
| `event_type` | `CharField` (`EventType` choices) | closed taxonomy, extensible by adding a choice (see §2) |
| `severity` | `CharField` (`Severity` choices) | closed taxonomy (see §3) |
| `title` | `CharField(200)` | short summary |
| `message` | `TextField` | short message body |
| `detail` | `TextField`, optional | longer explanation, rendered in a `.code-panel` on the detail page |
| `source` | `CharField(100)`, optional | which subsystem raised the event, e.g. `cli.send_test_notification` |
| `device` / `interface` / `change_id` / `lifecycle_state` | `CharField`, optional | structured context |
| `metadata` | `JSONField`, optional | structured safe metadata (see §4) |
| `detail_url` | `CharField(500)`, optional | optional **external** reference URL (e.g. a future GitHub Actions run) — never the in-app route, which is always `get_absolute_url()` |
| `correlation_key` | `CharField(200)`, optional, indexed | deduplication key (see §15) |
| `is_read` / `read_at` | bool / datetime | read state (see §9) |
| `created_at` / `updated_at` | datetime | creation + last-update timestamps |
| `slack_status` / `slack_error` / `slack_attempted_at` | see §10 | Slack delivery state — never the webhook itself |
| `is_test` | bool | true only for rows created by `send_test_notification` (see §13) |

`Meta.ordering = ["-created_at"]` — newest first everywhere, by construction.

## 2. Event types (extensibility model)

`Notification.EventType` (a `django.db.models.TextChoices`) currently
defines: `TEST`, `GENERIC`, plus the full future producer list named in the
Phase 4 brief — `GOLDEN_PROMOTION_BLOCKED`, `SOAK_REGRESSION`,
`SOAK_COMPLETE`, `DEPLOYMENT_FAILED`, `DEPLOYMENT_SUCCEEDED`, `UAT_PARTIAL`,
`GITHUB_ACTIONS_FAILED`, `GITHUB_ACTIONS_PASSED`, `ROLLBACK_FAILED`,
`ROLLBACK_SUCCEEDED`, `DEVICE_HEALTH_CRITICAL`, `LINK_STATE_CRITICAL`. None
of these are wired to a real producer yet (see §16) — they exist so the
schema and UI can render them once a later phase starts publishing.
Django's `choices` are validation metadata only (not a DB `CHECK`
constraint), so adding a new event type later is a one-line addition plus an
auto-generated, no-op-on-SQLite migration — not a schema redesign.
`publish_event()` additionally validates at call time (raises `ValueError`
for anything not in `EventType.values`) so a typo fails loudly instead of
silently persisting garbage.

## 3. Severity taxonomy

`Notification.Severity`: `INFO`, `SUCCESS`, `WARNING`, `ERROR`, `CRITICAL` —
a closed five-value set, validated the same way as event type. Severity
drives:

- badge color + label (`core/templatetags/core_extras.py::severity_badge_class`)
- an **icon glyph**, not color alone: ℹ (INFO), ✓ (SUCCESS), ⚠ (WARNING), ✖
  (ERROR), ‼ (CRITICAL) — `severity_icon`
- Slack message text (`[SEVERITY] Title`)
- future filtering (the Notification Center's severity filter already uses
  it)

**Why icon + text, not color alone**: `core/static/core/css/tokens.css`
defines `--danger` for Adeptus Mechanicus as `#d4483a` — nearly identical to
that theme's own `--accent-strong`. A CRITICAL badge that relied on color
alone would be visually camouflaged by the theme's own red palette. CRITICAL
therefore gets its own `.badge--critical` CSS class (solid fill + border +
bold, not just a tinted background like the other badges) on top of the icon
prefix, so it never becomes theme-dependent-ambiguous. See
`core/static/core/css/base.css` around `.badge--critical`.

Operational terms are never lore-themed: "Critical"/"Warning"/"Error" render
identically in every theme, including Dark Angels and Adeptus Mechanicus —
only the surrounding chrome (colors, watermark) changes.

## 4. Metadata policy

`metadata` is a plain `JSONField`. `publish_event()` enforces a hard
denylist (`notification_service._FORBIDDEN_METADATA_KEY_SUBSTRINGS`) —
`password`, `passwd`, `secret`, `token`, `webhook`, `credential`, `apikey`,
`api_key`, `private_key` — matched case-insensitively as a substring against
every metadata key. A match **raises `ValueError`** (the write is refused,
not silently stripped) so a caller that tries to smuggle a secret into
metadata fails immediately and loudly during development, not silently in
production. Safe example: `{"device": "R5", "change_id": "CHG-20260920-0004",
"candidate_iteration": 2, "affected_feature": "ecmp"}`. Metadata values are
rendered in the detail page via plain `{{ value }}` (Django auto-escaping,
never `|safe`), so even if a caller put HTML-looking text in a metadata
value it cannot inject markup (see §17, §11 tests).

## 5. Publisher API

`core/services/notification_service.py::publish_event(...)` is the **one**
reusable entry point every future Python subsystem should call instead of
writing its own `Notification.objects.create()` or its own Slack HTTP call:

```python
publish_event(
    event_type=Notification.EventType.SOAK_REGRESSION,
    severity=Notification.Severity.WARNING,
    title="Soak regression detected",
    message="R5 CPU regression during iteration 2",
    device="R5",
    change_id="CHG-58",
    metadata={"candidate_iteration": 2, "affected_feature": "ecmp"},
    correlation_key="SOAK_REGRESSION:CHG-58:iter2:cpu",
)
```

Flow (never reorder): persist the `Notification` row first (durable even if
everything below fails) → attempt Slack delivery, bounded and synchronous →
record the delivery outcome on the same row. `publish_event()` never raises
because of a Slack-layer failure; `slack_service.send_notification()` itself
never raises at all (every failure mode is caught and turned into a
`SlackDeliveryResult`).

## 6. Django persistence

One model, one migration (`core/migrations/0001_notification.py`), SQLite
(same database Phase 3 already uses for `auth`/`admin`/`sessions` — no new
database was introduced). No networking/device-state model was added
alongside it — `core_notification` is the only new table.

## 7. Service boundary

`core/views.py` still calls exactly one service function per view (the
Phase 3 rule, still enforced by `core/tests/test_architecture.py`'s AST
check). All ORM access lives in `notification_service.py`; `slack_service.py`
is the only module that imports `urllib` for an outbound call. No Django
view imports Slack machinery directly.

## 8. Audience model (explicit decision)

Phase 4 does **not** add an operator-account system. There is no
authenticated-user concept in this project yet (`docs/DJANGO_UI_FOUNDATION.md`
§10), so every `Notification` is global/system-wide — there is no
per-user foreign key, and "mark all read" means "mark every notification
read," not "mark my notifications read." This is the simplest design
compatible with the current project and was an explicit choice, not an
oversight: inventing accounts to satisfy this phase was out of scope. A
future accounts phase can add a nullable `recipient` FK to `auth.User`
without breaking anything here (global notifications would simply have
`recipient=None`).

## 9. In-app notifications: dropdown, Notification Center, detail

**Header dropdown** (`core/templates/core/components/notification_dropdown.html`,
included on every page via `header.html`): shows at most
`notification_service.MAX_DROPDOWN_NOTIFICATIONS` (4) notifications, newest
first, via `get_recent_notifications(limit=4)`. Empty state renders "No
notifications yet." — verified by `core/tests/test_notifications.py`. The
bell button carries an unread-count badge (`unread_notification_count()`
simple tag), capped at display **"9+"** for any count over 9 (documented
cap — `core_extras.py::notification_badge_display`). "Mark all read" is a
small CSRF-protected POST form in the dropdown footer.

**Notification Center** (`core/templates/core/notifications.html`, route
`/notifications/`, reachable only from the header bell — still absent from
the sidebar, per the Phase 3 rule, still enforced by
`test_routes.py`/`test_navigation.py`): unbounded list, newest first,
paginated 25/page (`django.core.paginator.Paginator`), with three simple
filters — unread-only checkbox, severity `<select>`, event-type `<select>` —
all plain GET query params, deliberately not a complex filter builder.

**Detail page** (`core/templates/core/notification_detail.html`, route
`/notifications/<id>/`): shows every safe field — event ID, event type,
severity, title, message, detail, timestamps, device/interface/change
ID/lifecycle state, metadata table, Slack delivery status/error, and a
"Retry Slack delivery" button when `slack_status == FAILED`. Never renders a
secret (there is none on the model to render).

## 10. Read/unread semantics

Default state is unread (`is_read=False`). Opening the detail page is a
plain `GET` and **does not by itself mutate anything** — proven by
`test_notification_views.py::NotificationDetailViewTests
::test_opening_detail_page_does_not_itself_mark_read`. Marking read only
ever happens via `POST /notifications/<id>/mark-read/`
(`@require_POST`, CSRF-protected via Django's default `CsrfViewMiddleware`).

The detail page provides two paths to that POST, both hitting the exact same
endpoint:

1. A visible "Mark as read" button (a normal CSRF-protected form) — the
   only mechanism when JavaScript is disabled.
2. Progressive enhancement (`core/static/core/js/app.js`): on page load, if
   the notification is unread, a background `fetch()` POST (with the CSRF
   token read from the same form's hidden input) fires automatically, with
   no page reload. This is what makes "opening a notification marks it
   read" feel automatic in a normal browser, while the actual mutation is
   still a CSRF-protected POST, never a GET.

"Mark all read" (`POST /notifications/mark-all-read/`) marks every currently
unread notification read in one `UPDATE` query
(`notification_service.mark_all_read()`), available from both the dropdown
footer and the Notification Center.

## 11. Slack provider

`core/services/slack_service.py` is the only Slack-aware module in the
project. Implementation choice: **Python standard library (`urllib`)**, not
`requests` and not a Slack SDK. `web/requirements.txt` is `Django>=5.1,<5.2`
only; `requests` is already a dependency of `monitoring/requirements.txt`
(a different subsystem's venv-shared dependency list) but adding it to
`web/` merely to POST one small JSON payload with a timeout is exactly the
case the Phase 4 brief says to avoid — `urllib.request` does the whole job
in ~30 lines with no new dependency.

Delivery is an **Incoming Webhook**: one `POST` of `{"text": "..."}` to the
URL in `SLACK_WEBHOOK_URL`. Message content
(`slack_service.build_message()`): severity + title, the short message,
device/change-id context if present, `Event: <type> · ID <n> ·
<timestamp>`, and a `Details: <APP_BASE_URL><path>` line **only** if
`APP_BASE_URL` is configured — never a fabricated or localhost URL.

## 12. Environment variables

| Variable | Purpose | Required? |
|---|---|---|
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL | No — absence is a first-class, tested state (`NOT_CONFIGURED`), not an error |
| `APP_BASE_URL` | externally-reachable base URL, e.g. `https://nmas.example.org`, used only to build the optional Slack detail link | No — omitted means no detail link is sent, ever |

Both are read directly from `os.environ` inside `slack_service.py` at send
time — never cached in Django `settings`, never placed in a template
context, never logged. Setting them for local testing:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T000/B000/xxxx"
export APP_BASE_URL="http://127.0.0.1:8000"   # optional
cd web
DJANGO_DEBUG=true /home/student/Scripts/.venv/bin/python3 manage.py send_test_notification
```

## 13. Test-notification command

`manage.py send_test_notification` (`core/management/commands/`):

- Creates exactly one `Notification` with `event_type=TEST`, `is_test=True`,
  and a title/message that both explicitly say "TEST" — never a fabricated
  real-looking outage.
- Options: `--severity` (default `INFO`), `--title`, `--message`,
  `--no-slack` (dry-run for Slack even if `SLACK_WEBHOOK_URL` is set),
  `--correlation-key`.
- Goes through the normal `publish_event()` path — real persistence, real
  (optional) Slack attempt, same code path production events will use.
- Never imports `netmiko`/`pynetbox`/`paramiko`/`subprocess` (statically
  checked in `core/tests/test_notification_commands.py`) — cannot touch a
  device, NetBox, or Containerlab even by accident.

`manage.py cleanup_test_notifications` deletes only `is_test=True` rows.
Dry-run by default (reports a count); `--apply` actually deletes. This is
the only sanctioned way to remove synthetic test rows from a shared/dev
database — it can never touch a real notification, regardless of that
notification's content.

## 14. Slack delivery semantics / failure behavior

States (`Notification.SlackStatus`): `NOT_CONFIGURED`, `PENDING`, `SENT`,
`FAILED`, `SKIPPED` (the fifth state, added beyond the brief's four-item
example list: set when a caller explicitly passes `notify_slack=False`,
e.g. the test command's `--no-slack` — distinct from `NOT_CONFIGURED`,
which means "no webhook is configured at all"). `PENDING` is the transient
value between `Notification.objects.create()` and the delivery attempt in
the same request — by the time `publish_event()` returns, it has always
already been resolved to one of the other four.

Delivery is a single bounded attempt: `slack_service.REQUEST_TIMEOUT_SECONDS
= 5`. No retry loop, no queue, no Celery/Redis (deliberately, per the Phase
4 brief — not justified at this project's current scale). Every failure
mode — missing config, HTTP error, connection error, timeout, anything
unexpected — is caught inside `slack_service.send_notification()` and
converted to a `SlackDeliveryResult(status=FAILED, error=...)`; the
in-app `Notification` row is never rolled back or deleted because of it
(`core/tests/test_slack_service.py::MockedSlackDeliveryTests
::test_slack_failure_does_not_delete_in_app_notification`). A manual retry
is available: `notification_service.retry_slack_delivery(id)`, exposed in
the UI as the detail page's "Retry Slack delivery" button when
`slack_status == FAILED`. It is a single additional bounded attempt, not an
automatic loop.

## 15. Deduplication / correlation support

`correlation_key` (optional, free-text, indexed) plus
`notification_service.DEDUP_WINDOW` (5 minutes, a module constant, not
env-configurable — kept simple per the brief). Semantics: publishing an
event with a `correlation_key` that already has a `Notification` created
within the last `DEDUP_WINDOW` **returns that existing row unchanged** — no
new row, no repeat Slack send. Example: a future soak-regression monitor
polling once a minute with
`correlation_key=f"SOAK_REGRESSION:{change_id}:iter{n}:cpu"` will not create
a new notification (or re-page Slack) on every poll while the same
regression persists.

**Known limitation**: the dedup check-then-create is not wrapped in a
database-level lock/transaction, so it is not race-proof under concurrent
publishers issuing the same `correlation_key` in the same instant. Acceptable
for this project's current single-process Django dev/lab deployment; a
future phase with real concurrent producers should reconsider (e.g. a
unique constraint plus `get_or_create`).

## 16. Future producer map (not implemented in Phase 4)

| Phase | Event type(s) it will publish |
|---|---|
| 15 | health/postcheck alerts → `DEVICE_HEALTH_CRITICAL`, `LINK_STATE_CRITICAL` |
| 16 | GitHub Actions results → `GITHUB_ACTIONS_FAILED`, `GITHUB_ACTIONS_PASSED` |
| 17 | deployment results → `DEPLOYMENT_FAILED`, `DEPLOYMENT_SUCCEEDED` |
| 19 | Golden/Probation lifecycle → `UAT_PARTIAL`, lifecycle_state transitions |
| 20 | soak regression / Golden promotion blocked → `SOAK_REGRESSION`, `SOAK_COMPLETE`, `GOLDEN_PROMOTION_BLOCKED` |
| 21 | rollback/removal outcomes → `ROLLBACK_FAILED`, `ROLLBACK_SUCCEEDED` |

None of these producers exist yet. Phase 4 deliberately did not wire any
current monitoring subsystem (SNMP/syslog/gNMI/CPU alerts/topology) into
`publish_event()` — the only Phase 4 producer is the synthetic test command
(§13), by design, to keep this phase's scope to the backbone itself.

## 17. Future AI assistant integration boundary

**No AI/chatbot/LLM integration exists in Phase 4.** This section exists only
to record that the schema does not block one later: every event carries
structured fields (`event_type`, `severity`, `created_at`, `source`,
`device`, `interface`, `change_id`, `metadata`, delivery history) completely
independent of the Slack presentation text (`slack_service.build_message()`
builds a string from the structured fields, never the other way around). A
future AI assistant could query `Notification` objects directly instead of
scraping Slack message prose. Nothing about this phase implements that
assistant, a Slack bot, interactive remediation, or any LLM call.

**Email is not, and will not be, an operational notification channel for
this project.** Slack is the sole external channel; no email
sending/receiving code exists or was added.

## 18. Security considerations

- **Secret handling**: `SLACK_WEBHOOK_URL` is read from `os.environ` only
  inside `slack_service.py`, at send time, and is never stored on any model,
  never placed in a Django template context, never logged (verified:
  `test_slack_service.py::WebhookNeverExposedTests`).
- **CSRF**: default `CsrfViewMiddleware` (unchanged from Phase 3) protects
  every state-changing endpoint — mark-read, mark-all-read, retry-Slack.
  Verified with `Client(enforce_csrf_checks=True)` in
  `test_notification_views.py`.
- **XSS/escaping**: no notification template uses `|safe` anywhere
  (statically checked); title/message/metadata values render through
  Django's default auto-escaping. Verified with injected `<script>`/`<img
  onerror>` payloads in `test_notification_views.py::SecurityEscapingTests`.
- **Metadata safety**: see §4 — secret-shaped keys are refused at
  `publish_event()`, not merely hidden in the UI.
- **Path traversal**: `theme_assets.resolve_watermark_url()` now defensively
  catches Django's own `SuspiciousFileOperation` (raised by the staticfiles
  finder for a traversal-style path) and treats it as "not found" rather
  than letting it propagate — see §19 below and
  `core/tests/test_artwork.py::NoPathTraversalTests`.

## 19. Artwork regression fix (Phase 4, incidental to notifications)

The operator manually added the ten real watermark files between Phase 3 and
Phase 4, into the directories Phase 3 already documented
(`core/static/core/themes/README.md`) and had already scaffolded with
`.gitkeep` placeholders (`brand/`, `minimal/`, `dark/`,
`dark_angels/{core,deathwing,ravenwing,hexagrammaton}/`,
`mechanicus/{core,forge,monitoring}/`). Verification found that **three of
the ten slots silently failed to resolve** — not because a file was
missing, but because `theme_registry.py`/`theme_assets.py`'s slot key
strings for the brand/minimal/dark-mode slots pointed one directory level
too deep (`"brand/app-mark"`, `"minimal/default"`, `"dark/default"`), a
mismatch that predates Phase 4 and was never exercised while no real
artwork existed. Fixed by correcting those three slot strings to match the
actual, already-documented, already-on-disk directory layout
(`"brand"`, `"minimal"`, `"dark"`) — **no artwork file was renamed, moved,
regenerated, recompressed, or otherwise altered.** All ten now resolve;
verified via `core/tests/test_artwork.py` and live `curl` against every
`/static/core/themes/.../watermark.png` path (all HTTP 200).

## 20. Known limitations

- No per-user notification targeting (see §8) — everything is global.
- Correlation-key dedup is not race-proof under concurrent publishers (§15).
- Slack delivery is single-attempt/bounded-synchronous; a genuinely
  unavailable Slack endpoint adds up to `REQUEST_TIMEOUT_SECONDS` (5s) of
  latency to the publishing request. Acceptable at current scale; would need
  to move off-request (queue/async) if publish-time latency ever matters.
- No Slack bot / interactive commands / AI assistant (by design, see §17).
- No email channel (by design, see §17).
- Dropdown "9+" is currently the only documented display cap; there is no
  cap on the underlying `get_unread_count()` integer itself.
- No producer beyond the synthetic test command is wired up yet (§16) —
  expected, this phase is the backbone only.
