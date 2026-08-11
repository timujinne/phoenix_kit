# PR #702 — Sort a user's notifications unseen first

**Author:** alexdont · **Branch:** `notifications-unseen-first` · **Reviewed:** 2026-08-11

Changes `list_for_user/2` and `recent_for_user/2` to order unseen-before-seen,
newest-first within each group, and adds four integration tests.

The change itself is right, and the reasoning in the PR body holds up: the
`fragment("? IS NOT NULL", ...)` formulation is correct (false sorts first, so
unseen leads without a negation), `admin_list/1` is correctly left alone, and
the claim that reading a notification never reorders the list under the cursor
is true *for the bell*. Two problems came out of reading the consumers.

---

## BUG - HIGH — the inbox renders duplicate day headers

`PhoenixKitWeb.Live.Notifications.Inbox.grouped/1` chunked rows into day
buckets on the day alone, under an explicit comment that the rows are
"desc-sorted by inserted_at, so buckets are contiguous". That premise is
exactly what this PR removes.

With unseen-first the day sequence restarts at the seen block, so an inbox
holding read and unread rows across more than one day renders:

```
Today          ← unread
Yesterday      ← unread
Today          ← read      ⟵ same header again, a week of history apart
Yesterday      ← read
```

`Enum.chunk_by/2` only merges *adjacent* equal keys, so the repeat is silent —
no error, just two identically-labelled sections on the page.

**Fixed.** The chunk key is now `{unread?, day}`, and the unread run is
labelled `"Unread · <day>"`. Every header is unique again, and the outstanding
work is now labelled as such at the top rather than left to be inferred from
row tint — which is the point of the new order.

**Test:** `test/integration/phoenix_kit_web/live/notifications/inbox_grouping_test.exs`.
It seeds read and unread rows across two days (the minimum shape that
reproduces), renders the LiveView, and asserts the section headers are all
distinct. No existing test set up that shape, which is why the regression was
invisible.

## BUG - MEDIUM — the order was not total, so paging could drop or repeat a row

`Notification.inserted_at` is `:utc_datetime` — **second** granularity. A
fan-out writes many notifications inside one second, and every one of them
ties. Under `LIMIT`/`OFFSET` an unstable tie lets Postgres return the same row
on two pages, or on neither.

Pre-existing (the old `desc: inserted_at` had the same hole), but this PR is
the one that promises an order, and its own tests have to `Process.sleep(1_100)`
between insertions to get a provable one — which is the tell.

**Fixed.** `desc: n.uuid` is now the final key in `order_unseen_first/1` and in
`admin_list/1`. The primary keys are UUIDv7, which is time-ordered, so
descending on it agrees with newest-first rather than scrambling the tied
block. `admin_list/1` keeps its plain newest-first seen-ness behaviour — the
tiebreaker is orthogonal to the decision the PR documents there.

---

## Accepted, with the limitation on record

**`recent_for_user/2` no longer uses its covering index.**
`phoenix_kit_notifications_recipient_inbox_index` is
`(recipient_uuid, inserted_at DESC) WHERE dismissed_at IS NULL` — it satisfied
the old bell query as an index scan stopping after 10 rows. The new
`seen_at IS NOT NULL` leading key cannot be served from it, so Postgres now
fetches the user's whole undismissed set and sorts it.

Not fixed, deliberately: `Notifications.PruneWorker` bounds an inbox by
`notifications_retention_days` (default 90), so the sorted set is a single
user's retained notifications, not an unbounded history. Adding a matching
index means a new core migration version for a cost that only appears on
pathological inboxes. Recorded here so it is a decision rather than an
oversight — if bell latency ever shows up, the index is
`(recipient_uuid, (seen_at IS NOT NULL), inserted_at DESC) WHERE dismissed_at IS NULL`.

**The PR's "nothing shuffles while you're looking at it" claim is bell-only.**
On the inbox page `handle_event("mark_seen", ...)` and the link-less branch of
`"open_notification"` both call `load(socket)` directly, so the row moves out
of the unread block immediately, under the cursor. Also true of a
`:notification_seen` broadcast from another tab. Freezing the order client-side
would be a bigger mechanism than the problem justifies; with the grouping fix
the row visibly moves from "Unread · Today" into "Today", which at least reads
as an explanation rather than a jump.

---

## Verification

- `mix precommit` — clean.
- `mix test` — 38 doctests, 1978 tests, 0 failures.
- ⚠️ **No PostgreSQL in the review environment**, so all 1359 `:integration`
  tests were excluded — including this PR's four ordering tests and the
  grouping test added here. They compile and are correctly tagged; they have
  not been executed. Per this repo's own CLAUDE.md, a green summary without a
  database proves nothing about a schema- or query-level change. Both files
  need a DB run before this ships.
