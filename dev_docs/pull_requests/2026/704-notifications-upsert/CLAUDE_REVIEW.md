# PR #704 — Let notifications collapse repeat events onto one row

**Reviewer:** Claude (post-merge sweep, 2026-08-11)
**Verdict:** Merged. Two bugs fixed on main, both in the same four lines.

## Summary

`upsert_inapp/3` fills a real gap, and the central design rule — **only unseen
rows collapse** — is right and well-argued. Folding a new event into a row the
user has already read would hide it and leave the unread count unmoved; that is
the same reasoning as the unseen-first ordering in #702, and it is good that it
is stated in the docstring rather than left implicit.

The `create_inapp/2` change that threads `:dedupe_key` and merges
`display[:metadata]` is safe for existing callers: `put_meta/3` drops `nil` and
`""`, so a caller that passes neither is unaffected.

Both defects below are on the **race fallback** — the branch that runs when the
row disappears between the read and the write. Neither is reachable from the
happy path, which is why seven tests pass over them.

## BUG - HIGH: the `update_all` guard the PR describes was never in the query

`lib/phoenix_kit/notifications/notifications.ex` — `refresh_inapp/2`.

The PR description says:

> the row-count guard on `update_all` was the only thing standing between a
> dismissed notification and resurrection

But the guard is only in the **read**. `find_collapsible/2` filters
`is_nil(dismissed_at) and is_nil(seen_at)`; the update filtered on
`where: n.uuid == ^notification.uuid` and nothing else. So the row count could
only ever be 0 if the row was physically **deleted** (pruned) in between —
dismissing or reading it changed nothing about whether the write landed.

Consequences, both of which defeat the rule the PR is built around:

1. A row the user **dismisses** between the read and the write gets refreshed
   anyway. `dismissed_at` stays set, so the row is not resurrected — it is
   worse than that. The update silently succeeds, `{:ok, updated}` comes back,
   and the event is now recorded only on a row that will never be shown again.
   The notification is lost, and the caller is told it succeeded.
2. A row the user **reads** between the read and the write gets the new event
   folded into it, unread count unmoved — exactly the outcome the unseen-only
   rule exists to prevent, arrived at by a different route.

**Fixed on main:** the same `is_nil(dismissed_at) and is_nil(seen_at)` guard
now appears in the update's `where`, which makes the row-count check mean what
the description says it means and makes the fallback reachable for the reason
it was written.

## BUG - MEDIUM: the fallback drops the dedupe key, disabling collapsing forever

Same function, the `_ ->` branch:

```elixir
create_inapp(notification.recipient_uuid, display)
```

`display` is the caller's map. The key lives in the separate `key` argument —
the new-row path in `upsert_inapp/3` puts it in explicitly
(`Map.put(display, :dedupe_key, key)`), and this path does not. Since
`put_meta/3` skips `nil`, the replacement row is written with **no
`dedupe_key` at all**.

Nothing errors. But `find_collapsible/2` matches on
`metadata->>'dedupe_key'`, so that row can never be found again: every
subsequent event for that key posts another new row, forever, for that user.
One lost race silently turns collapsing off — and it degrades to the pre-PR
behaviour that looks like the feature was never wired up, which is the hardest
kind of bug to notice from the outside.

**Fixed on main:** `refresh_inapp/3` now takes `key` and the fallback passes
`Map.put(display, :dedupe_key, key)`, matching the new-row path.

## Test coverage

The seven tests are good and cover the rules that matter — including the three
refusals and merge-not-replace. Both fixes above are on a genuine
read-then-write race that cannot be driven deterministically through the public
API from a single process (`find_collapsible/2` and `update_all` hit the same
connection in sequence), so **these two paths are verified by inspection, not
by a test.** Recorded here rather than papered over with a test seam that would
exist only to be tested.

The existing `"extra metadata is merged, not replaced"` test does pin the
invariant the fallback was breaking (`dedupe_key` survives a refresh), just not
via that branch.

## Notes, not defects

- `inserted_at` moving forward on every refresh means a continuously-refreshed
  notification is never pruned by `PruneWorker` (which ages on `inserted_at`).
  Working as intended for sort order; worth knowing if a hot key ever pins a row
  indefinitely.
- `Map.merge(display[:metadata] || %{})` runs *after* the `put_meta` calls, so a
  caller can overwrite `notification_text` or `dedupe_key` through `:metadata`.
  Harmless today, and arguably the useful precedence; noted in case it ever
  needs locking down.
- `find_collapsible/2` rescues but does not `catch :exit`. Core's AGENTS.md calls
  for both on soft-failure paths (a dead pool exits rather than raises). Left as
  is: unlike a settings read, there is no useful degraded path here — if the
  pool is dead the `create_inapp/2` fallback fails too.
