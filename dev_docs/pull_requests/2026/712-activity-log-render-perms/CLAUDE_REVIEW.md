# PR #712 Review — Fix admin activity crash on map metadata and scope the log to admins

**Author:** Tymofii Shapovalov (timujinne)
**Reviewed:** 2026-08-14 (post-merge sweep)
**Verdict:** APPROVED — merged unchanged

---

## Scope

Two commits: a render crash on `/admin/activity`, and an access-scoping change making
the full audit log administrators-only.

---

## 1. Render crash — `humanize_metadata_value/1`

`GET /admin/activity` raised `Protocol.UndefinedError` (String.Chars not implemented
for Map) whenever an entry's metadata carried a field-change diff such as
`%{"qty" => %{"from" => 1, "to" => 2}}`. Three call sites interpolated the value
directly; all three now route through `Activity.humanize_metadata_value/1`.

The clause ordering is right: `%{"from" => _, "to" => _}` before the general map
clause, `is_map(value) and not is_struct(value)` before the `to_string/1` catch-all.

**Exhaustiveness against the real input domain:** `metadata` is a `jsonb` column, so
decoded values are only maps, lists, binaries, numbers, booleans and `nil` — every one
of which has a clause or is safe under `to_string/1`. The `not is_struct` guard means a
struct would fall through to `to_string/1` and could still raise, but a struct cannot
come out of JSONB decoding, so that path is unreachable rather than a latent crash.

Minor, not worth changing: a map carrying `"from"`/`"to"` *plus* other keys renders only
the arrow form and drops the siblings. That matches how these diffs are actually
written by `log_user_change/4`.

## 2. Access scoping — the part worth checking carefully

The change is only as good as its enforcement point, so I traced it rather than reading
the diff:

- `Activity.Index` computes `full_log_access?` once in `mount/3` and derives
  `scoped_actor_uuid`, which is passed to `Activity.list/1` as `actor_uuid`.
- `apply_filters/2` does consult `:actor_uuid` — `maybe_filter_actor/2` has both a
  `nil` clause (no-op, for a full-access operator) and a real `where` clause. A filter
  key that the query layer silently ignored would have made this whole change
  decorative; it does not.
- **The count is scoped too.** `Activity.list/1` builds one query, derives `total` from
  `repo().aggregate(query, :count)`, and paginates the same query — so the pagination
  total cannot leak the existence of entries a scoped user can't see. This is the most
  common way a scoping fix like this is incomplete, and it isn't here.
- `Activity.Show` gates on `full_log_access?/1 or own_entry?/2` and returns the
  *not-found* response for someone else's entry, so the detail page is not an
  existence oracle for other users' audit records.

`scoped_actor_uuid(false, _scope)` falling back to `Ecto.UUID.generate()` is a slightly
unusual way to express "match nothing", but it is documented, fails closed, and is
strictly safer than `nil` (which `maybe_filter_actor/2` reads as *unrestricted*). A
scope with no resolvable user therefore sees an empty log, never the whole one.

Defining "own" as **authorship** (`actor_uuid`), not target, is the right call and is
pinned in one place — `Activity.own_entry?/2` — with both LiveViews deferring to it and
the docstring stating that the list's filter must change in lock-step. That is what
stops the two views drifting apart, which is the failure mode this class of fix usually
suffers.

---

## Findings

No blockers. No post-merge fixes were required — this PR was merged as-is.

### NITPICK — `humanize_metadata_value/1` has no `@spec`

Every other public function added in this diff (`full_log_access?/1`, `own_entry?/2`)
carries one. Not worth a follow-up commit on its own; fold into the next touch of this
module.

---

## Note on review provenance

The PR body cites an independent reviewer (GLM-5.2 via Pi) returning SHIP. I treated
that as context, not as verification, and re-derived the access-control conclusions
from the source — in particular the count-query check above, which a diff-only review
would not reach, since `Activity.list/1` is unchanged by this PR.
