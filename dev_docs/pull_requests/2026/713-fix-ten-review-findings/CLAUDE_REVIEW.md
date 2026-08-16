# PR #713 Review — Fix the ten findings from the high-effort review of the recent merges

**Author:** Sasha Don (alexdont)
**Reviewed:** 2026-08-14 (ecosystem sweep — PR arrived mid-sweep, after 2.4.0 published)
**Verdict:** APPROVED — merged unchanged; no post-merge fixes required

---

## Context

This PR opened at 10:04 on 2026-08-14, after `phoenix_kit` 2.4.0 had been published
earlier in the same sweep. Phase 7 of the sweep skill says a PR that appears mid-run gets
processed or explained; this one fixes ten confirmed findings in recently merged work, two
of which need schema support, so it was processed and ships as **2.5.0**.

---

## V170 — the part that deserved the most scrutiny

Two indexes on `phoenix_kit_notifications`, and a duplicate fold before the unique one is
built. Verified against the migrated database rather than read off the diff:

```
phoenix_kit_notifications_dedupe_unseen_idx
  UNIQUE (recipient_uuid, ((metadata ->> 'dedupe_key')))
  WHERE seen_at IS NULL AND dismissed_at IS NULL AND (metadata ->> 'dedupe_key') IS NOT NULL

phoenix_kit_notifications_recipient_unseen_first_idx
  (recipient_uuid, ((seen_at IS NOT NULL)), inserted_at DESC, uuid DESC)
  WHERE dismissed_at IS NULL
```

Chain comment reads `170`.

**The partial predicate matches `find_collapsible/2` term for term** — recipient,
`dismissed_at IS NULL AND seen_at IS NULL`, `metadata->>'dedupe_key' = ?`. That matters
twice over: it is what lets the index serve the lookup, and it is what makes the
uniqueness constraint scoped correctly. Rows with no dedupe key — everything the fan-out
path creates — fall outside the predicate entirely, so the ordinary notification path
cannot start tripping a constraint it never had.

**The race fix is a real fix, not a narrowing of the window.** `find`-then-`insert` cannot
be made safe by ordering alone; the index is the only thing that can decide it, and
`insert_collapsible/3` correctly treats the constraint violation as "someone else won" and
retries the find to collapse onto the winner. If the retry still finds nothing it returns
the changeset error rather than looping — right call.

**Dismissing existing duplicates rather than deleting them** is the correct choice and is
argued for properly: the rows and their history remain, they just stop occupying the
inbox, which is where the collapsing API would have put them had it won the race
originally. Deleting would destroy audit history to fix a display problem.

**The fold and the index creation share one `SHARE ROW EXCLUSIVE` lock**, which is the
detail that makes the migration correct rather than merely usually-correct — without it a
concurrent insert between the fold and the `CREATE UNIQUE INDEX` re-introduces a duplicate
and aborts the migration.

**It already follows the `LOCK TABLE` guard rule that 2.4.0 added a test for**, and its
comment cites the reason. `lock_table_guard_test.exs` (added in 2.4.0 after V169 shipped
with an unguarded `LOCK TABLE` in `down/1`) passes on V170 unmodified — the guard is
present with the schema anchor.

---

## The nine code findings

All are real, and each fix addresses the cause rather than the symptom. The ones worth
calling out:

- **The kill switch.** `upsert_inapp/3` not honouring `notifications_enabled` is the most
  consequential of the ten: it is host-facing, and a switch that silently didn't cover the
  newest creation path is worse than no switch, because an operator believes it is off.
- **Metadata clobber.** Merging caller metadata *first* and stamping reserved keys on top
  is the right order. The string-normalisation half is the subtler bug — without it
  `%{notification_text: …}` and `"notification_text"` can coexist in one map and which
  wins depends on adapter ordering, which is exactly the kind of defect that reproduces on
  one machine and not another.
- **`catch :exit` on `find_collapsible/2`.** This project's own soft-failure rule (a dead
  pool exits rather than raising, so `rescue` alone is not enough) is documented in core's
  `AGENTS.md` and was not applied here. Correctly applied now, and both clauses log — a
  permanent query bug silently degrading upsert into insert-always was otherwise
  undiagnosable.
- **The inbox event whitelist.** The fix is fine; the *test* is the valuable part —
  scraping every event the library broadcasts and holding the whitelist to it means the
  next event added fails the test until the inbox handles it, instead of producing another
  stale-rows bug years later.
- **Fingerprint logging.** Three log lines per mismatch, two of them wrong (an `:error`
  "possible hijacking" for a request that was then served normally), because the shipped
  `:phoenix_kit_admin_only` pipeline runs both plugs and only one had the #705 dedup.
  Caching the verdict in `conn.private` and sharing it is the right shape. Tested by
  seeding the cache with the *opposite* verdict and observing both plugs honour it, which
  is a genuinely good way to test a cache rather than asserting on log output.
- **`session_label`.** The log label and the sessions UI preview used different
  derivations, so the correlation the feature promised never worked. Now one derivation,
  pinned by a test.

---

## Findings

**No blockers, and no post-merge fixes were required** — the third repo in this sweep
where the PR gated and tested clean exactly as merged.

### NITPICK — dialyzer still reports 4 unnecessary skips

Pre-existing in core's 183-line `.dialyzer_ignore.exs`, unchanged by this PR and noted
here only so it is not read as new. `list_unused_filters: true` is already set in
`mix.exs`, so the count is visible on every run; clearing the four stale entries is worth
a separate pass.

---

## Verification

- `mix precommit` → exit 0 (credo `--strict` found no issues; dialyzer 225 errors, 225
  skipped, 0 unskipped).
- `mix test` → **3536 tests, 0 failures** against real PostgreSQL, including the V170
  integration tests and 2.4.0's `lock_table_guard_test.exs`.
- V170 confirmed applied: chain comment `170`, both indexes present with the predicates
  above.
