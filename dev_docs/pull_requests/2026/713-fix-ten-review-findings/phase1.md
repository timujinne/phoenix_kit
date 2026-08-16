# PR #713 Phase 1 Review — phoenix_kit
**Title:** Fix the ten findings from the high-effort review of the recent merges
**Author:** Sasha Don (alexdont)
**Branch:** `fix/high-review-followups` → `main`
**Reviewed:** 2026-08-14

**Verdict:** APPROVE WITH NOTES

---

## Summary

Follow-up to the high-effort review of #702–#705 (notifications-upsert,
fingerprint-logging, js-compiler-warning work). The PR claims ten findings fixed; all
ten are accounted for and correctly addressed. The diff is clean: 757 additions,
82 deletions across 13 files. Test suite reported 3,536 tests, 0 failures, `mix
precommit` exits 0. V170 migration adds two indexes (dedupe UNIQUE + ordering) with
careful duplicate-fold logic under a table lock.

Two notes — neither blocking.

---

## Findings addressed (all 10 confirmed)

### Notifications — V170 + `upsert_inapp` hardening

**Finding 1 — Dedupe lookup had no index.**
`find_collapsible/2` filters on `metadata->>'dedupe_key'` under `recipient_uuid +
unseen`, which the old `(recipient_uuid, inserted_at DESC) WHERE dismissed_at IS NULL`
index (V104/V135) could not serve. V170 adds a partial UNIQUE index on
`(recipient_uuid, (metadata->>'dedupe_key'))` over undismissed unseen keyed rows.
✅ Addressed — index definition in `v170.ex`, declared in `expected_schema.ex`,
`chain_hash` restamped.

**Finding 2 — No index for `order_unseen_first` expression.**
`recent_for_user` was fetching the entire undismissed backlog and sorting in Postgres.
V170 adds `phoenix_kit_notifications_recipient_unseen_first_idx` on `(recipient_uuid,
(seen_at IS NOT NULL), inserted_at DESC, uuid DESC) WHERE dismissed_at IS NULL`,
matching the ORDER BY term-for-term.
✅ Addressed.

**Finding 3 — Race: two concurrent upserts for the same absent key both inserted.**
No backstop existed — parallel Oban workers both read nil and both inserted, leaving
twin unseen rows. The unique index (finding 1) turns the loser's insert into a
constraint trip; `insert_collapsible/3` (new private function) retries
`find_collapsible` and folds.
✅ Addressed. Pre-existing duplicates folded under the same `SHARE ROW EXCLUSIVE`
lock that creates the index. Test `upsert_test.exs` covers the race backstop directly.

**Finding 4 — Kill switch didn't apply to `upsert_inapp/3`.**
`upsert_inapp` called `create_inapp` directly, bypassing the `enabled?()` gate that
`create/1` has. As a host-facing entry point, "off" must mean off.
✅ Addressed — `enabled?()` guard added; returns `{:ok, :skipped}` when disabled.
New test file: `upsert_kill_switch_test.exs`.

**Finding 5 — Metadata clobber: caller map could overwrite `dedupe_key`.**
Old order: `%{} |> put reserved keys |> Map.merge(caller metadata)` — a
passed-through metadata map won adapter-order-dependently over reserved keys. Fixed
to: `caller metadata |> stringify_keys() |> put reserved keys on top`. Atom keys
normalized to strings so `%{notification_text: "impostor"}` cannot coexist with the
string key and win.
✅ Addressed in both `create_inapp/2` and `refresh_inapp/3`. Two new tests in
`upsert_test.exs` confirm the clobber is gone and atom keys are normalized.

**Finding 6 — `find_collapsible/2` caught exceptions but not exits.**
A dead Ecto pool raises on an owned checkout but *exits* on an unowned one —
`rescue` alone let that exit propagate and crash the caller. Also: only the rescue
branch logged; a permanent query bug silently degraded upsert into insert-always.
UUID tie-break missing below `inserted_at`'s second granularity.
✅ Addressed — `catch :exit, reason ->` added alongside `rescue`, both clauses log,
`order_by` gains `desc: n.uuid`.

**Finding 7 — Inbox `handle_info` whitelist missing `:notification_updated`.**
`upsert_inapp/3` broadcasts `:notification_updated` when it refreshes a row; the bell
handled it but the inbox didn't — stale rows while the bell refreshed. No crash, no
log — silent hit to the catch-all.
✅ Addressed — added to the `when event in [...]` guard. New test file
`inbox_events_test.exs` scrapes broadcast call sites and holds the whitelist to every
event the library emits.

### Fingerprint logging

**Finding 8 — Double verification + triple-logging in the admin pipeline.**
`:phoenix_kit_admin_only` runs both `fetch_phoenix_kit_current_user` and
`fetch_phoenix_kit_current_scope`; each verified independently. Every mismatch was
checked twice, logged up to three times — including an old `:error` "possible
hijacking" line from the scope plug for requests that were then served.
✅ Addressed — `check_fingerprint_once/2` caches the verdict in
`conn.private[:phoenix_kit_fingerprint_valid]`; the second plug reuses it without
re-verifying or logging. New test file `fingerprint_once_test.exs` pre-seeds the
cache with the opposite verdict to prove neither plug re-verifies.

**Finding 9 — `session_label` could never match the sessions UI.**
Old derivation: `sha256(token) |> first 8 hex chars`. Sessions UI shows:
`encode(substring(token, 1, 4), 'hex')`. An operator pasting a logged label into the
sessions search got zero results every time.
✅ Addressed — new derivation is `binary_part(token, 0, 4) |> Base.encode16`. Made
`@doc false` public so `fingerprint_once_test.exs` can hold the two derivations
together; the test fails if they drift apart again.

### JS-compiler warning

**Finding 10a — False warning when a module package runs its own test suite.**
`js_compiler_configured?` read `Mix.Project.config()` of whatever project was
compiling, so a module package (e.g. `phoenix_kit_boards`) running `mix test` printed
the fix-your-mix.exs warning for a configuration that was already correct.
✅ Addressed — `warn_missing_js_compiler/0` checks whether any warned module was
compiled from the current project's own source tree (excluding `deps/`, which sits
under cwd — the first cut missed this and the test caught it). `compiled_from_current_project?/1` made `@doc false` public for testability.

**Finding 10b — `modules_declaring_js_sources/0` only rescued, didn't catch.**
A `throw` or `exit` from a discovered module's `js_sources/0` escaped the `rescue`
and aborted the host's compile — precisely what the adjacent comment promised couldn't
happen.
✅ Addressed — `catch _kind, _value -> []` added alongside the `rescue`. Test
verifies the clause is present in source.

---

## Blockers

None.

---

## Non-blockers

**1. `insert_collapsible/3` retry check is broader than the constraint.**
The retry branches on `Keyword.has_key?(errors, :metadata)` rather than the more
precise `dedupe_conflict?(cs)` helper defined just above (which additionally checks
`Keyword.get(opts, :constraint) == :unique`). In practice the only `:metadata`
constraint is the new unique index, so this is safe today. If a future metadata
validation is added, a spurious `find_collapsible` retry would fire on its failure —
wasted query, correct outcome (error returned). Low risk but worth tightening to
`dedupe_conflict?(cs)` for correctness at a glance.

**2. Second V170 index created without CONCURRENTLY.**
`phoenix_kit_notifications_recipient_unseen_first_idx` is `CREATE INDEX IF NOT EXISTS`
(not `CONCURRENTLY`), so it holds a `ShareLock` (blocking writes) for the duration of
its build. For databases with large notification backlogs this could cause visible
write latency during the migration window. Consistent with prior V-series migration
patterns. Acceptable given deployment practice, but worth noting for any heavy
installations.

---

## Nitpicks

- No `@version` bump or CHANGELOG entry. PR body explicitly calls this out as
  intentional — fine if the release discipline batches these separately.
- `session_label` made `def` + `@doc false`. Correct technique; minor API surface
  increase.
- The `inbox_events_test.exs` scrape regex (`Events\.broadcast\([^,]+,\s*\{:(\w+)`) is
  format-dependent — if the broadcast call style ever changes (multi-line, different
  quoting) the scrape silently returns stale results. The guard `assert events != []`
  catches total breakdown but not partial drift. Fine for now.

---

## Stats

- **Tests:** 4 new test files (`upsert_kill_switch_test.exs`,
  `fingerprint_once_test.exs`, `inbox_events_test.exs`, additions to
  `js_compiler_warning_test.exs` and `upsert_test.exs`). All 10 findings have
  at least one test; race backstop and scrape-pin tests are particularly strong.
  Suite: 3,536 tests, 0 failures (per PR body).
- **Migrations:** V170 — two indexes + pre-creation duplicate fold. Migration safety
  is good: `IF EXISTS` table guard, `IF NOT EXISTS` on both indexes,
  `SHARE ROW EXCLUSIVE` lock covers fold + unique index creation atomically.
  `down/1` drops both indexes (fold not reversed — deliberate, documented).
- **Version bump:** None (intentional per PR body).
- **Dependency changes:** None.
- **`expected_schema.ex` `chain_hash`:** Restamped
  `afba80ea02c44069735a602444c12d20436d8b17b37fdd8223d6b9285be9c438`.
  Both V170 indexes hand-declared with definitions captured from
  `pg_get_indexdef` on a live database (same caveat as V165–V167 objects).
