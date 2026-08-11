# PR #701 — Close the silent-success gaps in status, doctor and update; adopt locale_slug 0.2.0

**Author:** Max Don (`mdon`) · **Merged:** 2026-08-10 · **Base:** `main` · **Merge:** `32c38a20`

**Reviewer:** Claude Opus 5 · **Reviewed:** 2026-08-10 · post-merge, against the merged tree

**Scope:** 8 files — `phoenix_kit.{doctor,repair,status,update}.ex`, `migrations/repair.ex`,
`mix.exs` / `mix.lock`, plus a new `test/mix/tasks/phoenix_kit_status_test.exs`.

**Verdict:** Sound PR. The premise is correct and well-evidenced throughout, and the
`--exit-code` fail-closed reasoning in particular is the kind of thing that is normally
found in production rather than in review. Four defects found, all in the new code, all
fixed here. Two of them share a shape: a report that now states something precise, and
states it wrongly — the by-table breakdown misreports the exact number an operator was
given the feature to read, and the reworded repair message names the wrong version.

---

## BUG - MEDIUM — the new by-table breakdown invents tables out of index names

**File:** `lib/mix/tasks/phoenix_kit.repair.ex:213-224` (as merged)

`table_of/1` derived the table from any `object_id` by taking the segment between the
first `:` and the first following `.` or `:`. Its own comment states the contract —
*"Anything that does not parse is dropped rather than guessed at, so a malformed id cannot
invent a table"* — but the rule does not implement it. Four of the manifest's eight object
classes name the object itself and carry no table at all, and every one of them *parses*:

| id in the manifest | old `table_of/1` | reality |
|---|---|---|
| `index:idx_calendar_events_owner_starts_at` | `"idx_calendar_events_owner_starts_at"` | an index |
| `sequence:phoenix_kit_warehouse_goods_issues_number_seq` | `"…_number_seq"` | a sequence |
| `function:uuid_generate_v7()` | `"uuid_generate_v7()"` | a function |
| `extension:citext` | `"citext"` | an extension |

Counted against the generated manifest (`PhoenixKit.Migrations.ExpectedSchema`):

```
real tables in manifest:            161
distinct pseudo-"tables" produced:  627   (index 616 · sequence 6 · extension 3 · function 2)
```

**Why it matters.** This is not cosmetic, because of what the line is *for*. The PR added it
so an operator could see concentration — its own justification is "97 of 265 findings
concentrated in five warehouse tables … the one fact that makes the report actionable."
The concentration is computed from `length(tables)`, and every absent index contributed its
own one-finding row to that denominator. The `+N more tables` tail therefore reports a number
that can be several times the number of tables the schema even has, on precisely the run
where an operator is trying to judge whether the damage is localised or total. Missing tables
come with their indexes, so the inflation is worst exactly when the report matters most.
The top-6 rows are also wrong on their face — an index name is printed under `by table:`.

**Fix applied.** Restricted the tally to the four classes whose id is table-scoped by
construction (`table`, `column`, `constraint`, `seed`) and drop the rest, which is what the
existing comment already said it did. Recovering the table from an index *name*
(`idx_calendar_events_…` → `calendar_events`) was considered and rejected: that is guessing,
the one thing this tally must not do, and the manifest's index names do not follow a single
convention. Those findings remain fully visible in the `by kind:` line and in the per-finding
list above it; only the table attribution is withheld.

Made `table_of/1` a `@doc false` public seam, matching `exit_code/1` and `error_tag/1` in the
same file, and covered in `phoenix_kit_repair_test.exs`: the four table-scoped classes, the
four dropped ones, `object_id: nil`, plus a guard that enumerates the object classes the real
manifest emits and fails if the set changes — a new class added to the manifest would
otherwise silently rejoin the "invents a table" branch, which is unobservable from the report.

---

## BUG - MEDIUM — doctor's new module check drops unreadable modules when another is behind

**File:** `lib/mix/tasks/phoenix_kit.doctor.ex` — `check_module_schema_versions/1`

The new check's `cond` tests `pending != []` before `failed != []`, so a run with one module
behind *and* another whose coordinator raised reports only the first. The unreadable module
disappears from the report — no FAIL line, no WARN line, nothing.

The severity outcome is right (`:fail` outranks `:warn`), but the message is the whole
product of a doctor check, and this is a case of two orderings that must agree drifting
apart: both other consumers of the same `Modules.list/1` result surface `failed` **first**,
deliberately and with the reasoning written down —

- `StatusReport.next_action/3:99-103` — *"An unreadable module is NOT pending … But it must
  not report Ready either: its tables may well be behind"*
- `phoenix_kit.status.ex` `format_modules_summary/1:262-264` — `failed != []` is the first branch

An unreadable module is the one condition an operator cannot discover any other way; a behind
module at least shows up in `status` and in the next `update`.

**Fix applied.** `failed` is folded into the `:fail` branch as a suffix
(`"Behind: Boards V01 (code expects V02); version unreadable for Inbox. Run mix …"`) rather
than reordering the branches — the severity should stay `:fail`, since a behind module is the
actionable half, but neither fact should be lost.

---

## BUG - MEDIUM — the reworded repair message names a version that has nothing to be missing

**File:** `lib/phoenix_kit/migrations/repair.ex` — `ahead_of_schema_message/3` (as merged)

The rewrite is right about the problem (the old `N..comment` range overstated by everything
`take_while` never examined) and right to name the boundary instead. But the boundary it names
is computed as `lower + 1`, and that is not what `highest_fully_present_version/1` returns.

That helper returns the **`since` of the last consecutive present bucket** — a value drawn from
the bucket list, not an ordinal — so `lower + 1` is the first gap only where the list is
contiguous. Its own doctest is the counterexample (`comment_policy.ex:137-138`):

```elixir
CommentPolicy.highest_fully_present_version([{53, true}, {114, true}, {137, false}, {142, true}])
#=> 114        # the first version not all present is 137
```

The merged message renders that as *"V115 is the first version whose objects are not all
present"*. V115 may have no manifest objects at all — an operator who greps `since: 115,`
finds nothing and cannot reconcile the claim with the findings printed above it.

**Reachable, not theoretical.** `pad_vacuous_versions/3` makes the list contiguous only over
`floor..comment`; below the floor a version appears only if some object carries that `since`,
and the chain has 28 object-less versions, 18 of them below V114:

```
versions with NO manifest objects: 2 5 6 24 27 30 37 51 57 58 60 66 67 69 70 75 84 106
                                   121 124 130 142 153 156 157 160 161 163
```

Sub-floor drift is exactly the situation this message exists for — the PR's own field example
is a V35 gap. A first gap at V7 (V5, V6 object-less) reports "V5". And
`highest_fully_present_version([{53, false}])` returns `0`, so a first-bucket miss renders
*"V1 is the first version … cannot be confirmed past V0"* — V0 does not exist.

The net effect is smaller than the overstatement the PR removed, but it swaps a vague claim for
a precise wrong one, which is harder to discount when reading a report.

**Fix applied.** Added `first_gap_version/2` — find the first bucket after `lower` whose flag is
`false` in the already-computed `presence` list (available at the call site) — and thread it
through as a fourth argument. Falls back to `lower + 1` when no such bucket exists, which
`marker_cross_check/2` should make unreachable; this is an error message and must degrade
rather than crash a repair run.

---

## IMPROVEMENT - HIGH — `mix phoenix_kit.doctor` still prints "N failures" and exits 0

**File:** `lib/mix/tasks/phoenix_kit.doctor.ex` — `run/1` / `summary/1:1249-1264`

The PR's own framing is *"a tool that reports a problem and then exits 0"*, and doctor is
named in its title. It gained a check that returns `{:fail, …}` for a module sitting versions
behind — a deploy-blocking condition by the PR's own argument, and the motivating one — and
`summary/1` ends by printing `Fix the FAIL items above before running migrations.` and
returning `:ok`. The process exits 0. A deploy script that runs `mix phoenix_kit.doctor` gets
the same answer whether every check passed or six of them failed, which is the exact shape
`--exit-code` was added to `status` to remove, in the same PR.

`status` and `repair` both gate; doctor is now the only one of the three that cannot.

**Fix applied.** Added `--exit-code` to doctor, mirroring the pattern the PR established for
`status`:

- `exit_code/1` — public, documented, pure: `1` if any result is `:fail`, else `0`.
- `maybe_halt/2` — no-op unless the flag is passed; `exit({:shutdown, 1})`, matching
  `mix phoenix_kit.repair`'s `halt_with/1` rather than `Mix.raise/1`, since the failures are
  already printed in full above and re-raising would bury them under a second copy.
- Opt-in for the same reason `status --exit-code` is: an existing pipeline that runs doctor
  for its report must not start failing on an upgrade.

**Warnings deliberately do not gate.** Several `:warn`s fire on healthy installs — a pool
capped to 2 by `update_mode` (which doctor itself sets), an `application.ex` the child-order
check could not locate, `update_mode=true`. Gating on those would make the flag permanently
red, i.e. back to a signal nobody can act on. Pinned by a test.

New `test/mix/tasks/phoenix_kit_doctor_test.exs` covers all-pass, empty, any-fail,
warnings-only, fail-among-warnings, and the `run_check/2` rescue shape
(`{:fail, "Exception: …"}`) — a crashed check must not pass a deploy.

---

## Verified correct (checked, not assumed)

- **`staged_module_note/1` reads `& &1.name` off `write_pending_module_migrations/2`.** That
  returns `Enum.flat_map` over `write_module_migration/3`, which returns `[entry]` on success
  and `[]` on a write failure (`update.ex:1016-1027`) — entries, not paths. Correct, and the
  failure path correctly omits modules whose file could not be written.
- **The abort path's advice is now true.** `module_migrations_dir/0` resolves to the *host
  repo's* `priv/…/migrations` (`update.ex:1189-1194`), which is the directory
  `mix ecto.migrate` reads, so `"Either command above applies them"` holds. The core
  migration file is written earlier in the same run and sorts ahead by timestamp, so ordering
  is right too. `generate_module_migration/3`'s `Path.wildcard` guard means a later
  `--yes` re-run reuses the staged file instead of writing a duplicate — as claimed.
- **`stage_module_migrations/1`'s `rescue` + `catch :exit`** is the correct pair per
  CLAUDE.md (unreachable DB *raises* on an unowned checkout, *exits* on a dead pool), and it
  is the right call here: this runs on a path that is already failing, and a connection error
  must not replace the migration advice.
- **`exit_code/2`'s fail-closed clause ordering** — `{:ready, _}, :not_queried` before
  `{:ready, _}, _` before the catch-all. Correct, and the reasoning holds: `module_entries/2`
  returns `:not_queried` for any `database_status` that isn't `{:connected_with_tables, _}`,
  while `installation_status` is read independently, so the two really can disagree in one run.
- **`[]` vs `:not_queried`** stays distinct end to end (`module_entries/2:235-238`,
  `module_tree_rows/1:250-251`, `next_action/3:90-94`) — a core-only install still passes the gate.
- **`ahead_of_schema_message`'s reasoning** about `take_while` semantics is correct, in both the
  dry-run and post-repair voices, and the "re-run to confirm" advice follows from them — only
  the version number it names was wrong (above).
- **`locale_slug ~> 0.2.0`** — three-segment pin preserved, `mix.lock` updated to the matching
  0.2.0 hash. The stored-slug exposure argument is correct: nothing re-derives a persisted
  slug in this tree.

## NITPICK — not fixed, recorded

- **`Modules.list/1` returns `[]` both for "no modules" and "discovery itself failed"**
  (`modules.ex:65-67`, `discover/0`'s `rescue → []`). Doctor's new check therefore reports
  `{:pass, "No installed module owns migrations."}` when beam scanning failed on a host that
  *does* have modules — a silent pass of exactly the kind this PR is closing. `status` solved
  the analogous problem by distinguishing `:not_queried` from `[]`, but that distinction is
  about the *database*, not discovery, so doctor cannot reuse it. Fixing it properly means
  giving `list/1` a third return shape, which touches every caller; out of proportion to a
  post-merge review, and left for whoever next works in that module.
- **`write_pending_module_migrations/2` prints `⏳ Boards: V01 → V02` on the abort path**,
  where nothing is being migrated — the file is written and the task then raises. Slightly
  misleading, but threading a caller-specific label through the shared writer costs more
  clarity than the emoji does. The note in the raise text says plainly what happened.
- **The doctor moduledoc's "Checks Performed" list was four checks stale** and the PR added a
  fifth without updating it. Rebuilt the list against `run/1`'s actual order while adding the
  `--exit-code` docs (it was missing UUID Primary Keys, User Dashboard, Sitemap
  Discoverability and Demo Auth Pages in addition to the PR's new Module Schema Versions).

## Gate

`mix precommit` — compile (warnings as errors) + `deps.unlock --check-unused` + `quality.ci`
(format-check, credo --strict, dialyzer) + JS tests.
