# PR #694 Review — Stop reporting a comment-less database as version 1

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/694
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`e9dc1abf`, branch `fix/migration-review-findings` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 9 files, +186 / −24, 3 commits.

---

## Verdict

**Good PR, and unusually well self-corrected.** The headline fix is real: a
database that is current but has lost its version comment used to report
`{:current_version, 1}`, which is below the floor, so `mix phoenix_kit.update`
answered *"install the 1.7.x bridge first"* — the one instruction
`Postgres.migrated_version/1` refuses to give because the bridge's backfill
invents uuids for still-NULL tracked columns and then deletes the rows that
match no user. Two halves of one release disagreed about one state and the
operator met the destructive half first.

The third commit (`c661f1b9`) is the notable one: Tim found that his own first
commit fixed the wrong function — `check_installation_status/1` consults
`migrated_version_runtime/1` first, which *guesses* 1 for a comment-less table,
so the rewritten fallback was never reached and the new `{:unknown_version}`
clause was dead for exactly the state it was written for. He also found that the
new atom crashed `mix phoenix_kit.status` through a `StatusReport.next_action/3`
clause he had not extended. Both are documented plainly in the commit message,
including "the fix landed on the wrong one".

I verified the claims rather than reading them:

| Claim | Verified |
|---|---|
| All three consumers now handle `{:unknown_version}` | `rg` across `lib/` — `status.ex` (2 sites), `update.ex`, `status_report.ex`; and `check_installation_status/1` has only those two lib callers |
| The reordered V163 deferral isn't a dead end | `repair_uuid.ex:93` does check `UUIDIntegrity.castable?/3`, so a big *and* uncastable table is still diagnosed at the deferral target |
| `estimated_rows` is catalog-only, `castable?` is a full scan | `uuid_integrity.ex:125` — the reorder is a genuine saving, not a cosmetic swap |
| `contype = 'f'` matters | Without it a same-named CHECK reads as present, the guarded ADD raises 42710 into `EXCEPTION WHEN OTHERS`, and the result is reported `:created` with no FK — correct diagnosis |
| The test count | `mix test test/phoenix_kit/install/` — **86 tests, 6 doctests, 0 failures**, independently reproduced |
| The new test actually bites | `next_action({:unknown_version}, …)` has no fallback clause, so removing it is a `FunctionClauseError`, as claimed |

Three findings worth fixing — one leaves `mix precommit` **red on main**, one
leaves the PR's headline fix inert on a supported configuration — three worth
recording, and one note that changes tomorrow's release decision.

---

## BUG - HIGH — `action()` was not extended, and dialyzer fails on main

**Files:** `lib/phoenix_kit/install/status_report.ex`, `lib/mix/tasks/phoenix_kit.status.ex`

```
lib/mix/tasks/phoenix_kit.status.ex:420:8:pattern_match
The pattern can never match the type.

Pattern: {:fix_version_comment, _message}

Type:
  {:check_modules, [binary()]} | {:fix_connection, <<_::504>>}
  | {:install, <<_::248>>} | {:ready, <<_::40>>}
  | {:update, <<_::64, _::size(8)>>, [<<_::64, _::size(8)>>]}
```

`next_action/3` is `@spec`'d to return `action()`, and `action()` was never
given the new `{:fix_version_comment, String.t()}` member (nor was its
`@typedoc` bullet list). Dialyzer takes the spec as authoritative, concludes the
function cannot return that tuple, and therefore proves the brand-new
`format_next_action({:fix_version_comment, message})` clause unreachable.

Two things make this worth the HIGH:

1. **It is red right now.** `mix precommit` runs `quality.ci`, which runs
   dialyzer, and it exits 2 on `main` as merged. Every subsequent PR inherits a
   failing gate, and `mix prerelease` — already blocked on the stale manifest —
   would have been blocked on this too.
2. **It is the same omission as the finding below, one level up.** The docstring
   list, the type union and the consumer clause sets are three copies of "what
   states exist"; this PR added a state to one and a half of them. The type
   union is the copy that a tool checks, which is why this one announced itself
   and the others did not.

The PR notes verification as "`mix compile --warnings-as-errors`,
`mix format --check-formatted` and `mix credo --strict` — clean". That is three
of the four things `precommit` runs; dialyzer is the fourth, and it is the only
one that could have caught this.

**Fixed:** `{:fix_version_comment, String.t()}` added to `action()` and to the
typedoc. Dialyzer back to `222 errors, 222 skipped`, exit 0.

---

## BUG - HIGH — the new guard fails OPEN, so the headline fix does not apply on every host

**File:** `lib/phoenix_kit/install/common.ex`

Does #694 fix the comment-less database? **For the common configuration, yes** —
I traced it end to end rather than trusting the corrected commit message:
`check_version_with_runtime_repo/2` really does return `1` for a comment-less
table (`postgres.ex:903`), so the re-check fires and `{:unknown_version}` comes
out. The unparseable-comment case is covered too, by a different route
(`parse_version_comment_leniently/2` returns `0`, which falls through to
`check_alternative_version_detection/2`, which has its own `:unknown_version`
clause).

But the guard is written as a positive test for one specific answer:

```elixir
current_version == 1 and try_direct_database_version_check(opts) == :unknown_version ->
```

It fires only when the re-check *positively reports* "there is no comment".
Every way of **failing to answer** falls through to `{:current_version, 1}` —
below the floor — and the operator is told to install the 1.7.x bridge. The one
check standing between a comment-less database and the destructive advice is
fail-open.

That is reachable, not theoretical, because the two halves of the `cond` resolve
the repo differently:

| Call | Repo resolution |
|---|---|
| `migrated_version_runtime/1` (produces the `1`) | `Postgres.get_repo_with_fallback/0` — config, **then** start the app, **then** auto-detect from the Mix project |
| `try_direct_database_version_check/1` (the guard) | `Config.get(:repo, nil)` — config only |

On a host that never sets `config :phoenix_kit, repo:` and relies on
auto-detection — a supported setup, which is why strategies 2 and 3 exist — the
first finds the repo and returns `1`, the second finds nothing and returns `0`,
`0 != :unknown_version`, and the guard silently does not fire. The PR's headline
fix is inert there. The same is true for any transient failure of that second
query, which is worth noting given the PR reports the shared PostgreSQL "at its
connection ceiling all day".

This is the same shape as the mistake `c661f1b9` corrected — a guard and the
thing it guards reaching the database by different routes — one level further
down.

**Fixed:** inverted to `not comment_literally_says_one?(opts)`, so
`{:current_version, 1}` requires an affirmative "the comment reads 1" and every
other outcome is `{:unknown_version}`. Fail-closed is right here because the
errors are asymmetric: a genuine V01 install sent to `doctor` first loses a
minute and then learns the truth; a current database sent to the bridge has its
still-NULL tracked columns backfilled with invented uuids and the rows deleted
for matching no user.

Not covered by a test — `check_installation_status/1` needs a live database, and
none is reachable here. Worth adding when one is.

---

## IMPROVEMENT - MEDIUM — the return-value contracts were not extended with the new state

**File:** `lib/phoenix_kit/install/common.ex`

`check_installation_status/1` gained a fourth return value. Its `@doc` still
enumerates three:

```
  - `{:not_installed}` …
  - `{:current_version, version}` …
  - `{:unreachable, reason}` …
```

`check_update_needed/2`'s `## Returns` list is the same story — four entries,
`{:unknown_version}` absent, even though the function grew a passthrough clause
for it in this PR.

That list *is* the contract. It is what a caller reads to decide which clauses
to write, and this PR already paid for it being wrong: the crash Tim fixed in
`c661f1b9` was `StatusReport.next_action/3` missing a clause "in a module I
never opened". An exhaustive docstring is the cheapest thing that turns "which
modules match on this?" from an `rg` expedition into a read. The next state
added here will have the same problem.

**Fixed:** both lists now include `{:unknown_version}` with the reason it cannot
be folded into its neighbours (both of them route a caller somewhere that
writes), and `check_installation_status/1`'s doc records that the list is
exhaustive on purpose, naming the consumer that crashed when it wasn't.

---

## NITPICK — `check_update_needed/2` has no callers

Nothing in `lib/` or `test/` calls it; the `{:unknown_version}` clause added to
it in this PR is dead code, and its whole clause set is unexercised by the
suite. It is public API a host could be using, so removing it is not obviously
right — but "it's handled there too" should not be mistaken for coverage.

**Noted in the docstring** rather than changed, so the next person extending
`check_installation_status/1` knows this sibling needs updating by hand.

---

## NITPICK — three version-comment parsers, three accepted sets

The PR adds a second non-raising parser next to the existing two:

| Reader | `"164"` | `"0"` / `"-5"` | `"v164"`, `"164abc"`, `"1_6"` |
|---|---|---|---|
| `Postgres.parse_version_comment!/2` (migrator, strict) | 164 | **accepted** | raises, with restamp instructions |
| `Repair.Probe.read_comment/2` (this PR) | 164 | **accepted** | `nil` |
| `Common.parse_version_comment/1` (this PR) | 164 | **`:unknown_version`** | `:unknown_version` |

Measured, not inferred. The garbage cases agree — the raise-vs-report split is
deliberate and documented. The divergence is non-positive integers, where the
strict migrator would take `'0'` as a version and plan a fresh install over it
while `Common` refuses. `Common`'s answer is the safer one, so nothing needs
changing today; three independent definitions of "what is a version comment" is
just how they drift apart later.

---

## NITPICK — the strict re-check rescues to `0`, which re-opens the bug for one query

```elixir
current_version == 1 and try_direct_database_version_check(opts) == :unknown_version ->
```

`try_direct_database_version_check/1` ends in `rescue _ -> 0`. So if
`migrated_version_runtime/1` returns its guessed `1` and the immediately
following strict query fails transiently, the cond falls through to
`{:current_version, 1}` — the precise output this PR exists to prevent.

Narrow (it needs one query to succeed and the next to fail), and it degrades to
the previous behaviour rather than to something new, so it is not worth a guard
of its own. Recorded because the comment above the clause reads as though the
re-check is authoritative, and on error it is silently not.

---

## Note for the 1.7.237 release — these two edits are restamp-safe

`chain_hash` was already stale before this PR (see the #692 review). #694 edits
`v163.ex` and `v164.ex`, so it moves again — but **both edits are of the kind
`restamp_chain_hash.exs` explicitly permits**:

- V163 swaps the order of two `cond` branches. No SQL object changes.
- V164 adds `AND c.contype = 'f'` to a **detection** query. No SQL object changes.

That is the script's own criterion — "repair logic that acts on an
already-declared object". So the restamp-vs-regenerate decision waiting for
tomorrow is unchanged in shape: **V165 and V166 remain the only versions that
add manifest objects**, and they are the only reason a plain restamp
under-declares anything.

---

## Verified and left alone

- **The V163 reorder's changed message for a big, uncastable table.** It now reports "too large, run `mix phoenix_kit.repair_uuid`" where it used to report the bad data. Not a dead end — `repair_uuid` checks castability itself — and the alternative was paying a full sequential scan on precisely the tables the size guard exists to keep out of `mix ecto.migrate`.
- **`bridge_version/0`.** Correct fix for a real inconsistency: the below-floor notice is emitted at generation time, before either `BelowFloorError` raise site, so it could not have named the version those raises do.
- **`Probe.read_comment/2` accepting a partial parse.** It does not — `{n, ""}` rejects `"164abc"`. The docstring's "never raises" promise now holds.
- **The `{:unknown_version}` 1-tuple.** Odd next to a bare atom, but consistent with the `{:not_installed}` already in this contract.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit/install/status_report.ex` | `{:fix_version_comment, String.t()}` added to `action()` and its typedoc — unblocks dialyzer |
| `lib/phoenix_kit/install/common.ex` | the comment-less guard fails closed: `{:current_version, 1}` now requires an affirmative "the comment reads 1" |
| `lib/phoenix_kit/install/common.ex` | `check_installation_status/1` and `check_update_needed/2` docs list `{:unknown_version}`; the former records that the list is exhaustive by design and what happened when a consumer missed it; the latter records that it has no callers |

## Gate

`mix precommit` — format, `compile --warnings-as-errors`,
`deps.unlock --check-unused`, `credo --strict`, dialyzer, JS tests: **passing
after the fix above** (it failed on `main` as merged).
`mix test test/phoenix_kit/install/` — **86 tests, 6 doctests, 0 failures**
(unit tests, no database required, so these genuinely ran).

One cosmetic leftover, not chased: dialyzer reports `Unnecessary Skips: 3` where
it reported 2 before today's PRs. It does not fail the build, and it is not the
`mentions/users.ex` entry #692 added — I tested that by deleting it, and
dialyzer goes red without it, so that entry is load-bearing. Which of the three
is now redundant would need `list_unused_filters` to actually print its list.
