# PR #689 — Squash the migration chain at floor V135, verify-and-repair, V164

**Merge:** `cbf70fee` (into `main`, 2026-08-09) · **Author:** timujinne ·
**Scope:** 227 files, +139 665 / −26 063 (≈95 % generated: the V135 baseline,
`expected_schema.ex`, and the `dev_docs/squash/` reference dumps)

**Verdict: the code is sound and unusually well-argued, but this is NOT ready
to publish today.** Two of the blockers are mechanical and are fixed in this
pass; the two that remain are the maintainer's calls and cannot be closed from
inside the repo.

---

## Summary of findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | BUG - HIGH | `ensure_uuid_v7_function/1`'s privilege `rescue` is dead code in migration context — a DBA-owned function now aborts every migration | **Fixed** |
| 2 | BUG - HIGH | `ExpectedSchema.chain_hash/0` stale at merge HEAD — `release_check` and 2 unit tests fail | **Fixed** |
| 3 | IMPROVEMENT - MEDIUM | V164 warns "reconcile by hand" about the one FK it then repairs itself | **Fixed** |
| 4 | IMPROVEMENT - MEDIUM | `BelowFloorError.bridge_version` never populated — the most operator-facing message in the release is vague | **Fixed** |
| 5 | NITPICK | Five stale doc blocks left from the pre-squash draft (floor "is 1", manifest "does not exist yet") | **Fixed** |
| 6 | BLOCKER - release | Equivalence evidence (21 PASS) predates HEAD; no DB in this environment to re-run it | **Open — maintainer** |
| 7 | BLOCKER - release | Module ecosystem pins `~> 1.7.x`: `2.0` is a hard resolver conflict for every host using a feature module | **Open — maintainer** |
| 8 | IMPROVEMENT - HIGH | No CHANGELOG / no `@version` bump (author deliberately left both) | **Open — maintainer** |

---

## What the PR does, and whether the design holds up

Three independent things landed together:

1. **The squash.** `V01`..`V134` → one generated `V135` baseline (11 364 lines
   of DDL emitted by `dev_docs/squash/generate_baseline.exs`), floor raised to
   135, below-floor databases refused with `BelowFloorError` instead of a
   silent partial replay.
2. **The repair engine.** `PhoenixKit.Migrations.Repair` + a 67 k-line
   generated manifest, `mix phoenix_kit.repair`, and a new non-fatal
   `mix phoenix_kit.doctor` check.
3. **V164** — repair for the V56/V57 flush-order defect (≈46 columns left
   nullable, ≈67 of 70 declared FKs never created on single-shot installs),
   plus two prefix-unsafety convergences folded in.

The routing rewrite is the part that most deserved scrutiny and it holds up.
`plan_up/3` and `plan_down/3` are pure, floor-parameterised, and unit-tested at
synthetic floors — the right shape for logic whose only other testing surface
is a live database. I walked the interesting cases by hand:

- fresh install (`initial == 0`) clamps up to the floor, so a below-floor-pinned
  consumer wrapper (`up(version: 78)`) still yields `135..135` rather than
  dispatching deleted modules;
- teardown appends the floor as an explicit list element rather than extending
  the range across it (`postgres.ex:516`) — the deleted-module trap, correctly
  avoided;
- the `target <= 0` guard (rather than `== 0`) closes the negative-target path
  that would drop every table and *then* dispatch `V134..V1`.

`migrated_version/1` becoming a raise on a missing/garbage comment is the right
call and is correctly split from the lenient `migrated_version_runtime/1` — I
checked every caller: only the migrator uses the raising twin; `status`,
`doctor`, the dashboard and the installer all go through the lenient one.

The V135 baseline carries 88 `fk_*` constraints and deliberately leaves
`phoenix_kit_users_tokens.user_uuid` nullable with the V64 CHECK reasoning
inline — i.e. the generator was fed a *correctly flushed* replay, not one that
reproduced the V56/V57 damage into the baseline. That was my main worry about
the whole approach and it is answered.

---

## BUG - HIGH #1 — the privilege rescue that can never fire

`lib/phoenix_kit/migrations/postgres/helpers.ex`

This PR removed `ensure_uuid_v7_function/1`'s `unless uuid_v7_function_exists?`
guard so a stale function body can be refreshed — a good change — and added a
`rescue` to keep the hardened-install case safe:

```elixir
defp do_ensure_uuid_v7_function(repo, prefix, executor) do
  executor.("CREATE OR REPLACE FUNCTION ...")
  :ok
rescue
  error ->
    if insufficient_privilege?(error) and uuid_v7_function_present?(repo, prefix) do
      IO.warn(...)   # "Leaving it in place"
```

In migration context `executor` is `Ecto.Migration.execute/1`, which only
**queues** the statement. The `insufficient_privilege` error is raised at flush
time, outside this function — the `rescue` never sees it, and the migration
aborts. The rescue only works for the runtime `ensure_uuid_v7_function/2`
variant that calls `repo.query!/3` directly. This codebase knows the
distinction well (it is the entire subject of V164), which is what makes it
easy to miss here.

**Why it matters:** the aborting topology is one this project *documents and
recommends*. `PhoenixKit.Migration`'s moduledoc tells operators with a
DBA-owned schema to "have the DBA grant `CREATE` for the migration **or
pre-create the function in the schema**", and the helper's own comment cites a
real 2026-07-12 field report of exactly that. Worse, `up/1`'s `{:run_delta, _}`
branch calls this helper on **every** delta upgrade, so it is not confined to
fresh installs: the first `mix ecto.migrate` after upgrading on such a host
fails, on a release whose headline feature is that upgrades are now stricter.

**Fix applied:** exclude the un-ownable case *before* the statement is queued,
with one immediate catalog read using the same test Postgres itself applies:

```elixir
SELECT NOT pg_catalog.pg_has_role(p.proowner, 'USAGE')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proname = 'uuid_generate_v7' AND n.nspname = $1
```

Absent function or unreadable catalog both answer `false`, so the create is
still queued and a genuine failure still surfaces. A function owned by a role
the migrating role is a member of still gets its body refreshed — the
self-healing the PR wanted is preserved; only the case that cannot possibly
succeed is skipped, with a warning. The rescue is kept for the runtime variant.

*(A `DO $$ … EXCEPTION WHEN insufficient_privilege $$` wrapper would also work
regardless of queueing, but the function body is already `$$`-quoted, so the
dollar-quote tags would have to be reworked — more churn for no benefit.)*

---

## BUG - HIGH #2 — stale `chain_hash`, and a red test suite

`ExpectedSchema.chain_hash/0` is the manifest's staleness detector: a SHA-256
over the sorted `postgres/v*.ex` set, asserted by `release_check` and by a unit
test. At merge HEAD it was stale, and this is not a theoretical concern —
`mix phoenix_kit.release_check` on the merge commit:

```
FAIL Migration Version Sync
     PASS current_version/0 == v164.ex
     PASS min(vNN.ex on disk) == initial_version/0 (V135)
     PASS V135..V164 contiguous (30 versions), every module loadable
     FAIL PhoenixKit.Migrations.ExpectedSchema.chain_hash/0 is stale …
```

and `mix test` (the **unit** half — no database required) returned exit 2 with
two failures, both this hash.

**Cause:** merge ordering, not carelessness. The branch restamped the hash at
`bc3bae06` over its own copy of `v163.ex`; `main` had meanwhile advanced to
`1aea3d28`, which edits `v163.ex`. The merge took the newer file and kept the
older stamp. This is precisely the drift the detector is designed to catch, and
it caught it — after the merge button, which is why it reached `main`.

**Fix applied:** restamped via `dev_docs/squash/restamp_chain_hash.exs
--restamp` (30 files). The restamp is legitimate because I confirmed exactly
which `v*.ex` bytes changed since the stamp, and neither adds or alters a
manifest object: `1aea3d28` widens V163's two-million-row size guard to cover
every repair class (guard and logging only), and my V164 change filters one
warning. The manifest header now records this explicitly rather than leaving a
future reader to re-derive it.

**Note the limit, because the script says so itself:** a restamp asserts nothing
about the manifest *body*. See finding #6.

---

## IMPROVEMENT - MEDIUM #3 — V164 warns about the FK it is about to fix

`lib/phoenix_kit/migrations/postgres/v164.ex`

`fk_constraints/0` contains `{:phoenix_kit_comments, "user_uuid", …, "SET
NULL"}`, so on a damaged install the generic pass (item 2) sees the live
constraint with V72's guessed `ON DELETE CASCADE`, classifies it
`:mismatched_action`, and emits:

> …is already enforced by `fk_comments_user_uuid` with ON DELETE CASCADE, but
> this chain declares ON DELETE SET NULL. **Left untouched** — … Reconcile by
> hand …

Item 3, ten lines later in the same run, drops and re-adds it `SET NULL`. The
statement is false, and it is false about the single named defect the whole
migration is best known for — an operator reading the deploy log comes away
believing manual work is outstanding when it is not.

**Fix applied:** `adopted_fk/7` now carries the constraint name in its outcome
tuple, and the mismatch report excludes `@comments_constraint` — the one entry
item 3 owns by name. A *differently*-named FK enforcing the same pair is still
reported, which is correct: item 3 only looks for the constraint by name.

---

## IMPROVEMENT - MEDIUM #4 — the bridge message never names the bridge

`BelowFloorError` has a `:bridge_version` field documented as "`nil` until that
release is tagged". It is tagged (`v1.7.236` exists — `release_check`'s tag
collision check confirms it), but neither raise site passed it, so every
below-floor operator got the fallback wording: *"Install the last PhoenixKit
1.7.x release (the migration bridge)"* — and then had to go find out which one
that was.

This is the highest-stakes message in the release: it is what a host stuck at
V01..V134 sees instead of an upgrade, and getting it wrong means picking a
release that does not carry the chain.

**Fix applied:** `@bridge_version "1.7.236"` in `postgres.ex`, threaded into
both raise sites. The message now reads "Install PhoenixKit 1.7.236 (the
migration bridge)". The struct default stays `nil`, so
`below_floor_error_test.exs`'s explicit `bridge_version == nil` assertion still
holds. Bump the constant only if another 1.7.x ships after the 2.0 cut — naming
an earlier 1.7.x remains correct advice, since every 1.7.x carries the whole
pre-squash chain.

---

## NITPICK #5 — doc blocks left behind by the squash itself

Five places still describe the world as it was before the floor moved. Two
actively contradict themselves inside one paragraph:

- `repair/comment_policy.ex` — "the below-floor branches below are LIVE, not
  hypothetical: `classify/3`'s `:below_floor` branch is unreachable today (no
  integer satisfies `0 < comment < 1`)". Both halves in one sentence.
- `phoenix_kit.update.ex` — "Was dormant while `initial_version/0` is 1 …
  `current_version` can never land here today". It lands there now.
- `phoenix_kit.repair.ex`, `phoenix_kit.doctor.ex`, `phoenix_kit.release_check.ex`
  — all three still say the manifest "does not exist until the squash PR (P3)".
  It ships in this PR.

**Fixed**, rewritten to describe the shipped state and to say what the
not-generated branch is actually for now (a checkout where the manifest was
removed or overridden via `:expected_schema_module`).

The two stale-text items the PR description flagged as outstanding
(`v164.ex`'s moduledoc naming `v163_relaxed_columns_test.exs`, and the
`IO.warn` saying "the version comment now reads 163") were **already fixed** in
`bc3bae06` — verified at HEAD, no action needed.

---

## BLOCKER #6 — the equivalence evidence predates HEAD

This is the finding that decides "safe to release", and it is the author's own
open item #3, restated because it is still open.

The claim that a squashed install equals a pre-squash install is carried by
`verify.exs` S1/S2 — a normalized `pg_dump` and seed-row diff against
references built on the bridge checkout. That is exactly the right oracle. The
reported **21 PASS / 0 FAIL** run is from 2026-08-08 and predates:

- the renumber of the repair delta to V164,
- the merge that brought V163 in,
- `1aea3d28`'s V163 changes,
- and now my four fixes.

Of those, only my V164 edit and `1aea3d28` touch executable migration code, and
neither changes emitted DDL. But "reasoned about" is not what this doc's own
COVERAGE.md accepts — *"Every claim below was observed, not reasoned about"* —
and I agree with that standard for a migration squash.

**I could not close this here: there is no PostgreSQL in this environment**
(`psql`/`pg_isready` absent, `localhost:5432` refused). The 1 270 excluded
integration tests are precisely the ones that would exercise the chain. So:

- ✅ `mix precommit` passes (compile `--warnings-as-errors`, `deps.unlock
  --check-unused`, format, `credo --strict`, dialyzer, JS tests)
- ✅ `mix test` unit half green after fix #2 (1 919 tests, 38 doctests)
- ❌ **nothing has run a single line of this chain against a database in this
  review**

**Required before publishing** — a full `verify.exs --mode b` run against
current HEAD, plus the `--mode a` (public-schema) S1/S2 pass, and the manifest
regenerated if anything moves. `s7,s8` at minimum for the manifest body, since
the restamp deliberately asserts nothing about it.

---

## BLOCKER #7 — the module ecosystem cannot resolve `2.0`

Re-verified in `/www` at review time. Of 33 `phoenix_kit_*` packages, every one
that pins core pins it below 2.0:

| Module | Pin |
|---|---|
| `phoenix_kit_customer_support` | `~> 1.7.189` |
| `phoenix_kit_document_creator` | `~> 1.7.189` |
| `phoenix_kit_user_connections` | `~> 1.7.189` |
| `phoenix_kit_posts` | `~> 1.7.214` |
| `phoenix_kit_legal` | `~> 1.7.227` |
| `phoenix_kit_emails` | `~> 1.7.231` |
| `phoenix_kit_newsletters` | `~> 1.7 and >= 1.7.211` |

`{:phoenix_kit, "~> 2.0"}` plus **any** of these is an unsatisfiable dependency
for the host — `mix deps.get` fails outright; there is no degraded mode. None
of them call migration internals, so each needs only a widened pin and a patch
release, but that is a coordinated wave that has to land *before or with* the
2.0 publish, not after. Publishing 2.0 first strands every host running a
feature module.

> **This last sentence is wrong** — see "CORRECTION — core publishes FIRST" in
> the second pass below. Publishing core 2.0.0 first strands nobody: a host on
> `~> 1.7` cannot resolve to 2.0 at all. Left here as written, because the
> conclusion it fed into (ship 2.0.0) was reached partly by weighing a cost that
> does not exist.

(`phoenix_kit_legal` also still owes its unpublished 0.1.10 — worth folding
into the same wave.)

---

## IMPROVEMENT - HIGH #8 — version and CHANGELOG

`mix.exs` is at `1.7.236` and `CHANGELOG.md`'s top entry is `1.7.236` (PR
#688's). The author deliberately left both alone as maintainer-owned, which
matches this project's convention — but nothing ships until they move, and
`release_check` currently also fails on `Tag v1.7.236 already exists`.

The breaking upgrade contract (below-floor installs refused, not migrated)
argues for `2.0.0`. I have not written the entry, since it needs the target
version decided first and it should describe the ecosystem sequencing in #7.

---

## What I checked and found clean

Recorded so a later pass does not redo it:

- **No dangling references** to any deleted `V01`..`V134` module anywhere in
  `lib/` or `test/`; `PhoenixKit.Migrations.UUIDRepair` (deleted) has no live
  callers — `phoenix_kit.update.ex`'s pre-migration `run_uuid_repair/1` was
  removed with it, correctly (its sub-V40 gate is unreachable above the floor).
- **PR #688's content survived the merge intact** — `git diff 1aea3d28 HEAD`
  over V163, `uuid_integrity.ex`, `repair_uuid.ex` and its integration test is
  empty; only `doctor.ex` differs, by the squash's own added check.
- **Prefix safety** in V164's new SQL follows CLAUDE.md's rules throughout:
  bare index names on `CREATE`, qualified on `DROP`, `schemaname`/`table_schema`
  /`nspname` anchors on every existence probe, no `::regclass` casts in
  immediate checks. `fk_shape_present/5` anchors the *referenced* relation's
  schema too — a subtle one, and it is there.
- **`Repair.Probe.snapshot/2`** is 7 catalog queries total, not per-object, and
  restores `search_path` in an `after` on a pooled connection it borrows —
  so the new `doctor` check is cheap and does not poison the pool.
- **`Repair.Executor`** is genuinely additive: no `DROP`/`ALTER TYPE`/`DELETE`
  verb anywhere, and the single `UPDATE` only targets `IS NULL` on a column the
  same call just added. `--dry-run` cannot write *by construction* (the pure
  `create_action/2` half takes no repo), not by discipline.
- **`on_delete_char/1`** has no catch-all clause, but `fk_constraints/0`
  contains only `CASCADE`/`RESTRICT`/`SET NULL` — all covered. Left as-is: a
  `FunctionClauseError` on an unhandled action is the correct outcome for a
  repair migration.
- **`mix phoenix_kit.consolidate_wrappers`** deletes host migration files but
  is dry-run by default (`--apply` required), is never invoked automatically,
  and refuses on interleaved foreign migrations. Appropriately gated.
- **`validate_prefix!/1`**'s new 20-byte cap is justified by a measured failure
  (repair never converges past a 21-byte prefix) and is backed by a DB-free test
  that fails if a longer embedded object name ever ships.

---

## Recommendation

Do not publish yet. In order:

1. Run `verify.exs` (`--mode b` full matrix, `--mode a` S1/S2) against current
   HEAD on a real database. Regenerate the manifest if anything moves.
2. Land the ~7 module pin-widening releases, or at least stage them to publish
   in the same window.
3. Decide `2.0.0`, write the CHANGELOG entry, bump `mix.exs`.
4. `mix phoenix_kit.release_check` must come back fully green (the
   `chain_hash` FAIL is fixed; `Tag Collision` clears with the bump).

Once (1) is observed rather than reasoned about, this is a good release. The
engineering is careful, the honesty in the PR description is unusual and
correct, and the parts I could verify statically hold up under scrutiny. The
risk that remains is not in the design — it is that the strongest evidence for
it was gathered against a tree that is no longer the tree being shipped.

---

# Second pass — 2026-08-09, cutting 1.7.237

Re-opened while assembling the release, because #689 turned out to be in it and
had no CHANGELOG entry. This section only records what changed since the review
above; the findings there stand as written.

## The five mechanical findings are fixed

All landed in #690's `b3ef57b2` and are verified in
`690-security-p1-and-squash-review-fixes/CLAUDE_REVIEW.md` — including a
specific check that the `bridge_version` fix reached every raise site (it does:
`:ensure_current` re-raises the existing struct rather than building a new one).

## BLOCKER #7 is resolved — by the version number, not by a code change

The finding was that `{:phoenix_kit, "~> 2.0"}` is unsatisfiable alongside any
feature module. Re-verified in `/workspace` today; the pins have not moved:

| Module | Pin | Accepts 1.7.237? | Accepts 2.0.0? |
|---|---|---|---|
| `phoenix_kit_customer_support` | `~> 1.7.189` | ✅ | ❌ |
| `phoenix_kit_document_creator` | `~> 1.7.189` | ✅ | ❌ |
| `phoenix_kit_user_connections` | `~> 1.7.189` | ✅ | ❌ |
| `phoenix_kit_posts` | `~> 1.7.214` | ✅ | ❌ |
| `phoenix_kit_legal` | `~> 1.7.227` | ✅ | ❌ |
| `phoenix_kit_emails` | `~> 1.7.231` | ✅ | ❌ |
| `phoenix_kit_newsletters` | `~> 1.7 and >= 1.7.211` | ✅ | ❌ |

`~> 1.7.189` means `>= 1.7.189 and < 1.8.0`, so **1.7.237 satisfies all seven
and needs no coordinated wave at all.** Shipping as a patch release dissolves
the blocker rather than working around it.

## …but the version choice is a trade, and it was made by a `sed`

The first pass recommended `2.0.0`, on the grounds that refusing a below-floor
install rather than migrating it is a breaking upgrade contract. I bumped
`@version` to `1.7.237` while assembling this release **before reading this
review**, so that recommendation was overridden by accident rather than
decided. Both options have a real cost and the maintainer should pick knowingly:

**Shipping 1.7.237 (current state).** No module breaks. But a host still below
V135, pinned `{:phoenix_kit, "~> 1.7"}` — the pin the README tells people to
use — is auto-upgraded into the floor by a routine `mix deps.update`, and the
next `mix ecto.migrate` raises `BelowFloorError`. Recoverable and clearly
messaged (the error names 1.7.236 and the exact procedure since #690), but it is
a trap a patch bump walks them into with no opt-in.

**Shipping 2.0.0.** `~> 1.7` never resolves to it, so below-floor hosts are
never dragged across the floor unintentionally; they upgrade deliberately and
read the notes. Cost: all seven modules above need a widened pin and a patch
release, landing *before or with* the publish, or every host running one of them
has an unsatisfiable dependency.

My read at the time: 1.7.237 is the better trade, because the below-floor
failure is a refused migration with a precise remedy while the 2.0 failure is
`mix deps.get` refusing to resolve for a host that did nothing wrong.

## DECIDED: 2.0.0 (Tim, 2026-08-10)

The release ships as **2.0.0**, and the module pins are being widened the same
day so the ecosystem lands with it rather than after it. That removes the cost I
weighted most heavily — the unsatisfiable-dependency window is coordinated away
rather than endured — and it restores the property the patch-release route could
not offer: `{:phoenix_kit, "~> 1.7"}` does not resolve to 2.0, so no below-floor
host is carried across the floor by a routine `mix deps.update`. Given the pin
wave is happening anyway, this is the stronger of the two options and the first
pass's original recommendation was right.

`@version` is `2.0.0` and the CHANGELOG entry is retitled. Two consequences are
now recorded in the release notes that were not before: the major is *why*
below-floor hosts are protected, and feature modules need widened pins to
resolve at all. The earlier "a routine `mix deps.update` can drag a host across
the floor" warning was true of 1.7.237 and is **false** of 2.0.0 — it has been
replaced rather than left to mislead.

## CORRECTION — core publishes FIRST, and the pin wave follows

I wrote here, and in the first pass's blocker #7 above, that publishing core
2.0.0 before the module patch releases "strands every host running a feature
module" and that the wave must land "before or with" the 2.0 publish. **That is
wrong.** Max pushed back on it and was right.

Publishing core 2.0.0 first harms nobody, for exactly the reason this release is
a major in the first place (measured, not assumed):

| Requirement | accepts 1.7.237 | accepts 2.0.0 |
|---|---|---|
| `~> 1.7` | ✅ | ❌ |
| `~> 1.7.189` | ✅ | ❌ |
| `~> 1.7 and >= 1.7.211` | ✅ | ❌ |
| `~> 1.7.231 or ~> 2.0` | ✅ | ✅ |

A host on `{:phoenix_kit, "~> 1.7"}` plus any feature module is **untouched** by
2.0.0 existing on Hex — `mix deps.update --all` cannot pull it. The only host
affected is one who *deliberately* changes their own requirement to `~> 2.0`
while a module still pins `~> 1.7.x`, and what they get is a resolver error at
`mix deps.get` naming the conflict: opt-in, non-destructive, and self-explaining.
Nothing is stranded, and I had contradicted my own argument two paragraphs
earlier in the CHANGELOG, where the major's whole justification is that `~> 1.7`
does not resolve to 2.0.

**And core generally has to go first anyway.** A module cannot be published with
a bare `{:phoenix_kit, "~> 2.0"}` requirement until 2.0.0 exists on Hex —
`mix hex.publish` builds the package, and `mix deps.get` cannot resolve a
requirement no published version satisfies. The one way to invert the order is an
**OR** pin (`"~> 1.7.231 or ~> 2.0"`), which resolves against 1.7.x today and so
can ship before core; a module wanting to drop 1.7 support entirely must wait for
core.

So: **publish core 2.0.0, then the modules.** Cross-repo testing against
unpublished core is what `PHOENIX_KIT_PATH` / the `pk_dep/3` helper already
exist for (AGENTS.md, "Local cross-repo development"), so the modules can be
verified against 2.0 before it is public without needing it on Hex.

## BLOCKER #6 is still open

The equivalence evidence (21 PASS) still predates HEAD, and now predates it by
considerably more: V165, V166 and the V163/V164 edits from #694 have all landed
since. No PostgreSQL is reachable in this environment — nothing on 5432, no
`psql`, no container runtime — so `verify.exs` cannot be re-run here. This is
the same missing capability that blocks the manifest regeneration.

## Finding #8 is closed by this pass

`@version` is `1.7.237` and the CHANGELOG now carries an entry for this PR,
leading with the below-floor upgrade requirement.
