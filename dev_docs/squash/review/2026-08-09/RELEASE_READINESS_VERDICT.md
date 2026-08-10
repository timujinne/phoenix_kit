# Release-readiness verdict — PhoenixKit 2.0 (squash), 2026-08-09

Review of the brief in `RELEASE_READINESS_BRIEF.md`, performed by a read-only
Claude reviewer agent against commit `bc3bae06` (HEAD of `squash-migrations`,
merged upstream as PR #689). Recorded verbatim below, with one orchestrator
note appended at the end (the condition-4 root cause was found after the
reviewer wrote its report).

---

## Release-Readiness Verdict: GO WITH CONDITIONS

**Commit reviewed:** `bc3bae06` (HEAD of `squash-migrations`, merged as PR #689)

### Verdict: GO WITH CONDITIONS

The code, migration chain, and verification are release-ready. Four conditions
must be resolved before `mix hex.publish`, ordered by priority. None require
code changes to the migration chain itself.

### Conditions (ordered, each with who)

**1. Widen sibling module pins BEFORE publishing core 2.0.0** — *Maintainer*

This is the item the brief flagged as the potential actual blocker.
**Confirmed: it IS a hard coordination constraint.**

- Every sibling module on Hex pins `~> 1.7.x` (e.g. `~> 1.7.189`), which means
  `>= 1.7.189 and < 1.8.0`. Version `2.0.0` cannot satisfy any of these ranges.
- A consumer who depends on `{:phoenix_kit, "~> 2.0"}` AND any current module
  version gets an **unsolvable dependency set** — `mix deps.get` fails
  immediately.
- **Hex DOES support `or` requirements**: `"~> 1.7.189 or ~> 2.0"` is valid and
  expands to the union of both ranges. An even simpler widening:
  `">= 1.7.189 and < 3.0.0"`.
- **Correct publish order**: publish new versions of ALL 11 sibling modules
  with widened pins FIRST, then publish `phoenix_kit` 2.0.0. If core is
  published first, every consumer who hasn't updated their modules is broken.
- **Nothing in the modules' code breaks against 2.0**: the `PhoenixKit.Module`
  callback interface, `Routes.path/1`, and the migration coordinator contract
  are all unchanged. The widened pin is safe — modules need no code changes,
  only a version requirement bump.
- Consumer workaround exists (`override: true`) but is unsafe and should not be
  the plan.

**2. Bump `@version` to `"2.0.0"` and add CHANGELOG entry** — *Maintainer*

- `mix.exs` still reads `@version "1.7.235"`. The version must be `"2.0.0"`
  before publishing.
- CHANGELOG has no `## 2.0.0` heading. Consumers need to know: (a) below-floor
  refusal, (b) V164 FK repair including the CASCADE→SET NULL behavior change on
  comments, (c) the bridge path.

**3. Make the upgrade guide reachable by consumers** — *Maintainer*

- The upgrade guide (`dev_docs/guides/2026-08-07-upgrading-to-2.0-guide.md`) is
  excellent and thorough. But it lives in `dev_docs/`, which is excluded from
  both the hex package AND hexdocs.pm.
- The hex `files:` whitelist is `~w(lib priv mix.exs README.md LICENSE
  CHANGELOG.md)` — no `guides/`, no `dev_docs/`.
- **Fix**: copy/move the guide to `guides/upgrading-to-2.0.md` and add it to
  the `docs: extras:` list. It will then appear on hexdocs.pm. Alternatively,
  inline the critical steps into the CHANGELOG entry.

**4. Fix the prerelease gate and run it clean** — *Maintainer*

- `mix prerelease` failed at `hex.audit`. Paradoxically, `mix hex.audit` works
  standalone ("No retired packages found") — the failure is a gate-mechanics
  issue.
- Consequence: `docs`, `hex.build`, and `phoenix_kit.release_check` did NOT
  execute in this run.
- These have all been verified separately (`hex.build` unpacked successfully,
  `release_check` recorded as passing in the verification matrix), but the
  gate as a whole hasn't passed clean end-to-end.
- The orchestrator noted this is the FIRST TIME the gate has EVER run past the
  compile step (the `:enoent` bug was only fixed today). Weigh accordingly.
- **Fix**: debug the `hex.audit` failure in the alias context, then re-run
  `mix prerelease` clean.

### Brief Items Checklist

**Item 1 — Is a major the right version?** YES.
Two backwards-incompatible changes justify a major:

1. Below-floor databases are refused with `BelowFloorError` (breaking for any
   install at < V135)
2. Comments FK changed from `ON DELETE CASCADE` to `ON DELETE SET NULL`
   (behavior change — deleting a user no longer deletes their comments)

Additionally, V01–V134 are deleted, so downgrading from 2.0 to 1.7 and
replaying those versions is impossible.

**Item 2 — Hex package contents.** ✓ VERIFIED MYSELF.

- Unpacked `phoenix_kit-1.7.235` (from `mix hex.build --unpack`):
  - 30 migration files (V135–V164): all present ✓
  - Expected schema manifest (`expected_schema.ex` + `expected_schema/`
    directory): present ✓
  - Supporting migration modules (51 total files under
    `lib/phoenix_kit/migrations/`): present ✓
  - `dev_docs/` excluded: confirmed absent ✓
  - No private/sensitive content: confirmed ✓
  - `helpers.ex`, `uuid_fk_columns.ex`, `uuid_integrity.ex`, full `repair/`
    directory: present ✓

**Item 3 — Upgrade guide.** The guide itself is thorough and correct
(step-by-step bridge path, V164 lock behavior, PgBouncer warnings,
named-schema limits, rollback semantics). **But it is unreachable to
consumers** — see Condition 3.

**Item 4 — Unhappy path behavior.** ALL VERIFIED BY READING CODE:

- **Below floor**: `BelowFloorError` raised from `up/1`, `down/1`, AND
  `ensure_current/2`. Message is loud, safe, and actionable: names the floor
  (V135), names the bridge ("the last PhoenixKit 1.7.x release"), and appends
  `mix test.reset` hint for the `ensure_current` context. ✓
- **Missing/hand-edited version comment**: `Repair.Probe` reads and handles
  nil/absent comments. ✓
- **PgBouncer in transaction mode**: documented in upgrade guide ("use a
  direct connection"). ✓
- **V164 on a large table**: uses `NOT VALID` + separate `VALIDATE CONSTRAINT`
  (non-blocking validation). NULL rows → warns and skips (never forces).
  Already-existing FK → adopts by shape, not name.
  `@disable_ddl_transaction` makes partial failure safe to re-run. All
  documented. ✓
- **Degraded outcome exits successfully**: documented — the SUMMARY line names
  every constraint left NOT VALID. ✓

**Item 5 — Prerelease gate.** FAILED at `hex.audit` — see Condition 4. Partial
results: `deps.get --check-locked` ✓; `MIX_ENV=prod compile
--warnings-as-errors` ✓ (481 files, no warnings); `quality.ci` — format ✓,
credo ✓ (10096 mods/funs, no issues), dialyzer ✓ (221 errors, all 221 skipped
via ignore file, 2 unnecessary skips — clean pass); `deps.audit` ✓ ("No
vulnerabilities found"); `hex.audit` ✗ (task not found in alias context —
works standalone); `docs`, `hex.build`, `phoenix_kit.release_check` — NOT
REACHED in that run.

**Item 6 — Known-unproven items.** None should gate release:

- Second PostgreSQL major: documented as informational-only finding
  (expression rendering differences, not schema drift). Acceptable. ✓
- s16 (Oban delegated): `SKIP:pending-p2-body` — assertion body pending, low
  risk. Acceptable. ✓
- s18 (migration mid-repair interleave): detected by version-comment re-read,
  not prevented. Advisory lock prevents the reverse direction. Documented as a
  limitation. Acceptable. ✓

### Verified Myself vs. Taken from Brief

**Verified myself (code reading, file inspection, tool execution):**
Hex resolver semantics (`or` requirements ARE expressible; module pins CANNOT
resolve with 2.0.0); hex package contents (unpacked and listed every file);
30 versioned migration files present, V01–V134 absent; `BelowFloorError`
message text; `bridge_version` never set concretely (always nil → generic
"1.7.x" wording); `@current_version` 164 / `@initial_version` 135; upgrade
guide location (excluded from package); no 2.0.0 CHANGELOG entry; no README
upgrade mention; prerelease log (failure at `hex.audit`, works standalone);
dialyzer 221/221 skipped with 2 unnecessary ignore entries; V164 moduledoc +
implementation (NOT VALID strategy, idempotence, relaxed-column handling,
comments FK correction); all 6 recorded diffs in `dev_docs/squash/out/`
(expected normalizations, not bugs); `PhoenixKit.Module` callback interface
unchanged.

**Taken from the brief (not independently re-verified against the database):**
S1–S22 matrix results (0 FAIL, 3 SKIPs); 1919 tests passing;
`phoenix_kit.release_check` green (prior recorded result); S21 round-trip;
mode A equivalence oracle.

### Summary

The migration chain, the repair delta, the below-floor guard, and the hex
package contents are all sound. The three review rounds caught and fixed every
code issue. What remains is release *logistics*: the sibling-module pin
widening (a coordination step, not a code change), the version bump, the
upgrade guide placement, and a clean prerelease gate run. All four are
straightforward, none require changes to the migration chain itself, and none
change the risk profile of the release.

---

## Orchestrator note (post-review), 2026-08-09

Condition 4's root cause was isolated after the reviewer wrote its report:
**dialyxir breaks Hex-archive task resolution in the same VM.** Bisection:
`mix do deps.audit + hex.audit` passes, `mix do format --check-formatted +
credo --strict + hex.audit` passes, `mix do quality.ci + hex.audit` fails —
i.e. the `dialyzer` step is the trigger; project-dep tasks (`deps.audit`,
`docs`, `phoenix_kit.release_check`) keep resolving, archive tasks
(`hex.audit`, `hex.build`) stop. Fix applied to the `prerelease` alias: both
hex.* steps now run via `cmd mix …` (fresh VM per step). The remaining tail
(`docs` → `hex.build` → `release_check`) was also executed on this tree:
docs generate (70 broken-autolink warnings referencing hidden modules, mostly
`PhoenixKit.Migrations.ExpectedSchema` — cosmetic follow-up), `hex.build`
packages correctly, `release_check` passes every technical check (V135..V164
contiguous, chain_hash matches all 30 files, CHANGELOG shape) and fails only
the three environment checks that are expected to fail before the maintainer
cuts the release (dirty tree, branch ≠ main, tag 1.7.235 already exists).
