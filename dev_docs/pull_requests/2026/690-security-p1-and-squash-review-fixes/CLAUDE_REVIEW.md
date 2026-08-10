# PR #690 Review — feature/security-p1 (credential rank rule + #689 review fixes)

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/690
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`b5f28e77`, branch `feature/security-p1` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 16 files, +943 / −50, 5 commits.

---

## What is actually in it

The branch name says security; two thirds of it is the #689 review's fixes.

| Commit | Content |
|---|---|
| `31835d9d` | `mix.lock` only — three dependency bumps |
| `b3ef57b2` | The four defects from `689-squash-migrations/CLAUDE_REVIEW.md`, plus five stale doc blocks |
| `913315e7` | **`admin_update_user_password/3` authorizes as well as audits** |
| `40cd3d11` | `mix prerelease` alias fixed (`cmd env MIX_ENV=prod …`) |
| `d8536a83` | Release-readiness review round + verdict (docs) |

---

## Verdict

**Clean.** I found no new defects. Everything here is either a fix for a
previously-reviewed finding or a security fix whose successor (#691) I have
already reviewed and hardened separately. What follows is verification, recorded
so the next pass does not redo it.

### `913315e7` — the credential rank rule

`admin_update_user_password/3` wrote the hash for anyone who reached it; the
rank rule lived only in the edit LiveView. The actor was already threaded
through `context` for the audit row, so only the question was missing.

Already reviewed as part of **#691**, which extended it (the `nil` vs
`_malformed` actor split) and where I fixed a regression it introduced (the
refusal path raising `FunctionClauseError` on a non-`%User{}` target). See
`691-fix-credential-bypass-custom-fields/CLAUDE_REVIEW.md`. Nothing further here.

Worth noting the commit message is accurate about its own scope: "Not
exploitable through the shipped UI today — the one live caller gates on
`socket.assigns.can_manage_credentials` in all four of its handlers — so this
closes the second caller before it exists." That matched what I found when
reviewing #691.

### `b3ef57b2` — the four #689 fixes, verified

**1. `ensure_uuid_v7_function/1`'s dead privilege rescue.** The original added a
`rescue` for `insufficient_privilege`, but in migration context the executor is
`Ecto.Migration.execute/1`, which only *queues* — the error arrives at flush
time where no rescue in that function can see it, and the whole migration
aborts. On the DBA-pre-creates-the-function topology the project's own moduledoc
recommends. The fix excludes the un-ownable case *before* queueing:

```elixir
SELECT NOT pg_catalog.pg_has_role(p.proowner, 'USAGE')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proname = 'uuid_generate_v7' AND n.nspname = $1
```

Checked, and it holds up: `pg_has_role(owner, 'USAGE')` is the same test
Postgres applies for ownership of the replace, so a function owned by a role the
migrating role belongs to still gets refreshed; the query is immediate (not
queued) which is the established pattern for existence checks in this module;
it is parameterized rather than interpolated; and an absent function produces no
rows, falls to `_ -> false`, and queues the create — the correct default.

**2. Stale `chain_hash`.** Restamped over the 30 shipped files. Correct at the
time and correctly justified (neither edit since the old stamp altered a
manifest object). It has since gone stale again — see the release note below.

**3. V164 warning about the FK it then repairs.** Removed. It told the operator
to "reconcile by hand" the one constraint the migration drops and re-adds ten
lines later.

**4. `BelowFloorError.bridge_version` never populated.** Now threaded at both
raise sites, so the message reads "Install PhoenixKit 1.7.236 (the migration
bridge)" instead of "the last PhoenixKit 1.7.x release".

I specifically checked for the classic version of this bug — the fix applied to
some raise sites and not all. `BelowFloorError` has three contexts (`:up`,
`:down`, `:ensure_current`) but only two raise sites; `PhoenixKit.Migration`'s
`:ensure_current` path *re-raises the existing struct* with only `context`
changed (`migration.ex:332`), so it inherits `bridge_version`. Complete.

### `40cd3d11` — the `prerelease` alias

`mix cmd` shells out through `System.cmd/3`, which execs the first word
directly, so a bare `MIX_ENV=prod mix compile` step raised `:enoent` and aborted
the gate before it reached `deps.audit`, `hex.audit`, `docs`, `hex.build` or
`release_check`. Now `cmd env MIX_ENV=prod …`. Confirmed working — this is the
gate that caught the stale manifest blocking 1.7.237, which `mix precommit`
cannot see.

---

## Release note

`b3ef57b2`'s restamp of `chain_hash` was correct when it landed and is stale
again: #692 added V165/V166 and #694 edited V163/V164. Full analysis, including
why the DB-free restamp script is the wrong tool this time, is in
`692-add-mentions-display-name-no-email/CLAUDE_REVIEW.md`.

## Gate

No code changes in this pass. `mix precommit` passes on the tree as reviewed.
