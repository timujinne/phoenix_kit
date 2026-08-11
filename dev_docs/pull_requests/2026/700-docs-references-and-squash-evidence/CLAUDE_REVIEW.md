# PR #700 Review — Doc references, 2.0 upgrade docs, and the squash equivalence evidence

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/700
**Author:** Max Don (mdon)
**Merged:** 2026-08-10 (`d1a67261`, branch `mdon/main` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-10
**Scope:** 13 files, +3669 / −2783, 5 commits.

---

## Verdict

**Billed as "small docs stuff". Two of the five commits close release blockers.**
Worth saying plainly, because the framing undersells what landed:

| Commit | Actually is |
|---|---|
| `306efc2c` | **Fixes four false-alarm divergences in the schema manifest**, found by running it against a live database |
| `18fe1041` | **Closes #689's blocker #6** — the squash-equivalence evidence that predated HEAD |
| `ebc4f9ea` | Fixes a verify scenario that had silently stopped exercising V164 |
| `feb6e78f` | Corrects the bridge version / chain extent in the 2.0 docs; README upgrade section |
| `8714a511` | The seven broken doc references |

One finding, fixed here. Everything else verified and correct.

---

## The two that matter, verified

### `306efc2c` — the manifest entries I flagged as unvalidated

Three of my earlier reviews carried the same caveat: the V165/V166 objects were
hand-declared and **had never been checked against a real database**, so a green
`release_check` proved only that `chain_hash` matched the migration files. This
commit ran the check that settles it, on PostgreSQL 17.6 over the full
V135..V166 chain, and found the caveat was justified — all four hand-written
entries were in source-SQL form rather than the form Postgres stores:

```
CHECK (kind IN ('user', 'resource'))
  →  CHECK ((kind = ANY (ARRAY['user'::text, 'resource'::text])))
```

The differ compares against `pg_get_constraintdef` / `pg_get_indexdef`, so all
four reported `wrong_shape` on a perfectly healthy install — false alarms on
every database at V166, in a report whose value depends on being believed.

I checked the corrections against Postgres' actual deparsing rules rather than
taking them on trust, including the diagnosis of where the mistake came from:

| Claim | Verified |
|---|---|
| The predicate was copied from `phoenix_kit_org_invitations_pending_unique_idx` | `v135.ex:3902` — identical shape, with the `(status)::text` cast |
| That table's `status` is `varchar`, hence the cast | `v135.ex:8360` — `'pending'::character varying` |
| `access_requests.status` is `text`, so no cast appears | `v165.ex:112` — `status TEXT NOT NULL` |
| `comments.attribution_mode` is `text` too | `v166.ex:56` |
| `chain_hash` is untouched | correct — it hashes `v*.ex`, not the manifest. `release_check` still PASSES |

So `(status)::text = 'pending'::text` → `(status = 'pending'::text)` is right, and
the reason it was wrong is exactly as described. **s7 and s8 now pass where s8
previously failed on precisely these four findings** — which is the validation
that was outstanding.

### `18fe1041` — the equivalence evidence

`#689`'s review left blocker #6 open: the S1/S2 references were built at chain
v163, so every run since had skipped them with `reference-stale`, meaning the
squash-equivalence evidence covered neither V164's flush-order repair nor
V165/V166. Regenerated from the bridge commit with V164–V166 grafted on, so the
old chain runs all 166 versions individually against the squashed chain.

The commit is candid about a subtlety that would be easy to hide: the graft
needed HEAD's `uuid_fk_columns.ex`, which also drops
`{:phoenix_kit_users_tokens, "user_uuid"}` from the NOT NULL list. Taking HEAD's
copy is right — keeping the bridge's would have manufactured a divergence out of
a known, deliberate 2026-08-08 fix — and saying so is what makes the resulting
PASS meaningful rather than assumed. **S1/S2 now pass instead of skipping, and S4
is unblocked**, so the `BelowFloorError` guard protecting pre-2.0 upgrades is
verified rather than skipped.

### `ebc4f9ea` — a real bug in the harness

s21 computed its delta as `current_version() - 1 .. current_version()`, correct
only while V164 was the chain head. Once V165/V166 landed the delta became
165..166, V164 never ran, and the scenario reported ~70 unenforced foreign keys
and ~44 nullable columns as a product defect. Pinned to `@s21_repair_version`.
Right fix, and the right reasoning: the delta is a property of the migration
under test, not of where the chain happens to end.

---

## IMPROVEMENT - LOW — one broken link source left, of a class the PR didn't count

**File:** `lib/phoenix_kit_web/components/core/integrations_ui.ex`

`8714a511`'s goal is stated as removing links "which would have shipped as dead
links in the 2.0 hexdocs", and it reports the end state as "14 undefined
references to 0" with "54 remaining 'hidden' warnings … deliberate".

Both numbers are exactly right — I reproduced them: 0 undefined, and the
remaining hidden warnings are 28 module + 26 function = 54. But `mix docs` also
emits **two warnings of a third class** that the accounting doesn't mention:

```
warning: documentation references file "url" but it does not exist
  68 │ @doc "Simple inline markdown: **bold**, [links](url), `code`, and {variables}."
```

`[links](url)` is meant as an *illustration* of the syntax the function accepts,
but ExDoc reads it as a real link and publishes `<a href="url">`, which 404s from
the hexdocs page. So it is a genuine dead link in the 2.0 docs — the exact thing
the commit set out to eliminate — and it survived because it is a *file*
reference rather than an *undefined* one.

**Fixed:** the examples are backticked, which stops ExDoc linking them and also
reads better, since the sentence is describing syntax. `mix docs` is now **0
undefined, 0 broken file references, 54 hidden** — the stated goal, met.

---

## Verified and left alone

- **All seven reference fixes are correct**, checked against the declarations rather than the commit message: `Integrations.owner` and `Module.permission_meta` are `@type` (so `t:`), `Module.email_settings_sections` is a `@callback` (so `c:`), `Repair.delegate_oban` really is `defp` (so prose only), and `Dashboard.Registry.get_tabs/1` / `get_admin_tabs/1` both exist at that arity.
- **The seventh fix is the interesting one and it is right.** `Ecto.Adapters.SQL.checkout/2` does not exist; `checkout/3` does but is `@doc false`, so fixing only the arity would have traded a visible warning for a hidden one. `c:Ecto.Repo.checkout/2` is a real, public `@callback` (`deps/ecto/lib/ecto/repo.ex:819`, not `@doc false`) and matches what the code actually calls.
- **`feb6e78f`'s bridge-version correction.** Consistent with `@bridge_version "1.7.236"` and with the CHANGELOG's upgrade-requirement section.
- **`dev_docs/squash/reference/s1_old_chain.sql`** (+5647/−2783) is a tool-written reference regenerated by the harness, header-stamped with the chain version. Not hand-edited, and the harness refuses stale references rather than comparing against them.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit_web/components/core/integrations_ui.ex` | backtick the markdown examples so ExDoc stops publishing `href="url"` |

## Gate

`mix precommit` clean. `mix phoenix_kit.release_check` — **CHANGELOG heading,
body, migration version sync (including `chain_hash`), branch and tag collision
all PASS**; only Git Tree Clean was failing, because this pass was uncommitted at
the time. `mix docs` — 0 undefined references, 0 broken file references.

## What this changes about the release

Two of the three caveats I had been repeating are now closed by this PR:
the manifest body **has** been checked against a live database (s7/s8), and the
squash-equivalence evidence **does** now cover the current chain (S1/S2/S4).
What remains is the module pin wave for 2.0, and a full `mix test` on a machine
with PostgreSQL.
