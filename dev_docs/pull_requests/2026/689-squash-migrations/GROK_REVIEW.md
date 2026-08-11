# PR #689 Recheck — Squash the migration chain at floor V135

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/689
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`cbf70fee`)
**Reviewer:** Grok (recheck of Claude's work)
**Date:** 2026-08-09

---

## Verdict

**Claude's review holds up.** The five mechanical findings (#1–#5) are fixed in
`#690` / `b3ef57b2` and still correct on HEAD. I re-verified:

| Claim | Result |
|---|---|
| Privilege rescue for `ensure_uuid_v7_function/1` is pre-queue `pg_has_role` | Holds |
| `BelowFloorError.bridge_version` at both raise sites (+ re-raise path) | Holds |
| V164 no longer warns about the FK it repairs | Holds |
| Floor routing (`plan_up`/`plan_down`, teardown list element) | Holds |
| No dangling refs to deleted V01..V134 modules in `lib/`/`test/` | Holds |

## Still open (maintainer / environment)

1. **Equivalence evidence (Claude BLOCKER #6).** `verify.exs` 21 PASS predates
   HEAD (V164 renumber, V165/V166, V163/V164 edits). No PostgreSQL in this
   environment — cannot re-run. Required before treating the squash as
   *observed* equal to the pre-squash chain.
2. **Version choice (Claude #8 / second pass).** Shipped as **1.7.237** so
   feature-module pins (`~> 1.7.x`) keep resolving. Trade is documented in
   Claude's second pass: below-floor hosts on `~> 1.7` can be auto-resolved into
   a refused migration. Acceptable if the CHANGELOG lead is not missed.

## This pass

No code changes for #689 itself. Manifest body + `chain_hash` work for V165/V166
is recorded under the #692 recheck (objects those PRs added).
