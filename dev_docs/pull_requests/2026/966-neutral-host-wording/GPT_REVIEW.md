# PR #966 — Neutral host wording

**Author:** timujinne · **Merged:** 2026-10-22 (`2239d7dc2`) · **Reviewer:** GPT

Independent recheck of the merge and Claude's review at `a9fa57de0`.

## Findings

- **BUG - MEDIUM (fixed):** The V176 documentation edit changes the migration
  chain's source hash, leaving `ExpectedSchema.chain_hash/0` stale. The full suite
  fails both the manifest freshness assertion and migration synchronization check;
  the release gate also refuses the stale manifest. The diff since the manifest's
  last update contains only the V176 moduledoc change, so the schema-neutral
  restamping workflow applies. Ran `dev_docs/squash/restamp_chain_hash.exs --restamp`
  to refresh the generated hash; the manifest body is unchanged.

The squash tooling otherwise changes provenance descriptions and scenario labels,
not its DDL or assertions. JavaScript fixture renames preserve matching behavior.
Added the source-hash reminder to `AGENTS.md` so future comment-only migration
edits include this check.

## Validation

Validation results are recorded with the companion [gallery review](../965-gallery-mode/GPT_REVIEW.md).
The existing release-check tests provide the regression coverage. The `s7,s8`
verification command skips both scenarios because this checkout lacks the
pre-squash generated manifest in `dev_docs/squash/output/`; it is not a passing
schema verification. The direct production-manifest integration test passes
(1 test); all 15 release-check tests pass. The full run's two recorded failures
also pass under `mix test --failed` after the fix.
