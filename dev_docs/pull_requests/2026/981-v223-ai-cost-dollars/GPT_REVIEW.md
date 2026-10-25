# PR #981 — AI dollar-cost migration and release pairing

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked the V223 up/down SQL, cost conversion units, numeric precision, model width, schema-anchored catalog checks, foreign-key rebinding and caller search-path restoration. No additional migration defect found.

**BUG - HIGH (release dependency):** published `phoenix_kit_ai` 0.25.5 uses the legacy request schema. Its current main branch already contains the dollar-cost implementation; the earlier Claude review predates that merge. The companion still declared core `~> 2.63`, which permits a schema without `cost`. Prepared the companion floor correction to `~> 2.64` and extended its conformance test. Core 2.64.0 must ship with the compatible AI companion and the host must upgrade both before migrating. The core changelog now states this pairing, the journal lock and the destructive legacy-account removal.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
