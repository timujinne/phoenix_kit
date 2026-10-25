# PR #964 — Public direct URLs in batches

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

**BUG - MEDIUM (fixed):** `Storage.direct_urls/1` converted UUID inputs with `to_string/1` before validating them. A map or tuple UUID raised `Protocol.UndefinedError`, and an invalid list could raise too, losing every valid result in the batch. Both tuple values now must be strings before entering the batch. The mixed-input regression includes a map, list, nil, integer and a valid file, and asserts that the valid URL survives.

Rechecked private/suspended/trashed library filtering, hidden originals, edit state, inline disposition, backup exclusion, first serving bucket selection and fixed query count. No access-policy change.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
