# PR #977 — Bucket-scoped credential validation

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked `AccessDenied` mapping and its propagation through initial and confirmation-retry paths. The note states bucket access was not verified; invalid identities/signatures still fail and bucket forms retain their put/get/delete probe. No additional defect found.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
