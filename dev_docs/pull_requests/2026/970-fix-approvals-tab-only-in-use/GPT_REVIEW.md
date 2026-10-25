# PR #970 — Approval menu visibility

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked `Approvals.in_use?/0` against key expiry/revocation and confirmation kind. Future revocation remains active during rotation grace, retained approval history keeps the menu visible, and route permissions remain independent of visibility. No additional defect found.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
