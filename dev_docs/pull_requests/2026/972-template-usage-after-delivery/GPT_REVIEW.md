# PR #972 — Template usage after delivery

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked template send, magic-link, notification and built-message call sites. Usage is recorded only after a successful handoff, suppressed messages are excluded, queued messages count, and a tracking failure does not change the delivery result. The release changelog now records this behavior. No additional defect found.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
