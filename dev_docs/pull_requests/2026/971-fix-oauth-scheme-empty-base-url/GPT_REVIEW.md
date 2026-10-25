# PR #971 — OAuth endpoint scheme resolution

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked the merged scheme fix and subsequent port parsing correction. Unset OAuth base URLs reach endpoint configuration; endpoint ports accept integer, string and environment tuple forms. Trusted forwarded-proto handling remains first. Loopback inference requires both configured and incoming hosts to be loopback. No additional defect found.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
