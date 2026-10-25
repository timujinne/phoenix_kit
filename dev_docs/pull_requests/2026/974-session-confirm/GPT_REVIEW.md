# PR #974 — Person-confirmed session writes

**Reviewer:** GPT / Codex · **Rechecked:** 2026-10-24

Rechecked the merged change and subsequent fixes on main for the 2.64.0 release, including the existing review.

## Findings

Rechecked `execute_as/5`, `redeem_as/6`, `Confirm` and the session flow. Writes require both `allow: :all` and a configured module, then wait in a user-bound row. Redemption rebuilds session rights and repeats tool visibility, scope, permission, module, rate and input checks before a fresh fingerprint and atomic claim. The raw session secret never enters the reference.

V222 remains prefix-qualified and adds the user actor/index/check changes to the manifest. Impersonation refusal remains an explicit duty of the trusted host caller. The release changelog now records V222, the setting and the API. No additional defect found.

## Validation

Validation results are recorded in `dev_docs/pull_requests/2026/2026-10-24-release-recheck/GPT_REVIEW.md`.
