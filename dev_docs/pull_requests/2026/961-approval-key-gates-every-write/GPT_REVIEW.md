# PR #961 — Approval keys hold every write

**Author:** timujinne · **Merged:** 2026-10-22 (`436354712`) · **Reviewer:** GPT

Independent recheck of the merged change and Claude's review at `a9fa57de0`.

## Findings

No additional defect found. `Flow.gate/1` handles reads and dry runs before checking
the key's approval flag. All other writes of that key enter `confirm_flow/1`,
including tools with no danger declaration and danger callbacks returning false.
Sending a confirmation token cannot bypass that branch. Approval execution still
rechecks the key, current rights, enabled registry, input schema and fingerprint,
then atomically claims execution. Idempotency replays return an earlier answer
without executing another write; pending approval answers are not stored as results.

Checked the shared executor used by REST/MCP, the tool write predicate, the approval
execution path, the changed instructions and translated UI strings, and the gate
regressions. Existing release-note follow-up remains as recorded by Claude; this
review does not cut a release.

## Validation

Validation results are recorded with the companion [gallery review](../965-gallery-mode/GPT_REVIEW.md).
