# PR #961 — Hold every write of a key that requires approval, not only dangerous ones

**Author:** timujinne · **Merged:** 2026-10-22 (436354712) · **Reviewer:** Claude

## Summary

`Flow.gate/1` now sends any non-dry-run write of a `requires_approval` key to the approval queue (`approval_key?(state) or dangerous?(state)`),
and `redeem/2` refuses a `confirm_token` from such a key (`409 confirm_token_invalid`, reason `approval_required`). Docs, MCP/OpenAPI
instructions, the key form hint and the guide's sentence are reworded; nine `.po` files carry the changed strings (no empty or fuzzy entry).

Verdict: correct, and the change closes the real hole (splitting a change under the batch/percentage thresholds got round the approval queue).

## Checked

- Reads (`annotations.read_only`) and `dry_run` still pass before the new branch, so `system.get_identity` / `system.get_approval` and previews
  are never held; both core tools are `read_only: true`.
- A public caller is never an approval key (`approval_key?/1` matches `actor.kind == :key`).
- A write tool without a dry-run answer now fails (`crashed`) for an approval key, where before it ran. That is the documented contract (every
  write tool answers a dry run), now enforced for all writes of such a key; the guide and AGENTS.md say so.
- Tests: the new `executor_gate_test.exs` cases (queued, danger check says no, approve runs once, plain key unaffected, code refused, dry run, read) — green.

## Findings

- **NITPICK (not changed):** the `V219` moduledoc still says `requires_approval` marks a key whose "dangerous operations" wait. It describes what
  that migration shipped, and migration docs are history; the column's current meaning lives in `Keys.Key` / the guide.
- **Release note:** behaviour change for existing approval keys (non-dangerous writes now wait). CHANGELOG entry belongs to the release commit.
