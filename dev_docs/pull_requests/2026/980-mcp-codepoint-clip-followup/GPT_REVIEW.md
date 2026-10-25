# PR #980 — Approval reason code-point clipping

**Author:** timujinne · **Merged:** 2026-10-23 (`01c93d57d`) · **Reviewer:** GPT / Codex

Rechecked the merged implementation and Claude's review at `76db2cfe7`.

## Verdict

No production defect found. `cap/1` keeps exactly 160 code points intact and clips longer text to 159 code points plus an ellipsis. The code-point walker reads a bounded prefix, including when one grapheme contains 200,000 combining marks. Splitting a grapheme is an acceptable consequence of this display bound. The executor test correctly pins `idempotency_key` as the cause of the no-replay 422 response.

## Improvements

- Added tests for the combined `path: message` limit at 160/161 code points using four-byte Unicode characters, and for a path containing 200,000 combining marks.
- Assert the exact displayed prefix, valid UTF-8, and retention of the original preview in technical details whenever clipping occurs. An intact 160-code-point reason requires no technical fallback.

No production code change was needed for this PR. The limit applies to displayed reasons; the original text remains available in technical details by design.

## Validation

- `mix precommit` — passed: warnings-as-errors compilation, unused-dependency check, compilation of every test file, formatting, strict Credo, Dialyzer, and 473 JavaScript tests.
- `PGDATABASE=beamlab_test PGPOOL=20 mix test test/phoenix_kit/integrations/module_validation_test.exs test/phoenix_kit/api/approvals_view_test.exs --max-cases 8` — 67 tests, 0 failures.
- `PGDATABASE=beamlab_test PGPOOL=20 mix test test/phoenix_kit/integrations test/phoenix_kit/api test/integration/api test/integration/integrations* test/phoenix_kit_web/live/approvals_test.exs --max-cases 8` — 2,502 tests, 0 failures.
- Final `mix format --check-formatted` and `git diff --check` — passed.

The scoped suite ran with PostgreSQL reachable, rather than excluding integration tests for an unavailable database. The harness enabled its `:requires_createrole` filter because this database role lacks CREATEROLE. The entire repository suite was not run.
