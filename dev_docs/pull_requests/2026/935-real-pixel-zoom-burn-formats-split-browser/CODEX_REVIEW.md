# PR #935 — image viewer and burn pipeline: follow-up review

Reviewer: Codex · Date: 2026-10-17 · Baseline: `0f66cea4f`

Rechecked the previous review's fixes: animation budgets include source and
resized frames before cropping, the source has its own pixel budget, and failed
capture restores temporary styles and selected/hovered state in `finally`.
Also inspected the format/layout dispatch and viewer-library minification's
fallback and content-hashed outputs.

No additional fix is established in this focused recheck. The existing
`GPT_REVIEW.md` documents the earlier findings and tests. Its limitations remain:
photo burns need ImageMagick's WebP encoder, burn zoom with spill on both axes is
an estimate, and these tests do not provide interactive browser verification.

## Validation

- `mix precommit`: exit 0, including warnings-as-errors compilation, unused
  dependency check, test-file compilation, formatting, strict Credo, Dialyzer
  (using the existing ignore file), and all **377 JavaScript tests**.
- Full repository run:
  `PGDATABASE=phoenix_kit_codex_review_20261017 PGPOOL=12 mix test --max-cases 8`
  — exit 0; **89 doctests, 11,270 tests, 0 failures, 10 skipped (1 excluded)**.
  PostgreSQL integration tests ran in a fresh, separate database; the test role
  lacks `CREATEROLE`, accounting for the privileged-test exclusion.
- `git diff --check`: clean.
