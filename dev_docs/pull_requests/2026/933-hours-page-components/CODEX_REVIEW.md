# PR #933 — shared components: follow-up review

Reviewer: Codex · Date: 2026-10-17 · Baseline: `0f66cea4f`

Rechecked stacked-bar normalization and geometry, date navigation's event/target
wiring and bounds, and the existing review's picker-target fix.

## BUG - MEDIUM — JSON-decoded stacked bars render blank (fixed)

Plain bars accept atom-keyed and string-keyed maps, as do individual stacked
parts. The new outer stacked-bar clause accepted only `%{parts: ...}`. Passing
the same data through JSON decoding discarded every bar and rendered the empty
slot instead of a chart.

String-keyed stacked data now delegates to the same normalization path. A
regression compares the complete rendered SVG and tooltips before and after a
JSON round trip; it failed against the baseline.

The earlier picker-target fix remains correct. No additional date navigation,
search-picker or select change was required.

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
