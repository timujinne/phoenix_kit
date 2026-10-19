# PR #932 — profile custom fields and V218: follow-up review

Reviewer: Codex · Date: 2026-10-17 · Baseline: `0f66cea4f`

Rechecked the custom-field allowlist and its profile save callers, the existing
review's stale-data finding, and V218's default/backfill statements. V218 needs
no change; the data-loss issue recorded in the earlier review is now fixed.

## BUG - MEDIUM — stale profile saves overwrite newer system fields (fixed)

`User.profile_changeset/3` merges accepted fields over the supplied user's map.
`Auth.update_user_profile/2` previously persisted that entire snapshot. A form
opened before a notification preference changed could silently undo the change;
it could also restore a deleted avatar pointer or replace a now-structured value.
This behavior predates #932, but violates its preservation guarantee.

When the changeset changes custom fields, the context now reads the current row
under `FOR NO KEY UPDATE`, rebuilds the changeset with its current custom fields,
and saves it in the same transaction. System updates use the same row lock, so
they serialize with the merge. Validation failures roll back the save; events
and activity logging retain their existing success-only path. Other profile
saves keep the existing single-update path. This adds a locked read and repeats
custom-field validation only for a custom-field change.

Three regressions failed against the baseline: a mounted form losing a newer
preference, a stale context call restoring deleted/dropping added keys, and a
scalar replacing a field that became structured. A fourth test preserves the
existing stale-entry exception when the user was deleted.

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
