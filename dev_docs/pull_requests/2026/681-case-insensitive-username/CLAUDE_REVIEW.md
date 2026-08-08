# PR #681: Add V161: case-insensitive phoenix_kit_users.username via citext

**Author**: @timujinne
**Reviewer**: @timujinne (Claude)
**Status**: 🔄 In Review
**Commit**: `upstream/main..fix/case-insensitive-username`
**Date**: 2026-08-05

## Goal

`phoenix_kit_users.username` is a plain `varchar` under a plain btree unique index, so `Pavel` and
`pavel` are two different accounts. That happened in production. V161 converts the column to
`citext` so uniqueness *and* every lookup become case-insensitive from the column type outward.

## What Was Changed

| File | Change |
|------|--------|
| `lib/phoenix_kit/migrations/postgres/v161.ex` | New migration: collision pre-check, then idempotent `ALTER … TYPE citext`; `down/1` back to `varchar(255)` |
| `lib/phoenix_kit/migrations/postgres.ex` | `@current_version` 160 → 161, catalogue moduledoc entry |
| `test/phoenix_kit/migrations/v161_test.exs` | New: schema-state pins + pre-check SQL shape |
| `test/integration/users/registration_test.exs` | Inverts the test that pinned exact-match username lookup as intended |
| `config/test.exs` | `PGDATABASE` / `PGPOOL` so the suite can use an existing database |
| `AGENTS.md`, `mix.exs` | Corrects what `precommit` and CI actually run |

## Review Findings

Reviewed by an independent model (GLM-5.2 at max effort) against the code, then every finding
re-verified by hand before being accepted. Findings from an earlier pass on the migration itself
were already folded into commit 2 of this branch.

### IMPROVEMENT - MEDIUM — `config/test.exs`: set-but-empty env var aborted config loading

`System.get_env/2` falls back to its default only when the variable is **unset**. A set-but-empty
`PGPOOL=` returns `""`, and `String.to_integer("")` raised an `ArgumentError` during config
loading — before any test started, with a message that never named `PGPOOL`.

Trivially reachable: `PGPOOL= mix test` from a shell, or `PGPOOL:` with no value in a YAML
pipeline. Verified by running it, not by reading.

**Resolved** in this branch: both `PGDATABASE` and `PGPOOL` now treat empty as absent, trim
whitespace, and a non-numeric `PGPOOL` raises a message that names the variable and the value.
Checked across all four cases — unset, set-empty, valid, whitespace-padded.

### NITPICK — internal chronology in upstream-facing docs

Comments read "tried on 2026-08-04 and reverted" — a bare date without an actor reads as one
team's internal history in a public library.

**Resolved**: dates dropped, the reasoning kept.

### Self-correction — the docs this PR fixes contained an inaccuracy of their own

This PR's own wording claimed `mix test` with no database "silently" excludes integration tests.
It is not silent: `test_helper.exs` prints a warning banner. The substantive point survives and is
what matters — the run still **exits 0 and reports success**, so a green summary proves nothing
about a migration. Wording corrected.

### Verified and found correct (so a maintainer knows these are closed)

- **Dispatch**: `Module.concat([__MODULE__, "V#{pad_idx}"])` by version number plus the
  `@current_version` bump is the whole wiring — no registry to forget.
- **Pre-check cannot false-positive**: `WHERE username IS NOT NULL` is the load-bearing clause;
  without it `GROUP BY` folds every NULL into one group and two username-less accounts abort the
  upgrade. Pinned by test.
- **Re-running on an installation already at 161** is a no-op: the coordinator skips it, and even
  if DDL was once dropped, the `DO` block is guarded on `udt_name` and the pre-check returns empty
  on a citext column.
- **Prefix-safety**: both existence checks anchor on `table_schema`; no `::regclass` in an
  IMMEDIATE check; `escaped_prefix` is escaped at the entry point. Same shape as V151.
- **Auth needs no changes**: `get_user_by_username/1`, `unsafe_validate_unique/3` and
  `ensure_unique_username/3` all ride the column's semantics.
- **No internal infrastructure leaked** into the diff (checked for paths, hostnames, team names).

## Testing

- [x] Unit tests added/updated
- [x] Integration tests pass — 41/41 for the migration and registration suites
- [x] Migration tested on a real database — PostgreSQL 17.4, empty database, full chain V01→V161
- [x] Backward compatibility verified — see below
- [x] Documentation updated

Verified on the real run, not inferred: column became `citext`, `email` untouched, schema version
comment `161`, the unique index survived the `ALTER` with the same name and predicate, inserting
`'ALICE'` against an existing `'alice'` is rejected, and `WHERE username = 'BOB'` finds `'bob'` —
the exact SQL shape `Repo.get_by` emits.

Full suite against that database: 3 failures, all in `MaintenanceTest` (scheduling windows on an
unseeded database), which V161 does not touch. `mix precommit` green.

## Migration Notes

An installation that already contains case-variant usernames stops with a raise naming the
conflicting value, before any DDL. The operator renames or merges and re-runs — the same
experience V106 already establishes. Nothing is merged or renamed automatically.

`citext` has been a required extension since V01, so there is no new database prerequisite.

The behavioural change is the fix itself: username lookup and uniqueness become case-insensitive.
Anything relying on case-sensitive username matching would change behaviour — nothing in core does.

## Related

- Migration: `lib/phoenix_kit/migrations/postgres/v161.ex`
- Prior art for the pre-check shape: `lib/phoenix_kit/migrations/postgres/v106.ex`
- Prior art for the citext conversion: `lib/phoenix_kit/migrations/postgres/v151.ex`, `v01.ex`
