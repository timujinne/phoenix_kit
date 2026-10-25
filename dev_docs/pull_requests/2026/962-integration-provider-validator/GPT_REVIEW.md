# PR #962 — Module-supplied connection checks

**Author:** timujinne · **Merged:** 2026-10-23 (`570ba3211`) · **Reviewer:** GPT / Codex

Rechecked the merged implementation and Claude's review at `76db2cfe7`.

## Findings and changes

- **BUG - MEDIUM (fixed):** `required_fields_filled?/2` used `present?/1`, which accepts only strings. Required `:number` setup fields can reach the public context as integers (or floats), including through `save_setup/4`; the existing flat-credential gate explicitly supports them. A module provider with `port: 587` therefore returned “No credentials configured” before its validator ran. Reused `field_present?/1`. Tests cover integers, zero, floats, strings, missing values and blanks, before and after saving.
- **IMPROVEMENT - MEDIUM (fixed):** implemented the owner-aware callback Claude suggested deferring. A validator may implement `validate_connection/2`, receiving `[owner: owner]`; `/2` takes precedence and `/1` remains supported. Both callbacks are optional in the behaviour, with at least one required by the runtime dispatcher. The provider can now apply the personal endpoint policy when it accepts a host from an operator. This supplies context; the provider must still enforce the policy before its own network requests.
- **IMPROVEMENT - MEDIUM (fixed):** saved validation and fresh `reading/2` now dispatch with the resolved row's owner. An owner-agnostic `owner: :any` read must not become the policy context, and the old reading path discarded options entirely. Pre-save validation uses the caller's owner option, never ownership fields inside submitted attributes. Tests cover system/user/dashboard owners, owner-agnostic reads, forged pre-save fields, and cross-owner refusal.
- **NITPICK (test added):** Claude's review says the saved `"connected"`-without-required-key case is pinned, but the original test only created an unconfigured empty connection. Added the connected-status regression explicitly.

The existing isolation, deadline, operator locale, return normalisation and credential-safe logging remain in place. Added `/2` coverage for callback precedence, missing credentials, deadlines, raise/throw/exit with request-derived secret sentinels, and locale propagation. Neither callback receives arbitrary caller options beyond the explicit `owner:` context.

## Validation

- `mix precommit` — passed: warnings-as-errors compilation, unused-dependency check, compilation of every test file, formatting, strict Credo, Dialyzer, and 473 JavaScript tests.
- `PGDATABASE=beamlab_test PGPOOL=20 mix test test/phoenix_kit/integrations/module_validation_test.exs test/phoenix_kit/api/approvals_view_test.exs --max-cases 8` — 67 tests, 0 failures.
- `PGDATABASE=beamlab_test PGPOOL=20 mix test test/phoenix_kit/integrations test/phoenix_kit/api test/integration/api test/integration/integrations* test/phoenix_kit_web/live/approvals_test.exs --max-cases 8` — 2,502 tests, 0 failures.
- Final `mix format --check-formatted` and `git diff --check` — passed.

The scoped suite ran with PostgreSQL reachable, rather than excluding integration tests for an unavailable database. The harness enabled its `:requires_createrole` filter because this database role lacks CREATEROLE. The entire repository suite was not run.
