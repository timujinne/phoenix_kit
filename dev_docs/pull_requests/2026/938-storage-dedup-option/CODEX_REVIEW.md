# Recent changes review — PR #938 and session recovery

**Reviewer:** Codex · **Date:** 2026-10-18

**Scope:** PR #938 (`1383ea354`, author `timujinne`), its constraint-error
follow-up (`685d95be2`), and the adjacent multi-session recovery fix
(`8517ac6a0`). These are the code changes after release 2.63.0.

## BUG - HIGH — an invalid root could restore a secondary account (fixed)

The recovery fix selects the remembered active account before the authentication
plug resolves its user. `restore_persisted_accounts/2` checked the cookie's root
binding and validated secondary tokens, but never validated the root token.
Previously the plug authenticated the root, so a revoked or expired root failed
authentication. With the new active-account selection, the secondary token could
authenticate the browser despite root revocation, expiry, or deactivation.
This violated the persistent stack's rule that it cannot outlive the remembered
identity anchoring it.

**Fix:** require the root to resolve to an active user before restoring any
secondary account. Otherwise discard the persistent accounts cookie and let
authentication reject the root. Token loading still carries the active role.

**Regression coverage:** real HTTP login, add account, invalidate the root,
then restart with only the persistent cookies. Revocation, expiry, and
deactivation each reproduced the unauthorized recovery before the fix. A
revoked secondary account still falls back to a valid root, and the existing
tests retain normal active-account recovery and account switching.

## BUG - MEDIUM — checksum backfill undid the dedup opt-out (fixed)

`store_file_in_buckets/7` records the supplied content checksum unchanged.
An MD5-based caller using `dedup: false` therefore creates a row eligible for
`ChecksumBackfillJob`. That job replaced its independent `nodedup:<uuid>` key
with a computed dedup key. The next ordinary upload could resolve to the
independent attachment; another independent row of the same bytes could collide
with it during backfill.

**Fix:** normalize the content checksum while retaining a `nodedup:` key.
The atomic update also checks the previously observed dedup key, so a newer
choice made while the original was being read is not overwritten.

**Regression coverage:** normalize two independent uploads of the same bytes,
verify both retain their keys and neither occupies the normal dedup key;
verify a dedup key changed after the worker's read is left untouched. The first
test failed on the old code because the worker replaced the independent key.

## Other checks

- Reviewed the new directory lock, savepoint insert, in-flight upload hold,
  grace-period cutoff, and cleanup callers that ignore their own upload.
- The initial PR #938 storage tests passed against PostgreSQL (33 tests).
- Ordinary uploads still do not take the new insert lock; the documented
  concurrent-deletion guarantee requires every writer to use `dedup: false`.
- No schema or release changes. The pre-existing `mix.lock` edit is outside
  this review and is excluded from the commit.

## Validation

- PostgreSQL regression suite: **138 tests, 0 failures**, covering both upload
  tests, checksum backfill, HTTP multi-account sessions, context/unit
  multi-session tests, and API-only authentication doors (`PGPOOL=10`,
  `--max-cases 6`). Integration tests ran; the role lacks CREATEROLE, so tests
  requiring it are excluded by the suite's standard preflight.
- `mix precommit`: **passed**, including compilation with warnings as errors,
  unused-lock check, compilation of the test tree, formatting, strict Credo,
  Dialyzer under the repository's existing exclusions, and **377 JavaScript
  tests, 0 failures**.
- `git diff --check`: passed.
